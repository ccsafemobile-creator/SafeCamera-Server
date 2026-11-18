import os
import time
import secrets
import hashlib
import hmac

from fastapi import (
    FastAPI,
    WebSocket,
    WebSocketDisconnect,
    HTTPException,
    Header,
    Request
)
from pydantic import BaseModel, Field


app = FastAPI(title="SafeCamera Signaling Server")

# Temporary in-memory storage
pair_codes = {}
sessions = {}
rooms = {}
rate_limits = {}

PAIR_CODE_EXPIRY = 300
SESSION_EXPIRY = 30 * 24 * 60 * 60

RATE_LIMIT_WINDOW = 900       # 15 minutes
MAX_ATTEMPTS = 5


# -------------------------
# Helper Functions
# -------------------------

def hash_token(token: str):
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(room_id: str, role: str):
    token = secrets.token_urlsafe(32)

    sessions[hash_token(token)] = {
        "room_id": room_id,
        "role": role,
        "expires_at": time.time() + SESSION_EXPIRY
    }

    return token


def get_session(token: str):
    if not token:
        return None

    session = sessions.get(hash_token(token))

    if not session:
        return None

    if session["expires_at"] < time.time():
        sessions.pop(hash_token(token), None)
        return None

    return session


def get_bearer_token(authorization):
    if not authorization:
        return None

    parts = authorization.split(" ", 1)

    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None

    return parts[1].strip()


def check_rate_limit(key: str):
    now = time.time()

    record = rate_limits.get(key)

    if record is None or now - record["start"] >= RATE_LIMIT_WINDOW:
        rate_limits[key] = {
            "start": now,
            "count": 1
        }
        return

    if record["count"] >= MAX_ATTEMPTS:
        raise HTTPException(
            status_code=429,
            detail="Too many attempts. Try again after 15 minutes."
        )

    record["count"] += 1


def clean_expired_codes():
    now = time.time()

    expired = [
        code for code, data in pair_codes.items()
        if data["expires_at"] < now
    ]

    for code in expired:
        pair_codes.pop(code, None)


# -------------------------
# Home
# -------------------------

@app.get("/")
async def home():
    return {
        "status": "SafeCamera Server Running"
    }


# -------------------------
# Health
# -------------------------

@app.get("/health")
async def health():
    return {
        "status": "OK"
    }


# -------------------------
# Create Pairing Code
# Phone 1
# -------------------------

class CreatePairRequest(BaseModel):
    pin: str = Field(min_length=8, max_length=128)


@app.post("/pair/create")
async def create_pair(
    request: Request,
    data: CreatePairRequest
):
    client_ip = request.client.host if request.client else "unknown"

    check_rate_limit(f"create:{client_ip}")

    expected_pin = os.getenv("SAFECAMERA_PAIRING_PIN")

    if not expected_pin:
        raise HTTPException(
            status_code=503,
            detail="Pairing PIN is not configured on server"
        )

    if not hmac.compare_digest(data.pin, expected_pin):
        raise HTTPException(
            status_code=401,
            detail="Incorrect pairing PIN"
        )

    clean_expired_codes()

    code = str(secrets.randbelow(900000) + 100000)

    while code in pair_codes:
        code = str(secrets.randbelow(900000) + 100000)

    room_id = secrets.token_urlsafe(16)

    camera_token = create_session(room_id, "camera")

    pair_codes[code] = {
        "room_id": room_id,
        "expires_at": time.time() + PAIR_CODE_EXPIRY
    }

    rooms[room_id] = {}

    return {
        "pairing_code": code,
        "room_id": room_id,
        "session_token": camera_token,
        "role": "camera",
        "expires_in_seconds": PAIR_CODE_EXPIRY
    }


# -------------------------
# Redeem Pairing Code
# Phone 2
# -------------------------

class RedeemRequest(BaseModel):
    code: str = Field(min_length=6, max_length=6)


@app.post("/pair/redeem")
async def redeem_pair(
    request: Request,
    data: RedeemRequest
):
    client_ip = request.client.host if request.client else "unknown"

    check_rate_limit(f"redeem:{client_ip}")

    code = data.code.strip()

    if not code.isdigit():
        raise HTTPException(
            status_code=400,
            detail="Invalid pairing code"
        )

    pair = pair_codes.get(code)

    if not pair:
        raise HTTPException(
            status_code=404,
            detail="Pairing code not found or already used"
        )

    if pair["expires_at"] < time.time():
        pair_codes.pop(code, None)

        raise HTTPException(
            status_code=410,
            detail="Pairing code expired"
        )

    # One-time code
    pair_codes.pop(code, None)

    room_id = pair["room_id"]

    viewer_token = create_session(room_id, "viewer")

    return {
        "session_token": viewer_token,
        "room_id": room_id,
        "role": "viewer",
        "message": "Pairing successful."
    }


# -------------------------
# Check Session
# -------------------------

@app.get("/session")
async def check_session(
    authorization: str | None = Header(default=None)
):
    token = get_bearer_token(authorization)
    session = get_session(token)

    if not session:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired session"
        )

    return {
        "valid": True,
        "room_id": session["room_id"],
        "role": session["role"]
    }


# -------------------------
# Logout
# -------------------------

@app.post("/logout")
async def logout(
    authorization: str | None = Header(default=None)
):
    token = get_bearer_token(authorization)

    if not token:
        raise HTTPException(
            status_code=401,
            detail="Missing session token"
        )

    sessions.pop(hash_token(token), None)

    return {
        "success": True,
        "message": "Logged out successfully"
    }


# -------------------------
# WebSocket Signaling
# Phone 1 + Phone 2
# -------------------------

@app.websocket("/signal/{room_id}")
async def signaling(
    websocket: WebSocket,
    room_id: str
):
    await websocket.accept()

    role = None
    room = None

    try:
        # First message must contain session token
        auth_data = await websocket.receive_json()

        if auth_data.get("type") != "auth":
            await websocket.close(code=1008)
            return

        token = auth_data.get("token", "")
        session = get_session(token)

        if not session:
            await websocket.send_json({
                "type": "error",
                "message": "Invalid session"
            })
            await websocket.close(code=1008)
            return

        if session["room_id"] != room_id:
            await websocket.close(code=1008)
            return

        role = session["role"]

        if role not in ("camera", "viewer"):
            await websocket.close(code=1008)
            return

        room = rooms.setdefault(room_id, {})

        # Only one connection per role
        if role in room:
            await websocket.send_json({
                "type": "error",
                "message": "This role is already connected"
            })
            await websocket.close(code=1008)
            return

        room[role] = websocket

        await websocket.send_json({
            "type": "joined",
            "room": room_id,
            "role": role,
            "users": len(room)
        })

        other_role = "viewer" if role == "camera" else "camera"

        peer = room.get(other_role)

        if peer:
            await peer.send_json({
                "type": "peer_joined",
                "role": role
            })

        # Forward signaling messages
        while True:
            data = await websocket.receive_text()

            peer = room.get(other_role)

            if peer:
                await peer.send_text(data)

    except WebSocketDisconnect:
        pass

    except Exception:
        pass

    finally:
        if room is not None and role is not None:
            if room.get(role) is websocket:
                room.pop(role, None)

                other_role = "viewer" if role == "camera" else "camera"
                peer = room.get(other_role)

                if peer:
                    try:
                        await peer.send_json({
                            "type": "peer_left"
                        })
                    except Exception:
                        pass

            if not room:
                rooms.pop(room_id, None)
