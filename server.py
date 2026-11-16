import os
import hmac
import json
import time
import secrets
import hashlib
import asyncio

from collections import defaultdict
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request, Header
from pydantic import BaseModel

app = FastAPI(title="SafeCamera Signaling Server")

# Server-side secret: keep this only in Render Environment Variables.
MASTER_SECRET = os.environ.get("SAFECAMERA_PAIRING_TOKEN")

# Temporary in-memory storage for initial testing.
pair_codes = {}
sessions = {}
rooms = {}
rate_limits = defaultdict(list)

CODE_LIFETIME = 300
SESSION_LIFETIME = 30 * 24 * 60 * 60
MAX_CODE_ATTEMPTS = 5


def now():
    return int(time.time())


def client_ip(request: Request):
    return request.client.host if request.client else "unknown"


def check_rate_limit(key, limit=10, window=300):
    current = now()
    attempts = [t for t in rate_limits[key] if current - t < window]
    rate_limits[key] = attempts

    if len(attempts) >= limit:
        raise HTTPException(status_code=429, detail="Too many attempts. Try later.")

    attempts.append(current)


def code_hash(code):
    if not MASTER_SECRET:
        raise HTTPException(status_code=503, detail="Server secret is not configured.")

    return hmac.new(
        MASTER_SECRET.encode(),
        code.encode(),
        hashlib.sha256
    ).hexdigest()


def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(room_id, role):
    token = secrets.token_urlsafe(48)

    sessions[token_hash(token)] = {
        "room_id": room_id,
        "role": role,
        "expires": now() + SESSION_LIFETIME
    }

    return token


def get_session(token):
    if not token:
        return None

    key = token_hash(token)
    session = sessions.get(key)

    if not session:
        return None

    if session["expires"] < now():
        sessions.pop(key, None)
        return None

    return session


def bearer_token(authorization):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Login required.")

    return authorization[7:].strip()


class RedeemRequest(BaseModel):
    code: str


@app.get("/")
async def home():
    return {"status": "SafeCamera Server Running"}


@app.get("/health")
async def health():
    return {"status": "OK"}


@app.post("/pair/create")
async def create_pairing(request: Request):
    check_rate_limit("create:" + client_ip(request), limit=5)

    if not MASTER_SECRET:
        raise HTTPException(status_code=503, detail="Server secret is not configured.")

    room_id = secrets.token_urlsafe(24)
    code = f"{secrets.randbelow(1000000):06d}"

    pair_codes[code_hash(code)] = {
        "room_id": room_id,
        "expires": now() + CODE_LIFETIME,
        "attempts": 0,
        "used": False
    }

    camera_token = create_session(room_id, "camera")

    return {
        "pairing_code": code,
        "expires_in_seconds": CODE_LIFETIME,
        "session_token": camera_token,
        "role": "camera"
    }


@app.post("/pair/redeem")
async def redeem_pairing(data: RedeemRequest, request: Request):
    ip = client_ip(request)
    check_rate_limit("redeem:" + ip, limit=10)

    code = data.code.strip()

    if len(code) != 6 or not code.isdigit():
        raise HTTPException(status_code=400, detail="Invalid pairing code.")

    key = code_hash(code)
    pairing = pair_codes.get(key)

    if not pairing or pairing["used"] or pairing["expires"] < now():
        raise HTTPException(status_code=400, detail="Code is invalid or expired.")

    pairing["attempts"] += 1

    if pairing["attempts"] > MAX_CODE_ATTEMPTS:
        pair_codes.pop(key, None)
        raise HTTPException(status_code=429, detail="Too many incorrect attempts.")

    room_id = pairing["room_id"]

    if any(
        s["room_id"] == room_id and s["role"] == "viewer" and s["expires"] > now()
        for s in sessions.values()
    ):
        raise HTTPException(status_code=400, detail="Viewer already paired.")

    pairing["used"] = True
    viewer_token = create_session(room_id, "viewer")

    return {
        "session_token": viewer_token,
        "role": "viewer",
        "message": "Pairing successful."
    }


@app.get("/session")
async def check_session(authorization: str = Header(default=None)):
    token = bearer_token(authorization)
    session = get_session(token)

    if not session:
        raise HTTPException(status_code=401, detail="Session expired. Login again.")

    return {
        "status": "OK",
        "role": session["role"],
        "expires_at": session["expires"]
    }


@app.post("/logout")
async def logout(authorization: str = Header(default=None)):
    token = bearer_token(authorization)
    sessions.pop(token_hash(token), None)

    return {"status": "Logged out"}


@app.websocket("/signal/{room_id}")
async def signaling(websocket: WebSocket, room_id: str):
    await websocket.accept()

    try:
        auth_message = await asyncio.wait_for(
            websocket.receive_text(),
            timeout=10
        )

        data = json.loads(auth_message)
        token = data.get("token", "")
        session = get_session(token)

        if not session or session["room_id"] != room_id:
            await websocket.close(code=1008)
            return

        role = session["role"]
        room = rooms.setdefault(room_id, {})

        if role in room:
            await websocket.close(code=1008)
            return

        room[role] = websocket

        await websocket.send_json({
            "type": "joined",
            "role": role
        })

        while True:
            message = await websocket.receive_text()

            other_role = "viewer" if role == "camera" else "camera"
            peer = room.get(other_role)

            if peer:
                await peer.send_text(message)

    except (WebSocketDisconnect, asyncio.TimeoutError, json.JSONDecodeError):
        pass
    except Exception:
        pass
    finally:
        room = rooms.get(room_id, {})
        if room.get("camera") is websocket:
            room.pop("camera", None)
        if room.get("viewer") is websocket:
            room.pop("viewer", None)
        if not room:
            rooms.pop(room_id, None)
            
