import os
import hmac
import json

from fastapi import FastAPI, WebSocket, WebSocketDisconnect

app = FastAPI(title="SafeCamera Signaling Server")

rooms = {}

@app.get("/")
async def home():
    return {"status": "SafeCamera Server Running"}

@app.get("/health")
async def health():
    return {"status": "OK"}

@app.websocket("/signal/{room_id}")
async def signaling(websocket: WebSocket, room_id: str):

    await websocket.accept()

    secret = os.environ.get("SAFECAMERA_PAIRING_TOKEN")

    if not secret:
        await websocket.close(code=1011)
        return

    try:
        # First message must contain the pairing password
        auth_data = json.loads(await websocket.receive_text())

        if not isinstance(auth_data, dict):
            await websocket.close(code=1008)
            return

        supplied_token = auth_data.get("token", "")

        if not isinstance(supplied_token, str) or not hmac.compare_digest(supplied_token, secret):
            await websocket.close(code=1008)
            return

        if room_id not in rooms:
            rooms[room_id] = []

        if len(rooms[room_id]) >= 2:
            await websocket.close(code=1008)
            return

        rooms[room_id].append(websocket)

        await websocket.send_json({
            "type": "joined",
            "room": room_id,
            "users": len(rooms[room_id])
        })

        while True:
            data = await websocket.receive_text()

            for peer in list(rooms.get(room_id, [])):
                if peer != websocket:
                    await peer.send_text(data)

    except (WebSocketDisconnect, json.JSONDecodeError):
        pass

    finally:
        if room_id in rooms:
            if websocket in rooms[room_id]:
                rooms[room_id].remove(websocket)

            if not rooms[room_id]:
                del rooms[room_id]
