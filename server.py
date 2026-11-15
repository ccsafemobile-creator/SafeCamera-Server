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

    if room_id not in rooms:
        rooms[room_id] = []

    if len(rooms[room_id]) >= 2:
        await websocket.send_json({
            "type": "error",
            "message": "Room is full"
        })
        await websocket.close()
        return

    rooms[room_id].append(websocket)

    try:
        await websocket.send_json({
            "type": "joined",
            "room": room_id,
            "users": len(rooms[room_id])
        })

        while True:
            data = await websocket.receive_text()

            for peer in rooms[room_id]:
                if peer != websocket:
                    await peer.send_text(data)

    except WebSocketDisconnect:
        pass

    finally:
        if room_id in rooms:
            if websocket in rooms[room_id]:
                rooms[room_id].remove(websocket)

            if not rooms[room_id]:
                del rooms[room_id]

