"""WebSocket gateway (PRD §10.3): alerts.stream, indicators.high_severity,
incidents.{id}, system.health."""
import asyncio
import json

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session

from app.core.security import decode_token
from app.db import SessionLocal
from app.models import User
from app.services.bus import bus

router = APIRouter()

ALLOWED_CHANNELS = {"alerts.stream", "indicators.high_severity", "system.health"}
INCIDENT_PREFIX = "incidents."


def _authorize(token: str) -> tuple[str, str] | None:
    try:
        payload = decode_token(token, "access")
    except ValueError:
        return None
    db: Session = SessionLocal()
    try:
        user = db.get(User, payload["sub"])
        if user is None or user.status != "active":
            return None
        return user.id, user.role
    finally:
        db.close()


@router.websocket("/ws")
async def ws_endpoint(ws: WebSocket, token: str = Query(...)):
    auth = _authorize(token)
    if auth is None:
        await ws.close(code=4401)
        return
    user_id, role = auth
    await ws.accept()
    await ws.send_text(json.dumps({"type": "hello", "user_id": user_id, "role": role}))

    subscriptions: dict[str, asyncio.Queue] = {}

    async def pump() -> None:
        while True:
            raw = await ws.receive_text()
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                await ws.send_text(json.dumps({"type": "error", "message": "invalid json"}))
                continue
            action = msg.get("action")
            if action == "subscribe":
                channel = msg.get("channel", "")
                if channel in ALLOWED_CHANNELS or (channel.startswith(INCIDENT_PREFIX) and channel.count(".") == 1):
                    if channel not in subscriptions:
                        subscriptions[channel] = bus.subscribe(channel)
                    await ws.send_text(json.dumps({"type": "subscribed", "channel": channel}))
                else:
                    await ws.send_text(json.dumps({"type": "error", "message": f"unknown channel {channel}"}))
            elif action == "unsubscribe":
                channel = msg.get("channel", "")
                q = subscriptions.pop(channel, None)
                if q:
                    bus.unsubscribe(channel, q)
                await ws.send_text(json.dumps({"type": "unsubscribed", "channel": channel}))
            elif action == "ping":
                await ws.send_text(json.dumps({"type": "pong"}))

    async def deliver() -> None:
        while True:
            for channel, q in list(subscriptions.items()):
                try:
                    item = q.get_nowait()
                except asyncio.QueueEmpty:
                    continue
                try:
                    await ws.send_text(json.dumps(item))
                except Exception:
                    return
            await asyncio.sleep(0.15)

    try:
        await asyncio.gather(pump(), deliver())
    except WebSocketDisconnect:
        pass
    finally:
        for channel, q in subscriptions.items():
            bus.unsubscribe(channel, q)
