"""In-process publish/subscribe event bus backing the WebSocket channels.
Redis pub/sub can be swapped in behind the same interface when configured."""
import asyncio
import json
from typing import Any


class EventBus:
    def __init__(self) -> None:
        self._loop: asyncio.AbstractEventLoop | None = None
        self._subscribers: dict[str, list[asyncio.Queue]] = {}

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def subscribe(self, channel: str) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=256)
        self._subscribers.setdefault(channel, []).append(q)
        return q

    def unsubscribe(self, channel: str, q: asyncio.Queue) -> None:
        queues = self._subscribers.get(channel, [])
        if q in queues:
            queues.remove(q)

    def publish(self, channel: str, payload: dict[str, Any]) -> None:
        self._publish_sync(channel, payload)

    def _publish_sync(self, channel: str, payload: dict[str, Any]) -> None:
        data = {"channel": channel, "data": payload, "ts": _now()}
        queues = self._subscribers.get(channel, [])
        for q in list(queues):
            self._offer(q, data)

    def _offer(self, q: asyncio.Queue, item: dict) -> None:
        def _put():
            try:
                q.put_nowait(item)
            except asyncio.QueueFull:
                pass

        if self._loop is not None:
            try:
                self._loop.call_soon_threadsafe(_put)
            except RuntimeError:
                pass
        else:
            _put()

    def stats(self) -> dict:
        return {
            "channels": {ch: len(qs) for ch, qs in self._subscribers.items()},
            "loop_bound": self._loop is not None,
        }


def _now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


bus = EventBus()
publish = bus.publish
