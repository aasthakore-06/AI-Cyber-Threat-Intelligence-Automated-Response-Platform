"""Pushes new alerts to connected dashboards over a websocket (so no page refresh needed)."""
import asyncio
import json
from typing import Set, Optional
from fastapi import WebSocket


class LiveFeed:
    def __init__(self):
        self.clients: Set[WebSocket] = set()
        self.loop: Optional[asyncio.AbstractEventLoop] = None

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.clients.add(ws)
        self.loop = asyncio.get_running_loop()

    def disconnect(self, ws: WebSocket):
        self.clients.discard(ws)

    async def _send_all(self, text: str):
        for ws in list(self.clients):
            try:
                await ws.send_text(text)
            except Exception:
                self.clients.discard(ws)

    def push(self, payload: dict):
        """Called from normal (sync) code running in a worker thread."""
        if not self.clients or not self.loop:
            return
        try:
            asyncio.run_coroutine_threadsafe(self._send_all(json.dumps(payload, default=str)), self.loop)
        except Exception:
            pass


live_feed = LiveFeed()
