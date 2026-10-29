"""Local Open-Source AI Gateway service (OpenAI `/v1/chat/completions` & Anthropic `/v1/messages`) for the Docker `demo` profile."""

from __future__ import annotations

import json
import uuid
from typing import Any, AsyncIterator

from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse


def _extract_last_text(payload: dict[str, Any]) -> str:
    for msg in reversed(payload.get("messages", [])):
        content = msg.get("content", "")
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            return " ".join(p.get("text", "") for p in content if isinstance(p, dict))
    return ""


async def _openai_stream(model: str, text: str) -> AsyncIterator[bytes]:
    cid = f"chatcmpl-{uuid.uuid4().hex[:12]}"
    for token in [f"[Gateway ({model})]:", *text.split()[:30]]:
        chunk = {
            "id": cid,
            "object": "chat.completion.chunk",
            "model": model,
            "choices": [{"index": 0, "delta": {"content": token + " "}, "finish_reason": None}],
        }
        yield f"data: {json.dumps(chunk)}\n\n".encode("utf-8")
    done = {
        "id": cid,
        "object": "chat.completion.chunk",
        "model": model,
        "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
    }
    yield f"data: {json.dumps(done)}\n\n".encode("utf-8")
    yield b"data: [DONE]\n\n"


async def _anthropic_stream(model: str, text: str) -> AsyncIterator[bytes]:
    mid = f"msg_{uuid.uuid4().hex[:12]}"
    start = {
        "type": "message_start",
        "message": {"id": mid, "type": "message", "role": "assistant", "model": model, "content": []},
    }
    yield f"event: message_start\ndata: {json.dumps(start)}\n\n".encode("utf-8")
    delta = {
        "type": "content_block_delta",
        "index": 0,
        "delta": {"type": "text_delta", "text": f"[Anthropic Gateway ({model})]: {text[:200]}"},
    }
    yield f"event: content_block_delta\ndata: {json.dumps(delta)}\n\n".encode("utf-8")
    yield b'event: message_stop\ndata: {"type": "message_stop"}\n\n'


def create_gateway_app() -> FastAPI:
    app = FastAPI(title="POD Demo Local AI Gateway (OpenAI & Anthropic)", version="0.1.0")

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "service": "pod-demo-ai-gateway"}

    @app.get("/v1/models")
    def list_models() -> dict[str, Any]:
        return {
            "object": "list",
            "data": [
                {"id": "local-model", "object": "model", "owned_by": "g1-docket-local"},
                {"id": "vpc-model", "object": "model", "owned_by": "g1-docket-vpc"},
                {"id": "gpt-4o", "object": "model", "owned_by": "openai"},
                {"id": "claude-3-5-sonnet", "object": "model", "owned_by": "anthropic"},
            ],
        }

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request) -> Any:
        payload = await request.json()
        model = payload.get("model", "gpt-4o")
        text = _extract_last_text(payload)
        if payload.get("stream"):
            return StreamingResponse(_openai_stream(model, text), media_type="text/event-stream")
        return {
            "id": f"chatcmpl-{uuid.uuid4().hex[:12]}",
            "object": "chat.completion",
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": f"[Gateway ({model})]: {text}"},
                    "finish_reason": "stop",
                }
            ],
        }

    @app.post("/v1/messages")
    async def messages(request: Request) -> Any:
        payload = await request.json()
        model = payload.get("model", "claude-3-5-sonnet")
        text = _extract_last_text(payload)
        if payload.get("stream"):
            return StreamingResponse(_anthropic_stream(model, text), media_type="text/event-stream")
        return {
            "id": f"msg_{uuid.uuid4().hex[:12]}",
            "type": "message",
            "role": "assistant",
            "model": model,
            "content": [{"type": "text", "text": f"[Anthropic Gateway ({model})]: {text}"}],
            "stop_reason": "end_turn",
        }

    return app
