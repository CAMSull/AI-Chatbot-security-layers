from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, description="The user's chat message.")
    conversation_id: Optional[str] = Field(
        default=None, description="Optional client-supplied conversation identifier."
    )


class ChatResponse(BaseModel):
    reply: str
    conversation_id: Optional[str] = None
    request_id: str
    mock_mode: bool


class ErrorResponse(BaseModel):
    error: str
    layer: str
    detail: str
