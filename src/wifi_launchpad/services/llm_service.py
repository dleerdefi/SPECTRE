"""OpenAI-compatible LLM client with agentic tool-dispatch support.

This is an optional service — SPECTRE operates fully without it.
When no LLM backend is reachable, ``check_health()`` returns *False* and
callers should gracefully disable AI features.

Agentic analysis pattern adapted from METATRON
(https://github.com/sooryathejas/METATRON)
Copyright (c) 2026 sooryathejas — MIT License.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import List, Tuple

import requests

from wifi_launchpad.app.settings import LLMConfig

logger = logging.getLogger(__name__)


class LLMService:
    """Thin async wrapper around an OpenAI-compatible chat completions API."""

    def __init__(self, config: LLMConfig) -> None:
        self.base_url = config.url.rstrip("/")
        self.api_url = self.base_url + "/v1/chat/completions"
        self.models_url = self.base_url + "/v1/models"
        self.model = config.model
        self.max_tokens = config.max_tokens
        self.timeout = config.timeout

    # ── Health ────────────────────────────────────────────────────────────

    async def check_health(self) -> bool:
        """Return *True* if the LLM backend is reachable and a model is loaded."""
        try:
            resp = await asyncio.to_thread(
                requests.get, self.models_url, timeout=5,
            )
            resp.raise_for_status()
            models = resp.json().get("data", [])
            if not models:
                logger.warning("LLM server reachable but no models loaded")
                return False

            if not self.model:
                self.model = models[0]["id"]
                logger.info("Auto-selected LLM model: %s", self.model)

            return True
        except Exception:
            logger.debug("LLM backend not reachable at %s", self.base_url)
            return False

    # ── Chat completion ──────────────────────────────────────────────────

    async def ask(self, messages: List[dict]) -> str:
        """Send a chat completion request and return the response text.

        Handles Qwen 3.5 thinking-mode models that split output between
        ``content`` and ``reasoning_content``.
        """
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "max_tokens": self.max_tokens,
            "temperature": 0.7,
            "top_p": 0.9,
        }
        headers = {"Content-Type": "application/json"}

        try:
            resp = await asyncio.to_thread(
                requests.post,
                self.api_url,
                json=payload,
                headers=headers,
                timeout=self.timeout,
            )
            resp.raise_for_status()
            msg = resp.json()["choices"][0]["message"]
            content = (msg.get("content") or "").strip()
            if not content:
                content = (msg.get("reasoning_content") or "").strip()
            return content or "[!] Model returned empty response."
        except requests.exceptions.ConnectionError:
            return f"[!] Cannot connect to LLM at {self.base_url}."
        except requests.exceptions.Timeout:
            return "[!] LLM request timed out."
        except requests.exceptions.HTTPError as exc:
            return f"[!] LLM HTTP error: {exc}"
        except Exception as exc:
            return f"[!] Unexpected LLM error: {exc}"

    # ── Output compression ───────────────────────────────────────────────

    async def summarize(self, raw_output: str) -> str:
        """Compress verbose tool output into security-relevant bullet points."""
        if len(raw_output) < 500:
            return raw_output

        messages = [
            {
                "role": "system",
                "content": (
                    "You are a security data compressor. Extract only "
                    "security-relevant facts. Return maximum 15 bullet points. "
                    "Plain text only. No markdown."
                ),
            },
            {
                "role": "user",
                "content": f"Compress this tool output:\n{raw_output[:6000]}",
            },
        ]

        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "max_tokens": 512,
            "temperature": 0.2,
            "top_p": 0.9,
        }
        headers = {"Content-Type": "application/json"}

        try:
            resp = await asyncio.to_thread(
                requests.post,
                self.api_url,
                json=payload,
                headers=headers,
                timeout=120,
            )
            resp.raise_for_status()
            msg = resp.json()["choices"][0]["message"]
            summary = (msg.get("content") or msg.get("reasoning_content") or "").strip()
            return summary or raw_output
        except Exception:
            return raw_output

    # ── Tag extraction ───────────────────────────────────────────────────

    @staticmethod
    def extract_tool_calls(response: str) -> List[Tuple[str, str]]:
        """Parse ``[TOOL: ...]`` and ``[SEARCH: ...]`` tags from LLM output."""
        calls: List[Tuple[str, str]] = []
        for match in re.findall(r"\[TOOL:\s*(.+?)\]", response):
            calls.append(("TOOL", match.strip()))
        for match in re.findall(r"\[SEARCH:\s*(.+?)\]", response):
            calls.append(("SEARCH", match.strip()))
        return calls
