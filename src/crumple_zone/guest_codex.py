"""Locked invocation seam for the independent guest Codex process."""

from __future__ import annotations

import re
from pathlib import Path


CODEX_SEAM_VERSION = "guest-codex.v1"
CODEX_MODEL = "gpt-5.4"
CODEX_PROVIDER_ID = "crumple_host_proxy_v1"
CAPABILITY_ENV = "CRUMPLE_RUN_CAPABILITY"
_BASE_URL = re.compile(r"http://(?:127\.0\.0\.1|172\.16\.0\.1):[1-9][0-9]{0,4}/v1")


def build_exec_command(codex_path: str, workspace: Path, proxy_base_url: str, prompt: str) -> list[str]:
    if not Path(codex_path).is_absolute():
        raise ValueError("CODEX_PATH_MUST_BE_ABSOLUTE")
    if not workspace.is_absolute():
        raise ValueError("WORKSPACE_PATH_MUST_BE_ABSOLUTE")
    if _BASE_URL.fullmatch(proxy_base_url) is None:
        raise ValueError("MODEL_PROXY_BASE_URL_NOT_ALLOWED")
    if not 1 <= len(prompt) <= 16_384:
        raise ValueError("PROMPT_SIZE_INVALID")
    provider = (
        '{ name="Crumple Host Proxy", '
        f'base_url="{proxy_base_url}", '
        f'wire_api="responses", env_key="{CAPABILITY_ENV}" }}'
    )
    return [
        codex_path,
        "exec",
        "--ephemeral",
        "--json",
        "--ignore-user-config",
        "--ignore-rules",
        "--strict-config",
        "--skip-git-repo-check",
        "--cd",
        str(workspace),
        "--sandbox",
        "read-only",
        "--config",
        'approval_policy="never"',
        "--config",
        f'model="{CODEX_MODEL}"',
        "--config",
        f'model_provider="{CODEX_PROVIDER_ID}"',
        "--config",
        f"model_providers.{CODEX_PROVIDER_ID}={provider}",
        "--config",
        'history.persistence="none"',
        prompt,
    ]

