# SPDX-License-Identifier: Apache-2.0
"""Shared gate configuration — ONE source for server AND CLI.

Lesson from the field: the approval TTL used to be applied by whichever
process created the approval (the CLI), while the documentation described it
as a server setting — an env variable set for the server silently did
nothing. A security setting that can be set without effect is unacceptable,
so server and CLI now read the SAME configuration file, and env variables
override it for both.

File: ``~/.hashgate/config.toml`` (override via ``HASHGATE_CONFIG``):

    db = "~/.hashgate/hooks.db"
    ttl_seconds = 900
    token = "…"        # optional shared secret
    port = 8377

Precedence per field: environment variable > config.toml > default.
"""
from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path

DEFAULT_CONFIG_PATH = "~/.hashgate/config.toml"
DEFAULT_DB_PATH = "~/.hashgate/hooks.db"
DEFAULT_TTL_SECONDS = 900
DEFAULT_PORT = 8377

class GateConfigError(Exception):
    """The shared config file is unreadable/invalid — carried as a clean
    error (with file name and hint) instead of a raw parser traceback."""


_ENV_NAMES = {
    "db": "HASHGATE_DB",
    "ttl_seconds": "HASHGATE_TTL_SECONDS",
    "token": "HASHGATE_TOKEN",
    "operator_token": "HASHGATE_OPERATOR_TOKEN",
    "port": "HASHGATE_PORT",
}


@dataclass(frozen=True)
class GateConfig:
    db_path: str = DEFAULT_DB_PATH
    ttl_seconds: int = DEFAULT_TTL_SECONDS
    token: str | None = None
    #: SEPARATE secret for the operator UI. The hook token lives in the
    #: environment Claude Code hands to the wrapper — from the agent's point
    #: of view it is potentially readable, so it must never authorize
    #: operator decisions. This one is never needed in the agent/hook
    #: environment and must never appear there.
    operator_token: str | None = None
    port: int = DEFAULT_PORT
    config_path: str | None = None  # where the file values came from (display)

    @property
    def resolved_db_path(self) -> str:
        return str(Path(self.db_path).expanduser())

    def summary(self) -> str:
        """One line of effective values for startup logging — the operator
        must be able to SEE what is in force."""
        return (
            f"db={self.resolved_db_path} ttl={self.ttl_seconds}s "
            f"token={'set' if self.token else 'unset'} "
            f"operator_token={'set' if self.operator_token else 'unset'} "
            f"port={self.port} config={self.config_path or '(no file)'}"
        )


def load_config(config_path: str | None = None,
                env: dict[str, str] | None = None) -> GateConfig:
    """Resolve the effective configuration (env > config.toml > default)."""
    env = os.environ if env is None else env
    path = Path(
        config_path or env.get("HASHGATE_CONFIG") or DEFAULT_CONFIG_PATH
    ).expanduser()
    file_values: dict[str, object] = {}
    file_used: str | None = None
    if path.is_file():
        try:
            with path.open("rb") as fh:
                file_values = tomllib.load(fh)
        except tomllib.TOMLDecodeError as exc:
            raise GateConfigError(
                f"invalid TOML in {path}: {exc}\n"
                'hint: string values need quotes, e.g. token = "abc123" — '
                "an unquoted token/operator_token is the usual cause"
            ) from exc
        except OSError as exc:
            raise GateConfigError(f"cannot read {path}: {exc}") from exc
        file_used = str(path)

    def pick(field: str, default):
        env_value = env.get(_ENV_NAMES[field])
        if env_value not in (None, ""):
            return env_value
        file_value = file_values.get(field)
        if file_value not in (None, ""):
            return file_value
        return default

    return GateConfig(
        db_path=str(pick("db", DEFAULT_DB_PATH)),
        ttl_seconds=int(pick("ttl_seconds", DEFAULT_TTL_SECONDS)),
        token=(lambda t: str(t) if t else None)(pick("token", None)),
        operator_token=(lambda t: str(t) if t else None)(
            pick("operator_token", None)),
        port=int(pick("port", DEFAULT_PORT)),
        config_path=file_used,
    )
