from __future__ import annotations

import secrets as pysecrets
import string
from pathlib import Path

import yaml

from .config import Config, SecretBackend


SECRET_URI_PREFIX = "secret://"


class SecretsResolver:
    """Resolves `secret://<path>` URIs against the configured backend."""

    def __init__(self, cfg: Config, secrets_file: Path):
        self.cfg = cfg
        self.path = secrets_file
        self._store: dict[str, str] = {}
        if secrets_file.exists():
            raw = yaml.safe_load(secrets_file.read_text()) or {}
            if isinstance(raw, dict):
                self._store = {str(k): str(v) for k, v in raw.items()}

    def is_secret_uri(self, value: str) -> bool:
        return isinstance(value, str) and value.startswith(SECRET_URI_PREFIX)

    def resolve(self, value: str) -> str:
        """Return the plaintext secret for a `secret://<path>` URI."""
        if not self.is_secret_uri(value):
            return value
        key = value[len(SECRET_URI_PREFIX):]

        backend = self.cfg.secrets.backend
        if backend == SecretBackend.inline:
            return self._resolve_inline(key)
        if backend == SecretBackend.env:
            import os
            env_name = self.cfg.secrets.env_prefix + key.replace("/", "_").upper()
            if env_name in os.environ:
                return os.environ[env_name]
            raise KeyError(f"env secret {env_name} not set (from {value})")
        raise NotImplementedError(f"secret backend '{backend.value}' not implemented yet")

    def _resolve_inline(self, key: str) -> str:
        if key in self._store:
            return self._store[key]
        # Not stored yet: generate once and persist.
        length = self.cfg.secrets.generated.password_length
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        value = "".join(pysecrets.choice(alphabet) for _ in range(length))
        self._store[key] = value
        self._flush()
        return value

    def resolve_in_tree(self, obj):
        """Walk a nested dict/list and replace every `secret://` string in place."""
        if isinstance(obj, dict):
            for k, v in list(obj.items()):
                obj[k] = self.resolve_in_tree(v)
            return obj
        if isinstance(obj, list):
            return [self.resolve_in_tree(x) for x in obj]
        if isinstance(obj, str) and self.is_secret_uri(obj):
            return self.resolve(obj)
        return obj

    def _flush(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(yaml.safe_dump(self._store, sort_keys=True))
        self.path.chmod(0o600)
