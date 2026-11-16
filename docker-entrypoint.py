from __future__ import annotations

import os
import sys

from sqlalchemy.engine import make_url


def use_host_gateway(raw_url: str) -> str:
  url = make_url(raw_url)
  if url.host in {"localhost", "127.0.0.1", "::1"}:
    return url.set(host="host.docker.internal").render_as_string(
      hide_password=False,
    )
  return raw_url

for variable in ("DATABASE_URL", "REDIS_URL"):
  value = os.environ.get(variable)
  if value:
    os.environ[variable] = use_host_gateway(value)

if len(sys.argv) < 2:
  raise SystemExit("A container command is required.")

os.execvp(sys.argv[1], sys.argv[1:])
