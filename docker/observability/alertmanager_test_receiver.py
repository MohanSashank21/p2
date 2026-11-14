import json
import logging
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock

_MAX_BODY_BYTES = 1_048_576
_MAX_EVENTS = 256
_events: list[dict] = []
_events_lock = Lock()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("alertmanager-test-receiver")


class AlertmanagerTestReceiver(BaseHTTPRequestHandler):
  def do_GET(self) -> None:
    if self.path == "/healthz":
      self._write_json(200, {"status": "healthy"})
      return
    if self.path == "/events":
      with _events_lock:
        events = list(_events)
      self._write_json(200, {"events": events})
      return
    self._write_json(404, {"detail": "Not found"})

  def do_POST(self) -> None:
    if self.path != "/alerts":
      self._write_json(404, {"detail": "Not found"})
      return
    try:
      body_size = int(self.headers.get("Content-Length", ""))
    except ValueError:
      self._write_json(400, {"detail": "Invalid Content-Length"})
      return
    if body_size < 0 or body_size > _MAX_BODY_BYTES:
      self._write_json(413, {"detail": "Payload exceeds the 1 MiB limit"})
      return
    try:
      payload = json.loads(self.rfile.read(body_size))
    except (json.JSONDecodeError, UnicodeDecodeError):
      self._write_json(400, {"detail": "Request body must be valid JSON"})
      return
    if not isinstance(payload, dict) or not isinstance(payload.get("alerts"), list):
      self._write_json(400, {"detail": "Alertmanager notification is invalid"})
      return

    event = {
      "received_at": datetime.now(UTC).isoformat(),
      "payload": payload,
    }
    with _events_lock:
      _events.append(event)
      del _events[:-_MAX_EVENTS]
    logger.info(
      "received Alertmanager notification (status=%s, alerts=%d, group=%s)",
      payload.get("status", "unknown"),
      len(payload["alerts"]),
      payload.get("groupKey", "unknown"),
    )
    self._write_json(200, {"status": "accepted"})

  def log_message(self, format: str, *args: object) -> None:
    logger.info("%s - %s", self.address_string(), format % args)

  def _write_json(self, status_code: int, value: dict) -> None:
    body = json.dumps(value, separators=(",", ":")).encode()
    self.send_response(status_code)
    self.send_header("Content-Type", "application/json")
    self.send_header("Content-Length", str(len(body)))
    self.end_headers()
    self.wfile.write(body)


def main() -> None:
  server = ThreadingHTTPServer(("0.0.0.0", 8080), AlertmanagerTestReceiver)
  logger.info("local Alertmanager test receiver listening on port 8080")
  server.serve_forever()


if __name__ == "__main__":
  main()
