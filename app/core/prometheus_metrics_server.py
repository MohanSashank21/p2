import asyncio

from uvicorn import Config, Server

from app.core.config import settings
from app.core.prometheus_metrics import metrics_app


class _MetricsServer(Server):
  def install_signal_handlers(self) -> None:
    return


async def start_metrics_server() -> tuple[_MetricsServer, asyncio.Task[None]]:
  server = _MetricsServer(
    Config(
      app=metrics_app,
      host="0.0.0.0",
      port=settings.PROMETHEUS_METRICS_PORT,
      access_log=False,
      lifespan="off",
      log_config=None,
    ),
  )
  task = asyncio.create_task(server.serve(), name="prometheus-metrics-server")
  try:
    async with asyncio.timeout(10):
      while not server.started:
        if task.done():
          await task
          raise RuntimeError("Prometheus metrics server exited before starting")
        await asyncio.sleep(0.01)
  except TimeoutError as error:
    server.should_exit = True
    try:
      await asyncio.wait_for(task, timeout=5)
    except TimeoutError:
      task.cancel()
      try:
        await task
      except asyncio.CancelledError:
        pass
    raise RuntimeError("Prometheus metrics server did not start in time") from error
  return server, task
