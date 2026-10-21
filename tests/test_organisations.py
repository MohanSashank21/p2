import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app


@pytest.mark.asyncio
async def test_organization_routes_are_no_longer_active():
  transport = ASGITransport(app=app)
  async with AsyncClient(transport=transport, base_url="http://testserver") as client:
    response = await client.get("/organisations")
    invitation_acceptance = await client.post(
      "/organisations/invitations/accept",
      json={"token": "a" * 32},
    )

  assert response.status_code == 404
  assert invitation_acceptance.status_code == 404
