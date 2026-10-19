"""Fork-only behaviour (Tomvis/liteadmin-mcp enhanced)."""
import copy
import logging

import httpx2
import pytest

from conftest import SPEC, session_for
from litellm_admin_mcp.config import Config
from litellm_admin_mcp.gateway import Gateway, USER_AGENT


def test_plain_http_gateway_needs_opt_in():
    with pytest.raises(ValueError):
        Config("http://10.0.0.101:4000")
    assert Config("http://10.0.0.101:4000", allow_http=True).base_url == "http://10.0.0.101:4000"
    assert Config("http://litellm:4000/v1", allow_http=True).base_url == "http://litellm:4000"


@pytest.mark.parametrize("url", ["http://user:secret@litellm:4000", "http://litellm:4000/path", "ftp://litellm"])
def test_plain_http_opt_in_keeps_origin_rules(url):
    with pytest.raises(ValueError):
        Config(url, allow_http=True)


def test_public_url_stays_https():
    with pytest.raises(ValueError):
        Config("http://litellm:4000", allow_http=True, public_url="http://mcp.example.com")


def test_allow_http_env(monkeypatch):
    monkeypatch.setenv("LITELLM_BASE_URL", "http://litellm:4000")
    monkeypatch.setenv("LITELLM_ALLOW_HTTP", "true")
    assert Config.read().allow_http


async def test_drifted_operation_is_skipped_not_fatal(stub, caplog):
    stub.spec = copy.deepcopy(SPEC)
    stub.spec["paths"]["/model/new"]["post"]["operationId"] = "changed"
    with caplog.at_level(logging.WARNING):
        async with session_for(stub) as session:
            names = {t.name for t in (await session.list_tools()).tools}
            assert "add_model" not in names and "list_keys" in names
            assert (await session.call_tool("add_model", {"body": {}})).is_error
    assert "add_model" in caplog.text
    assert not stub.writes


async def test_requests_send_browser_user_agent(stub):
    seen = []
    def handle(request):
        seen.append(request.headers["user-agent"])
        return stub.handle(request)
    gateway = Gateway(Config("https://gateway.example.com"))
    async with gateway:
        gateway.client._transport = httpx2.MockTransport(handle)
        await gateway.call("list_keys", {}, "alice-admin")
    assert seen and set(seen) == {USER_AGENT}
    assert "Chrome/" in USER_AGENT
