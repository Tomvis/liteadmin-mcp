"""One trusted gateway per server; credentials are transport-specific."""
from dataclasses import dataclass, field
import ipaddress
import os
from urllib.parse import urlsplit

from .catalog import BY_NAME


def gateway_origin(value: str, allow_http: bool = False) -> str:
    value = value.rstrip("/").removesuffix("/v1")
    parsed = urlsplit(value)
    loopback = parsed.hostname == "localhost"
    try:
        loopback = loopback or ipaddress.ip_address(parsed.hostname or "").is_loopback
    except ValueError:
        pass
    if (not parsed.hostname or parsed.username or parsed.password or parsed.path
            or parsed.query or parsed.fragment or any(c.isspace() for c in value)
            or not (parsed.scheme == "https" or parsed.scheme == "http" and (loopback or allow_http))):
        raise ValueError("LITELLM_BASE_URL must be an HTTPS gateway origin (optionally /v1); HTTP is allowed only on loopback or with LITELLM_ALLOW_HTTP.")
    try:
        parsed.port
    except ValueError:
        raise ValueError("Invalid gateway port") from None
    return value


def env_bool(name: str) -> bool:
    value = os.getenv(name, "false").lower().strip()
    if value not in {"true", "false", "1", "0"}:
        raise ValueError(f"{name} must be true or false")
    return value in {"true", "1"}


@dataclass(frozen=True)
class Config:
    base_url: str
    api_key: str = field(default="", repr=False)
    read_only: bool = False
    allowed_tools: frozenset[str] = frozenset()
    public_url: str = ""
    response_view: str = "compact"
    schema_mode: str = "full"
    # Fork: plain-HTTP gateway on a trusted LAN (e.g. http://litellm:4000).
    allow_http: bool = False
    # Fork: accept a proxy_admin on a gateway that predates admin_mcp_permissions
    # (LiteLLM without BerriAI/litellm#48080); every tool stays visible.
    legacy_gateway: bool = False

    def __post_init__(self):
        object.__setattr__(self, "base_url", gateway_origin(self.base_url, self.allow_http))
        if self.response_view not in {"full", "compact"}:
            raise ValueError("LITELLM_ADMIN_RESPONSE_VIEW must be full or compact")
        if self.schema_mode not in {"full", "discovery"}:
            raise ValueError("LITELLM_ADMIN_SCHEMA_MODE must be full or discovery")
        if self.allowed_tools - BY_NAME.keys():
            raise ValueError("LITELLM_ADMIN_TOOLS contains unknown tool names; inspect the published tool catalog.")
        if self.public_url:
            value = gateway_origin(self.public_url)
            if value != self.public_url.rstrip("/") or not value.startswith("https://"):
                raise ValueError("LITELLM_MCP_PUBLIC_URL must be an HTTPS origin")

    @classmethod
    def read(cls) -> "Config":
        return cls(
            base_url=os.getenv("LITELLM_BASE_URL", ""),
            api_key=os.getenv("LITELLM_API_KEY", ""),
            read_only=env_bool("LITELLM_ADMIN_READ_ONLY"),
            allowed_tools=frozenset(x.strip() for x in os.getenv("LITELLM_ADMIN_TOOLS", "").split(",") if x.strip()),
            public_url=os.getenv("LITELLM_MCP_PUBLIC_URL", "").rstrip("/"),
            response_view=os.getenv("LITELLM_ADMIN_RESPONSE_VIEW", "compact").strip(),
            schema_mode=os.getenv("LITELLM_ADMIN_SCHEMA_MODE", "full").strip(),
            allow_http=env_bool("LITELLM_ALLOW_HTTP"),
            legacy_gateway=env_bool("LITELLM_ADMIN_LEGACY_GATEWAY"),
        )
