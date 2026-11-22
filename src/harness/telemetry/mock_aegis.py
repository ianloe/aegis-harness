"""Mock Aegis server validated against Aegis's real ingestion schemas.

Implements:
- POST /api/telemetry/ingest (BOUNDARY_BREACH, ROI_METRIC, GUARDRAIL_EVENT)
- POST /api/telemetry/pydantic (OTLP resourceSpans or direct PydanticAI payloads)
- POST /api/telemetry/mcp-a2a (MCP and A2A protocol call events)
- GET /api/assets/{asset_code}/gate (runtime circuit-breaker status)
"""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional, Set, Union

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, ValidationError

from harness.telemetry.schema import (
    AegisBoundaryBreachPayload,
    AegisGuardrailEventPayload,
    AegisMcpA2aPayload,
    AegisRoiMetricPayload,
)

IngestPayload = Union[
    AegisBoundaryBreachPayload,
    AegisRoiMetricPayload,
    AegisGuardrailEventPayload,
]


class MockAegisState(BaseModel):
    """In-memory state held by the mock Aegis instance for testing."""

    valid_tokens: Set[str] = Field(default_factory=lambda: {"aegis_test_token_1234567890abcdef"})
    registered_assets: Dict[str, Literal["ALLOW", "RESTRICTED", "SUSPENDED"]] = Field(
        default_factory=lambda: {"HARNESS-001": "ALLOW", "AI-004": "ALLOW"}
    )
    ingested_events: List[Dict[str, Any]] = Field(default_factory=list)
    pydantic_spans: List[Dict[str, Any]] = Field(default_factory=list)
    mcp_a2a_events: List[Dict[str, Any]] = Field(default_factory=list)
    seen_idempotency_keys: Set[str] = Field(default_factory=set)


def create_mock_aegis_app(state: Optional[MockAegisState] = None) -> FastAPI:
    """Create a FastAPI mock Aegis server matching Aegis's HTTP contracts."""
    app = FastAPI(title="Mock Aegis Governance Server", version="0.1.0")
    store = state or MockAegisState()
    app.state.mock_store = store

    def _check_auth(authorization: Optional[str]) -> None:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Bearer token required.")
        token = authorization[7:].strip()
        if token not in store.valid_tokens:
            raise HTTPException(status_code=401, detail="Invalid or revoked telemetry API key.")

    def _is_duplicate(key: Optional[str]) -> bool:
        if not key:
            return False
        if key in store.seen_idempotency_keys:
            return True
        store.seen_idempotency_keys.add(key)
        return False

    @app.get("/api/assets/{asset_code}/gate")
    async def get_asset_gate(
        asset_code: str,
        authorization: Optional[str] = Header(default=None),
    ) -> JSONResponse:
        _check_auth(authorization)
        if asset_code not in store.registered_assets:
            return JSONResponse({"error": f'Asset "{asset_code}" not found.'}, status_code=404)
        return JSONResponse(
            {
                "assetCode": asset_code,
                "gateStatus": store.registered_assets[asset_code],
                "reason": None,
            }
        )

    @app.post("/api/telemetry/ingest")
    async def ingest_telemetry(
        request: Request,
        authorization: Optional[str] = Header(default=None),
        x_idempotency_key: Optional[str] = Header(default=None),
    ) -> JSONResponse:
        _check_auth(authorization)
        raw = await request.json()
        event_type = raw.get("eventType") if isinstance(raw, dict) else None
        model_map = {
            "BOUNDARY_BREACH": AegisBoundaryBreachPayload,
            "ROI_METRIC": AegisRoiMetricPayload,
            "GUARDRAIL_EVENT": AegisGuardrailEventPayload,
        }
        schema_cls = model_map.get(event_type)
        if not schema_cls:
            return JSONResponse({"error": "Invalid telemetry payload."}, status_code=400)
        try:
            parsed = schema_cls.model_validate(raw)
        except ValidationError as exc:
            return JSONResponse({"error": "Invalid telemetry payload.", "details": exc.errors()}, status_code=400)

        if parsed.assetCode not in store.registered_assets:
            return JSONResponse({"error": f'Asset "{parsed.assetCode}" not found.'}, status_code=404)

        if not _is_duplicate(x_idempotency_key):
            store.ingested_events.append(parsed.model_dump())

        if isinstance(parsed, AegisBoundaryBreachPayload) and parsed.severity == "CRITICAL":
            store.registered_assets[parsed.assetCode] = "SUSPENDED"

        return JSONResponse({"status": "ingested", "eventType": parsed.eventType}, status_code=201)

    @app.post("/api/telemetry/pydantic")
    async def ingest_pydantic(
        request: Request,
        authorization: Optional[str] = Header(default=None),
        x_idempotency_key: Optional[str] = Header(default=None),
    ) -> JSONResponse:
        _check_auth(authorization)
        raw = await request.json()
        if not isinstance(raw, dict):
            return JSONResponse({"error": "Invalid JSON payload."}, status_code=400)

        asset_code: Optional[str] = raw.get("assetCode")
        if "resourceSpans" in raw and isinstance(raw["resourceSpans"], list):
            for rs in raw["resourceSpans"]:
                for attr in rs.get("resource", {}).get("attributes", []):
                    if attr.get("key") == "aegis.asset_code":
                        asset_code = attr.get("value", {}).get("stringValue")
        if not asset_code:
            return JSONResponse(
                {"error": "Missing assetCode or aegis.asset_code in OTLP attributes."},
                status_code=400,
            )
        if asset_code not in store.registered_assets:
            return JSONResponse({"error": f'Asset "{asset_code}" not found.'}, status_code=404)

        if not _is_duplicate(x_idempotency_key):
            store.pydantic_spans.append(raw)
        return JSONResponse({"status": "ingested", "processed": 1}, status_code=201)

    @app.post("/api/telemetry/mcp-a2a")
    async def ingest_mcp_a2a(
        request: Request,
        authorization: Optional[str] = Header(default=None),
        x_idempotency_key: Optional[str] = Header(default=None),
    ) -> JSONResponse:
        _check_auth(authorization)
        raw = await request.json()
        try:
            parsed = AegisMcpA2aPayload.model_validate(raw)
        except ValidationError as exc:
            return JSONResponse({"error": "Invalid MCP/A2A telemetry payload", "details": exc.errors()}, status_code=400)

        if parsed.assetCode not in store.registered_assets:
            return JSONResponse({"error": f'Asset "{parsed.assetCode}" not found.'}, status_code=404)

        if not _is_duplicate(x_idempotency_key):
            store.mcp_a2a_events.append(parsed.model_dump())
        return JSONResponse({"status": "ingested", "processed": 1, "violations": 0}, status_code=201)

    return app
