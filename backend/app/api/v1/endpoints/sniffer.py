"""
Live NIC Sniffer API Endpoints (backend/app/api/v1/endpoints/sniffer.py)

GET  /api/v1/sniffer/interfaces   — List available network interfaces
POST /api/v1/sniffer/start        — Start passive live capture
POST /api/v1/sniffer/stop         — Stop active capture
GET  /api/v1/sniffer/status       — Current capture session status
GET  /api/v1/sniffer/stream       — SSE stream of live-captured alerts

STRICT OPERATIONAL CONSTRAINTS:
  - READ-ONLY passive capture only.
  - No packet injection, active probing, or traffic modification.
  - ALERT_ONLY action — zero return path authority.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Dict, List

import psutil
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from app.core.auth import verify_api_key
from app.ingest.live_capture import live_capture_engine

logger = logging.getLogger("sentinelflow.sniffer_api")

router = APIRouter(prefix="/sniffer", tags=["Live NIC Sniffer"])


# ─── Schemas ──────────────────────────────────────────────────────────────────

class NicInterface(BaseModel):
    name: str
    description: str
    is_up: bool
    addresses: List[str] = []


class StartCaptureRequest(BaseModel):
    interface: str
    bpf_filter: str = "ip or ip6"


class StartCaptureResponse(BaseModel):
    ok: bool
    message: str
    interface: str
    bpf_filter: str


class StopCaptureResponse(BaseModel):
    ok: bool
    message: str
    stats: Dict[str, Any]


# ─── Endpoints ────────────────────────────────────────────────────────────────

@router.get("/interfaces", summary="List available network interfaces")
async def list_interfaces() -> Dict[str, Any]:
    """
    Returns available network interfaces from psutil.
    Includes UP/DOWN status and assigned IP addresses.
    """
    try:
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to enumerate interfaces: {exc}",
        )

    interfaces: list[NicInterface] = []
    for name, stat in stats.items():
        iface_addrs = addrs.get(name, [])
        ip_list = [
            a.address for a in iface_addrs
            if a.family.name in ("AF_INET", "AF_INET6")
        ]
        interfaces.append(
            NicInterface(
                name=name,
                description=f"{'UP' if stat.isup else 'DOWN'} | Speed: {stat.speed}Mbps",
                is_up=stat.isup,
                addresses=ip_list,
            )
        )

    # Sort: UP interfaces first
    interfaces.sort(key=lambda i: (not i.is_up, i.name))

    return {
        "interfaces": [i.model_dump() for i in interfaces],
        "total": len(interfaces),
        "note": "Live capture requires elevated privileges (sudo/Administrator).",
    }


@router.post(
    "/start",
    response_model=StartCaptureResponse,
    summary="Start passive live network capture",
    dependencies=[Depends(verify_api_key)],
)
async def start_capture(
    req: StartCaptureRequest,
    _auth: str = Depends(verify_api_key),
) -> StartCaptureResponse:
    """
    Starts a passive live packet capture on the specified interface.
    Requires the FastAPI process to run with elevated privileges.
    Strictly read-only — no packets are ever injected or modified.
    """
    if live_capture_engine.stats.running:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Capture already running on interface '{live_capture_engine.stats.interface}'. "
                "POST /api/v1/sniffer/stop first."
            ),
        )

    try:
        live_capture_engine.start(
            interface=req.interface if req.interface != "default" else None,
            bpf_filter=req.bpf_filter,
        )
    except PermissionError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Permission denied: live packet capture requires elevated privileges. "
                "Restart the backend with 'sudo' or grant CAP_NET_RAW capability."
            ),
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    except Exception as exc:
        logger.error("Failed to start capture: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Capture start failed: {exc}",
        )

    return StartCaptureResponse(
        ok=True,
        message=f"Passive capture started on '{req.interface}' (filter: '{req.bpf_filter}'). ALERT_ONLY — zero return path.",
        interface=req.interface,
        bpf_filter=req.bpf_filter,
    )


@router.post(
    "/stop",
    response_model=StopCaptureResponse,
    summary="Stop the active live capture session",
    dependencies=[Depends(verify_api_key)],
)
async def stop_capture(
    _auth: str = Depends(verify_api_key),
) -> StopCaptureResponse:
    """Gracefully stops the active live capture session."""
    if not live_capture_engine.stats.running:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No capture session is currently running.",
        )

    stats_before = live_capture_engine.get_status()
    live_capture_engine.stop()

    return StopCaptureResponse(
        ok=True,
        message="Live capture stopped successfully.",
        stats=stats_before,
    )


@router.get("/status", summary="Get current capture session status")
async def get_status() -> Dict[str, Any]:
    """Returns the current live capture session status and counters."""
    return live_capture_engine.get_status()


@router.get("/stream", summary="SSE stream of live-captured threat alerts")
async def stream_alerts():
    """
    Server-Sent Events endpoint that streams threat alerts captured from
    the live NIC session as they arrive in real-time.
    """
    async def event_generator():
        # Heartbeat if nothing captured yet
        if not live_capture_engine.stats.running:
            yield 'data: {"status":"idle","message":"No active capture session"}\n\n'
            return

        while live_capture_engine.stats.running:
            alert = await live_capture_engine.next_alert(timeout=5.0)
            if alert is not None:
                yield f"data: {json.dumps(alert)}\n\n"
            else:
                # Send heartbeat to keep connection alive
                heartbeat = json.dumps({
                    "status": "heartbeat",
                    "running": live_capture_engine.stats.running,
                    "packets": live_capture_engine.stats.packets_captured,
                    "flows": live_capture_engine.stats.flows_reconstructed,
                    "alerts": live_capture_engine.stats.alerts_emitted,
                })
                yield f"data: {heartbeat}\n\n"
            await asyncio.sleep(0)

        yield 'data: {"status":"stopped"}\n\n'

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
