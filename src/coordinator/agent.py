"""The agent-facing API (spec section 3), with mock responses.

Every operation answers with fixed example data taken from the spec. Nothing is
checked or stored yet.
"""

from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Response

from coordinator.models import (
    ControlMessage,
    Lease,
    PendingApproval,
    PollRequest,
    PollResponse,
    SiteList,
    TaskEnvelope,
)
from coordinator.problems import INVALID_REQUEST

router = APIRouter(prefix="/api/agent/v1", tags=["agent"], responses=INVALID_REQUEST)


def current_node() -> str:
    """The calling node. Fixed for now; it will come from the client certificate."""
    return "biodata-pt"


CurrentNode = Annotated[str, Depends(current_node)]


# Mock data

STUDY_DIGEST = "sha256:9f2c..."
WORKFLOW_DIGEST = "sha256:41ab..."
POLL_INTERVAL_S = 10
LEASE_S = 3 * POLL_INTERVAL_S

# The site list as the federation signed it. The Hub sends these bytes as they
# are: the signature covers them, so parsing and writing the document again
# would break it.
SITE_LIST = b"""{
  "version": 15,
  "expires_at": "2027-01-01T00:00:00Z",
  "nodes": [
    {"node": "biodata-pt", "encryption_key": "age1qz3f...", "signing_key": "MCowBQYDK2VwAyEA...",
     "certificate": "sha256:5b1e..."},
    {"node": "ifb-fr", "encryption_key": "age1x9wn...", "signing_key": "MCowBQYDK2VwAyEA...",
     "certificate": "sha256:c07d..."},
    {"node": "nottingham", "encryption_key": "age1m4tk...", "signing_key": "MCowBQYDK2VwAyEA...",
     "certificate": "sha256:9a62..."}
  ]
}
"""
SITE_LIST_SIGNATURE = "7vE1qDk3..."


def task_for(node: str, now: datetime) -> TaskEnvelope:
    return TaskEnvelope.model_validate(
        {
            "task_id": "tk_7a3d...",
            "attempt": 1,
            "lease_id": "ls_41c2...",
            "job_request": {
                "request_id": "rq_5b8e...",
                "study_id": "st-01",
                "study_version": 3,
                "study_digest": STUDY_DIGEST,
                "workflow_digest": WORKFLOW_DIGEST,
                "member": "m-02",
                "node": node,
                "datasets": ["EGAD00001001234"],
                "not_after": now + timedelta(days=7),
                "payload_digest": "sha256:77d1...",
            },
            "signature": {"alg": "ES256", "key": "m-02/sign", "sig": "MEQC..."},
            "payload": {"enc": "age-x25519", "ciphertext": "YWdlLWVuY3J5cHRpb24..."},
        }
    )


@router.get(
    "/site-list",
    summary="The current signed site list",
    responses={
        200: {
            "model": SiteList,
            "description": "The site list, byte for byte as the federation signed it.",
            "headers": {
                "BioChef-Signature": {
                    "description": "Ed25519 signature over the body, base64url.",
                    "schema": {"type": "string"},
                }
            },
        }
    },
)
async def get_site_list() -> Response:
    return Response(
        SITE_LIST,
        media_type="application/json",
        headers={"BioChef-Signature": SITE_LIST_SIGNATURE},
    )


@router.post(
    "/poll",
    summary="Heartbeat: states and capacity go up; tasks, approvals and control messages come down",
)
async def poll(body: PollRequest, node: CurrentNode) -> PollResponse:
    now = datetime.now(UTC).replace(microsecond=0)
    capacity = body.capacity
    return PollResponse(
        server_time=now,
        next_poll_after_s=POLL_INTERVAL_S,
        # Listing a lease renews it.
        leases=[
            Lease(lease_id=t.lease_id, expires_at=now + timedelta(seconds=LEASE_S), valid=True)
            for t in body.active
        ],
        # Never more tasks than free slots, and none when the agent is not accepting.
        tasks=[task_for(node, now)] if capacity.accepting and capacity.slots_free > 0 else [],
        pending_approvals=[
            PendingApproval(kind="study", study_id="st-01", version=3, digest=STUDY_DIGEST),
            PendingApproval(kind="workflow", study_id="st-01", version=3, digest=WORKFLOW_DIGEST),
        ],
        control=[ControlMessage(type="cancel", task_id="tk_6ff0...", attempt=1)],
    )
