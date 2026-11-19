"""The agent-facing API (spec section 3), with mock responses.

Every operation answers with fixed example data taken from the spec. Nothing is
checked or stored yet.
"""

from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Response

from coordinator.models import (
    Approval,
    ControlMessage,
    Lease,
    PendingApproval,
    PollRequest,
    PollResponse,
    SiteList,
    StudyVersion,
    TaskEnvelope,
    Workflow,
)
from coordinator.problems import INVALID_REQUEST
from coordinator.researcher import WORKFLOW

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


def study_version(study_id: str, version: int) -> StudyVersion:
    def member(member: str, ls_aai_id: str) -> dict:
        return {
            "member": member,
            "ls_aai_id": ls_aai_id,
            "signing_key": {"kty": "EC", "crv": "P-256", "x": "f83O...", "y": "x_FE..."},
            "result_key": "age1qyqszqgpqyqszqgp...",
            "binding_token": "eyJhbGciOiJSUzI1NiIs...",
        }

    return StudyVersion.model_validate(
        {
            "study_id": study_id,
            "version": version,
            "previous_digest": "sha256:1c7e..." if version > 1 else None,
            "goal": "Allele frequencies of variant X in three cohorts",
            "members": [
                member("m-01", "a1b2c3...@lifescience-ri.eu"),
                member("m-02", "d4e5f6...@lifescience-ri.eu"),
            ],
            "nodes": [
                {
                    "node": "biodata-pt",
                    "encryption_key": "sha256:3f9a...",
                    "datasets": ["EGAD00001001234"],
                },
                {
                    "node": "ifb-fr",
                    "encryption_key": "sha256:77c0...",
                    "datasets": ["EGAD00001005678"],
                },
                {
                    "node": "nottingham",
                    "encryption_key": "sha256:b812...",
                    "datasets": ["EGAD00001009012"],
                },
            ],
            "output_rules": {
                "aggregates_only": True,
                "min_count": 10,
                "types": ["TEXT", "TSV"],
                "max_bytes": 1048576,
            },
            "proposer": "m-01",
            "signature": "MEQC...",
        }
    )


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


@router.get(
    "/studies/{study_id}/versions/{version}",
    summary="A study version waiting for this node's approval",
)
async def get_study_version(study_id: str, version: int) -> StudyVersion:
    return study_version(study_id, version)


@router.get(
    "/workflows/{digest}",
    summary="A workflow waiting for this node's approval",
    # Input nodes carry no data in the canonical form (spec 3.4): leave it out, not null.
    response_model_exclude_none=True,
)
async def get_workflow(digest: str) -> Workflow:
    return WORKFLOW


@router.post(
    "/approvals",
    status_code=204,
    summary="A data manager's signed approval, refusal or withdrawal",
)
async def post_approval(approval: Approval) -> None:
    """The Hub knows a decision by the calling node and its decision_id. The agent sends
    a decision again when it cannot tell whether it arrived: one the Hub already holds
    gets the same answer and is not stored twice."""
