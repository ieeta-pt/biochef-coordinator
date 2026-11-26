"""The agent-facing API (spec section 3), with mock responses.

Every operation answers with fixed example data taken from the spec. Nothing is
checked or stored yet.
"""

from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Header, Response

from coordinator.models import (
    Approval,
    ControlMessage,
    Lease,
    PartialCommit,
    PendingApproval,
    PollRequest,
    PollResponse,
    SiteList,
    StudyVersion,
    TaskDecision,
    TaskEnvelope,
    TaskEvent,
    Workflow,
)
from coordinator.problems import INVALID_REQUEST, Problem
from coordinator.researcher import WORKFLOW

router = APIRouter(prefix="/api/agent/v1", tags=["agent"], responses=INVALID_REQUEST)


def current_node() -> str:
    """The calling node. Fixed for now; it will come from the client certificate."""
    return "biodata-pt"


CurrentNode = Annotated[str, Depends(current_node)]


# Mock data

STUDY_DIGEST = "sha256:9f2c..."
WORKFLOW_DIGEST = "sha256:41ab..."
# The agent's default interval (BIOCHEF_COORDINATOR_POLL_SECONDS).
POLL_INTERVAL_S = 30
LEASE_S = 3 * POLL_INTERVAL_S

# Synthetic member keys. m-01's are the test vector in biochef-infra docs/identity.md.
MEMBER_KEYS = {
    "m-01": {
        "signing_key": {
            "kty": "EC",
            "crv": "P-256",
            "x": "AO1cfutKPq_Pj_qgqcxF6mw7pf0zvS0bOTf3G-GON1s",
            "y": "HjpzF_k9FmBSD7iiJq3QrtNRFM_uF0xVckpsACGAf38",
        },
        "result_key": "age1vpw3jerf7764tnxv0jvwg9umcmstqf2zxwvezp4xpeetjxwsgsdsesfryj",
    },
    "m-02": {
        "signing_key": {
            "kty": "EC",
            "crv": "P-256",
            "x": "MCkhgR_EhFA02uM0Ypg4Jd1s6uFdNQn03y5o6659Trs",
            "y": "-dzFB0Tpy3oYOp1E8NiDxoEjrG38n6BwNuxpNKYwbXI",
        },
        "result_key": "age1pc6dxh9vdwmrw28knpnde34c7ja5cfqhtlyl69x53t9exe2g7f0qcva2nn",
    },
}

# The site list as the federation signed it. The coordinator sends these bytes
# as they are: the signature covers them, so parsing and writing the document
# again would break it.
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
  ],
  "ls_login_keys": [
    {"jwk": {"kty": "RSA", "kid": "2026-04", "alg": "RS256", "use": "sig", "n": "0vx7agoe...",
             "e": "AQAB"},
     "published_from": "2026-04-01T00:00:00Z", "published_until": "2026-10-01T00:00:00Z"},
    {"jwk": {"kty": "RSA", "kid": "2026-10", "alg": "RS256", "use": "sig", "n": "xjlCRBqk...",
             "e": "AQAB"},
     "published_from": "2026-10-01T00:00:00Z"}
  ]
}
"""
SITE_LIST_SIGNATURE = "7vE1qDk3..."

# For every call under /tasks/{task_id}/attempts/{attempt}. The same answer for
# all three cases, so a node cannot learn whether another node's task exists.
TASK_NOT_FOUND = {
    404: {
        "model": Problem,
        "description": "Not a task of the calling node, not its current attempt, or its lease "
        "is no longer valid.",
    }
}


def study_version(study_id: str, version: int) -> StudyVersion:
    def member(member: str, ls_aai_id: str) -> dict:
        return {
            "member": member,
            "ls_aai_id": ls_aai_id,
            **MEMBER_KEYS[member],
            "binding_token": "eyJhbGciOiJSUzI1NiIs...",
        }

    return StudyVersion.model_validate(
        {
            "study_id": study_id,
            "version": version,
            **({"previous_digest": "sha256:1c7e..."} if version > 1 else {}),
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
            "result_recipients": "submitter",
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
                "not_after": f"{now + timedelta(days=7):%Y-%m-%dT%H:%M:%SZ}",
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
    response_model_exclude_unset=True,
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
            PendingApproval(kind="study", study_id="st-01", version=4, digest="sha256:e07b..."),
            PendingApproval(kind="workflow", study_id="st-01", version=3, digest=WORKFLOW_DIGEST),
        ],
        control=[ControlMessage(type="cancel", task_id="tk_6ff0...", attempt=1)],
    )


@router.get(
    "/studies/{study_id}/versions/{version}",
    summary="A study version waiting for this node's approval",
    response_model_exclude_unset=True,
)
async def get_study_version(study_id: str, version: int) -> StudyVersion:
    return study_version(study_id, version)


@router.get(
    "/workflows/{digest}",
    summary="A workflow waiting for this node's approval",
    response_model_exclude_unset=True,
)
async def get_workflow(digest: str) -> Workflow:
    return WORKFLOW


@router.post(
    "/approvals",
    status_code=204,
    summary="A data manager's signed approval, refusal or withdrawal",
)
async def post_approval(approval: Approval) -> None:
    """The coordinator knows a decision by the calling node and its decision_id. The agent
    sends a decision again when it cannot tell whether it arrived: one already held
    gets the same answer and is not stored twice. The signature is checked against the
    calling node's signing key on the site list, and decision.node must be that node."""


@router.post(
    "/tasks/{task_id}/attempts/{attempt}/decision",
    status_code=204,
    responses=TASK_NOT_FOUND,
    summary="Accept or refuse a delivered task after the local checks",
)
async def post_task_decision(task_id: str, attempt: int, decision: TaskDecision) -> None:
    """A refusal is final for that request at that node: the same request delivered again
    gets the same refusal."""


@router.post(
    "/tasks/{task_id}/attempts/{attempt}/events",
    status_code=204,
    responses=TASK_NOT_FOUND,
    summary="Report a state change at once instead of on the next poll",
)
async def post_task_event(task_id: str, attempt: int, event: TaskEvent) -> None:
    """The same state also arrives in the next poll, so a lost event only costs delay."""


@router.put(
    "/tasks/{task_id}/attempts/{attempt}/partial",
    status_code=204,
    responses=TASK_NOT_FOUND
    | {409: {"model": Problem, "description": "Different bytes were already uploaded."}},
    summary="Upload the encrypted partial",
    # The body is the ciphertext itself, not JSON.
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/octet-stream": {"schema": {"type": "string", "format": "binary"}}
            },
        }
    },
)
async def put_partial(
    task_id: str,
    attempt: int,
    digest: Annotated[
        str, Header(alias="Digest", description="sha-256=<base64 of the body's SHA-256>")
    ],
) -> None:
    """The coordinator checks the lease and the digest. Uploading the same bytes again
    changes nothing."""


@router.post(
    "/tasks/{task_id}/attempts/{attempt}/commit",
    responses=TASK_NOT_FOUND,
    summary="Commit the partial with the node's signed statement",
    response_model_exclude_unset=True,
)
async def commit_partial(task_id: str, attempt: int, commit: PartialCommit) -> PartialCommit:
    """The coordinator makes the partial available to the study's result recipients.
    A repeated commit returns the stored one. A result withheld at barrier 1 is committed
    as withheld, with no partial and no subject, so the job can finish."""
    return commit
