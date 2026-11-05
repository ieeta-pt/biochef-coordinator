"""The researcher-facing API (spec section 7), with mock responses.

Every operation answers with fixed example data taken from the spec. Nothing is
checked or stored yet.
"""

import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends
from fastapi.sse import EventSourceResponse

from coordinator.models import (
    AddWorkflow,
    JobState,
    JobSubmission,
    KeyRegistration,
    LibraryWorkflow,
    Member,
    NodeApproval,
    Partial,
    SiteStatus,
    Statement,
    Study,
    StudyVersion,
    StudyVersionStatus,
    TaskState,
    Workflow,
    WorkflowStatus,
)
from coordinator.problems import INVALID_REQUEST

router = APIRouter(prefix="/api/v1", tags=["researcher"], responses=INVALID_REQUEST)


def current_member() -> str:
    """The member making the call. Fixed for now; it will come from the Keycloak token."""
    return "m-02"


CurrentMember = Annotated[str, Depends(current_member)]


# Mock data, from the spec's examples.

NODES = ["biodata-pt", "ifb-fr", "nottingham"]
STUDY_DIGEST = "sha256:9f2c..."
WORKFLOW_DIGEST = "sha256:41ab..."
APPROVED_AT = datetime(2026, 10, 22, 9, 12, tzinfo=UTC)
SUBMITTED_AT = datetime(2026, 10, 22, 10, 0, tzinfo=UTC)


def approvals(decision: str) -> list[NodeApproval]:
    at = None if decision == "pending" else APPROVED_AT
    return [NodeApproval(node=node, decision=decision, at=at) for node in NODES]


WORKFLOW = Workflow.model_validate(
    {
        "nodes": [
            {
                "id": "gto.fasta.info-1779037868982",
                "type": "workflowNode",
                "data": {
                    "repo": "biochef-plugins-gto.fasta.info@sha256:5e0c...",
                    "paramValues": {},
                },
            },
            {"id": "in", "type": "inputWorkflowNode"},
            {"id": "o-stats", "type": "outputWorkflowNode"},
        ],
        "edges": [
            {"source": "gto.fasta.info-1779037868982", "sourceHandle": "out", "target": "o-stats"},
            {
                "source": "in",
                "sourceHandle": "out",
                "target": "gto.fasta.info-1779037868982",
                "targetHandle": "in",
            },
        ],
    }
)

WORKFLOW_STATUS = WorkflowStatus(
    digest=WORKFLOW_DIGEST,
    study_version=3,
    workflowhub_id="https://workflowhub.eu/workflows/1234?version=2",
    withdrawn=False,
    approvals=approvals("approved"),
)


def job_state(job_id: str, state: str, tasks: list[tuple[str, str, int]]) -> JobState:
    return JobState(
        job_id=job_id,
        request_id="rq_5b8e...",
        study_id="st-01",
        study_version=3,
        workflow_digest=WORKFLOW_DIGEST,
        submitted_by="m-02",
        submitted_at=SUBMITTED_AT,
        state=state,
        tasks=[TaskState(node=n, state=s, attempt=a) for n, s, a in tasks],
    )


def partial(node: str, task_id: str) -> Partial:
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "partial", "digest": {"sha256": "aa01..."}}],
        "predicateType": "https://biochef.app/partial/v1",
        "predicate": {
            "request_id": "rq_5b8e...",
            "task_id": task_id,
            "attempt": 1,
            "study_id": "st-01",
            "study_version": 3,
            "study_digest": STUDY_DIGEST,
            "workflow_digest": WORKFLOW_DIGEST,
            "node": node,
            "ciphertext_size": 18231,
            "recipient_key": "sha256:c41e...",
        },
    }
    return Partial(
        node=node,
        attempt=1,
        decision="released",
        statement=Statement.model_validate(statement),
        signature="MEUC...",
        ciphertext="YWdlLWVuY3J5cHRpb24...",
    )


# Nodes and keys


@router.get("/sites", summary="Each node's status")
async def list_sites() -> list[SiteStatus]:
    return [
        SiteStatus(node="biodata-pt", status="online", last_poll_at=SUBMITTED_AT, queue_length=0),
        SiteStatus(node="ifb-fr", status="degraded", last_poll_at=SUBMITTED_AT, queue_length=2),
        SiteStatus(node="nottingham", status="offline", last_poll_at=APPROVED_AT, queue_length=1),
    ]


@router.put("/me/keys", summary="Register the caller's signing key and result key")
async def register_keys(keys: KeyRegistration, member: CurrentMember) -> Member:
    return Member(member=member, ls_aai_id="d4e5f6...@lifescience-ri.eu", **keys.model_dump())


# Studies


@router.post("/studies", status_code=201, summary="Propose a study")
async def propose_study(study: StudyVersion) -> StudyVersionStatus:
    return StudyVersionStatus(
        version=study.version, digest=STUDY_DIGEST, approvals=approvals("pending")
    )


@router.post(
    "/studies/{study_id}/versions",
    status_code=201,
    summary="Propose a new version of a study; the nodes approve it again",
)
async def propose_study_version(study_id: str, study: StudyVersion) -> StudyVersionStatus:
    return StudyVersionStatus(
        version=study.version, digest=STUDY_DIGEST, approvals=approvals("pending")
    )


@router.get("/studies/{study_id}", summary="A study's versions and each node's approval")
async def get_study(study_id: str) -> Study:
    return Study(
        study_id=study_id,
        versions=[
            StudyVersionStatus(version=2, digest="sha256:1c7e...", approvals=approvals("approved")),
            StudyVersionStatus(version=3, digest=STUDY_DIGEST, approvals=approvals("approved")),
        ],
    )


# Workflows


@router.post(
    "/studies/{study_id}/workflows",
    status_code=201,
    summary="Add a workflow to an approved study version",
)
async def add_workflow(study_id: str, body: AddWorkflow) -> WorkflowStatus:
    return WorkflowStatus(
        digest=WORKFLOW_DIGEST,
        study_version=body.study_version,
        workflowhub_id=body.workflowhub_id,
        withdrawn=False,
        approvals=approvals("pending"),
    )


@router.get("/studies/{study_id}/workflows", summary="A study's workflows and their approvals")
async def list_workflows(study_id: str) -> list[WorkflowStatus]:
    return [WORKFLOW_STATUS]


@router.post(
    "/studies/{study_id}/workflows/{digest}/withdraw",
    summary="Withdraw a workflow from new jobs",
)
async def withdraw_workflow(study_id: str, digest: str) -> WorkflowStatus:
    return WORKFLOW_STATUS.model_copy(update={"digest": digest, "withdrawn": True})


@router.get(
    "/library/workflows",
    summary="Pre-configured workflows, linked to WorkflowHub",
    # Input nodes carry no data in the canonical form (spec 3.4): leave it out, not null.
    response_model_exclude_none=True,
)
async def list_library_workflows() -> list[LibraryWorkflow]:
    return [
        LibraryWorkflow(
            name="FASTA statistics",
            version="2",
            description="Counts and composition of the sequences in a FASTA file.",
            workflowhub_id="https://workflowhub.eu/workflows/1234?version=2",
            digest=WORKFLOW_DIGEST,
            workflow=WORKFLOW,
        )
    ]


# Jobs


@router.post("/studies/{study_id}/jobs", status_code=201, summary="Submit a job")
async def submit_job(study_id: str, job: JobSubmission, member: CurrentMember) -> JobState:
    first = job.tasks[0].job_request
    return JobState(
        job_id="j-19c",
        request_id=job.request_id,
        study_id=study_id,
        study_version=first.study_version,
        workflow_digest=first.workflow_digest,
        submitted_by=member,
        submitted_at=datetime.now(UTC),
        state="running",
        tasks=[TaskState(node=t.job_request.node, state="queued", attempt=1) for t in job.tasks],
    )


@router.get("/jobs/{job_id}", summary="The job's state and each task's state")
async def get_job(job_id: str) -> JobState:
    return job_state(
        job_id,
        "running",
        [
            ("biodata-pt", "partial_delivered", 1),
            ("ifb-fr", "barrier_1", 1),
            ("nottingham", "queued", 2),
        ],
    )


@router.get(
    "/jobs/{job_id}/events",
    response_class=EventSourceResponse,
    summary="Live progress of the job, as server-sent events",
)
async def job_events(job_id: str) -> AsyncIterator[JobState]:
    # A scripted run: every task goes from queued to partial_delivered.
    for task_state in ["queued", "running", "barrier_1", "partial_delivered"]:
        done = task_state == "partial_delivered"
        yield job_state(
            job_id, "complete" if done else "running", [(n, task_state, 1) for n in NODES]
        )
        if not done:
            await asyncio.sleep(1)


@router.post(
    "/jobs/{job_id}/cancel",
    status_code=202,
    summary="Cancel the job; running tasks stop on their next poll",
)
async def cancel_job(job_id: str) -> JobState:
    return job_state(job_id, "running", [(n, "running", 1) for n in NODES])


@router.get("/jobs/{job_id}/partials", summary="The encrypted partials, for the submitter only")
async def list_partials(job_id: str) -> list[Partial]:
    return [partial("biodata-pt", "tk_7a3d..."), partial("ifb-fr", "tk_7a4e...")]
