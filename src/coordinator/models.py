"""The JSON bodies the API sends and receives, as Pydantic models.

These are API documents, not database tables. The shapes come from the spec
("BioChef Coordination Hub API"); the numbers in the docstrings are its sections.
"""

import base64
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    WithJsonSchema,
)

Digest = str
"""A SHA-256 digest, written sha256:<hex>."""


def _says_its_zone(value: str) -> str:
    try:
        moment = datetime.fromisoformat(value)
    except ValueError:
        raise ValueError("not an ISO 8601 date and time") from None
    if moment.tzinfo is None:
        raise ValueError("an ISO 8601 date and time must say its zone")
    return value


Timestamp = Annotated[
    str,
    AfterValidator(_says_its_zone),
    WithJsonSchema({"type": "string", "format": "date-time"}),
]
"""A date and time inside a signed document, kept as the exact string that was signed."""


class Signed(BaseModel):
    """A document, or part of one, that someone signed or hashed.

    The coordinator passes these on to whoever checks the signature, so it must hand
    on exactly what it received: a field dropped, or a value written another way
    (2026-10-29T00:00:00.000Z becoming 2026-10-29T00:00:00Z, "3" becoming 3), breaks
    the signature far from where it happened. So the model only checks. An unknown
    field or a value of the wrong type is refused, not dropped or converted, and a
    date and time stays the string that was signed. Routes that send one back set
    response_model_exclude_unset, so a field the sender left out stays out.
    """

    model_config = ConfigDict(extra="forbid", strict=True)


# Members and their keys


def _is_32_bytes(value: str) -> str:
    # 43 characters hold 258 bits; the last 2 must be zero, or two spellings decode
    # to the same coordinate.
    decoded = base64.urlsafe_b64decode(value + "=")
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode() != value:
        raise ValueError("not the canonical base64url form of 32 bytes")
    return value


Coordinate = Annotated[
    str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{43}$"), AfterValidator(_is_32_bytes)
]
"""A P-256 coordinate: 32 bytes, leading zeros kept, base64url without padding."""

AgeRecipient = Annotated[str, StringConstraints(pattern=r"^age1[02-9ac-hj-np-z]{58}$")]
"""An age X25519 recipient, in lowercase."""


class SigningKey(Signed):
    """A member's public signing key, as a P-256 JWK with exactly crv, kty, x and y."""

    kty: Literal["EC"]
    crv: Literal["P-256"]
    x: Coordinate
    y: Coordinate


class KeyRegistration(Signed):
    """PUT /me/keys.

    The nonce of binding_token is the hash of these keys exactly as sent (biochef-infra
    docs/identity.md), so keys in any other form are refused, never normalised: a
    normalised key would hash to something the member never signed in for.
    """

    signing_key: SigningKey
    result_key: AgeRecipient = Field(
        description="The age public key that partials are encrypted for."
    )
    binding_token: str = Field(
        description="LS Login ID token whose nonce is the hash of both keys (8)."
    )


class Member(Signed):
    """A researcher as listed in a study version (7.1)."""

    member: str
    ls_aai_id: str
    signing_key: SigningKey
    result_key: AgeRecipient
    binding_token: str


# Studies


class StudyNode(Signed):
    node: str
    encryption_key: Digest = Field(description="Fingerprint of the node's encryption key.")
    datasets: list[str]


class OutputRules(Signed):
    aggregates_only: bool
    min_count: int
    types: list[str]
    max_bytes: int


class StudyVersion(Signed):
    """One version of a study, signed by its proposer (7.1). Each node approves its digest."""

    study_id: str
    version: int
    previous_digest: Digest | None = None
    goal: str
    members: list[Member]
    nodes: list[StudyNode]
    output_rules: OutputRules
    proposer: str
    signature: str


class NodeApproval(BaseModel):
    """One node's decision on a study version or a workflow (3.2)."""

    node: str
    decision: Literal["pending", "approved", "refused", "withdrawn"]
    at: datetime | None = None


class StudyVersionStatus(BaseModel):
    version: int
    digest: Digest
    approvals: list[NodeApproval]


class Study(BaseModel):
    """GET /studies/{id}: the versions and each node's approval (7)."""

    study_id: str
    versions: list[StudyVersionStatus]


# Workflows


class ToolData(Signed):
    repo: str = Field(description="The tool, pinned by digest.")
    paramValues: dict[str, Any]


class WorkflowNode(Signed):
    id: str
    type: Literal["workflowNode", "inputWorkflowNode", "outputWorkflowNode"]
    data: ToolData | None = Field(None, description="Only on tool nodes (workflowNode).")


class WorkflowEdge(Signed):
    source: str
    sourceHandle: str
    target: str
    targetHandle: str | None = None


class Workflow(Signed):
    """A BioChef workflow in canonical form (3.4). Its digest identifies it."""

    nodes: list[WorkflowNode]
    edges: list[WorkflowEdge]


class AddWorkflow(BaseModel):
    """POST /studies/{id}/workflows (7)."""

    study_version: int
    workflow: Workflow
    workflowhub_id: str | None = None


class WorkflowStatus(BaseModel):
    """A workflow of a study and each node's approval (7)."""

    digest: Digest
    study_version: int
    workflowhub_id: str | None
    withdrawn: bool
    approvals: list[NodeApproval]


class LibraryWorkflow(BaseModel):
    """A pre-configured workflow, linked to WorkflowHub (7)."""

    name: str
    version: str
    description: str
    workflowhub_id: str
    digest: Digest
    workflow: Workflow


# Jobs


class JobRequest(Signed):
    """What the member signs, once per node"""

    request_id: str
    study_id: str
    study_version: int
    study_digest: Digest
    workflow_digest: Digest
    member: str
    node: str
    datasets: list[str]
    not_after: Timestamp
    payload_digest: Digest


class Signature(Signed):
    alg: Literal["ES256"]
    key: str
    sig: str


class EncryptedPayload(Signed):
    enc: Literal["age-x25519"]
    ciphertext: str = Field(description="Base64. Only the node can decrypt it.")


class SignedJobRequest(BaseModel):
    job_request: JobRequest
    signature: Signature
    payload: EncryptedPayload


class JobSubmission(BaseModel):
    """POST /studies/{id}/jobs: one signed request and payload per node"""

    request_id: str
    tasks: list[SignedJobRequest] = Field(min_length=1)


class TaskState(BaseModel):
    node: str
    state: Literal[
        "queued",
        "leased",
        "refused",
        "running",
        "barrier_1",
        "partial_delivered",
        "withheld",
        "failed",
        "canceled",
    ]
    attempt: int


class JobState(BaseModel):
    """GET /jobs/{id}, and each server-sent event"""

    job_id: str
    request_id: str
    study_id: str
    study_version: int
    workflow_digest: Digest
    submitted_by: str
    submitted_at: datetime
    state: Literal["running", "complete", "incomplete", "canceled"]
    tasks: list[TaskState]


# Results


class StatementSubject(Signed):
    name: str
    digest: dict[str, str]


class PartialPredicate(Signed):
    request_id: str
    task_id: str
    attempt: int
    study_id: str
    study_version: int
    study_digest: Digest
    workflow_digest: Digest
    node: str
    ciphertext_size: int | None = None
    recipient_key: Digest | None = Field(None, description="Fingerprint of the submitter's key.")


class Statement(Signed):
    """A node's outer statement on a partial, as an in-toto Statement"""

    type: Literal["https://in-toto.io/Statement/v1"] = Field(alias="_type")
    subject: list[StatementSubject] = Field(description="Empty when the result was withheld.")
    predicateType: Literal["https://biochef.app/partial/v1"]
    predicate: PartialPredicate


class Partial(BaseModel):
    """One node's result for a job, encrypted for the submitter"""

    node: str
    attempt: int
    decision: Literal["released", "withheld"]
    statement: Statement
    signature: str = Field(description="The node's signature over the statement.")
    ciphertext: str | None = Field(None, description="Base64. None when withheld.")


# Nodes


class SiteStatus(BaseModel):
    """A node's status, derived from its polls"""

    node: str
    status: Literal["online", "degraded", "offline"]
    last_poll_at: datetime | None
    queue_length: int


class SiteListNode(BaseModel):
    """One node on the site list, with its keys"""

    node: str
    encryption_key: str = Field(description="The age public key job payloads are encrypted for.")
    signing_key: str = Field(description="The public key that checks the node's signatures.")
    certificate: Digest = Field(description="Fingerprint of the node's client certificate.")


class SiteList(BaseModel):
    """The federation's site list. The coordinator serves it byte for byte, as it was signed"""

    version: int = Field(description="Increases with every new list.")
    expires_at: datetime = Field(description="ISO 8601, with its zone.")
    nodes: list[SiteListNode]


# Polling


class AgentInfo(BaseModel):
    """What the agent reports about itself in every poll"""

    version: str
    profile: str = Field(description='For example "tre".')
    runner: str = Field(description='For example "apptainer".')
    signing_mode: str = Field(description='For example "strict".')
    state: Literal["alive", "running", "waiting", "error"]


class Capacity(BaseModel):
    slots_total: int
    slots_free: int
    accepting: bool


AgentTaskState = Literal["queued", "running", "barrier_1", "held", "failed", "canceled"]
"""A task's state as the agent reports it."""


class ActiveTask(BaseModel):
    """A task the agent holds. Listing its lease renews it"""

    task_id: str
    attempt: int
    lease_id: str
    state: AgentTaskState


class PollRequest(BaseModel):
    """POST /poll: the agent's heartbeat"""

    api_version: str
    agent: AgentInfo
    site_list_version: int
    capacity: Capacity
    active: list[ActiveTask] = Field(default_factory=list)


class Lease(BaseModel):
    lease_id: str
    expires_at: datetime
    valid: bool = Field(description="False when the coordinator re-queued or canceled the attempt.")


class TaskEnvelope(BaseModel):
    """A task as the coordinator delivers it, which adds task_id, attempt and lease_id, unsigned"""

    task_id: str
    attempt: int
    lease_id: str
    job_request: JobRequest
    signature: Signature
    payload: EncryptedPayload


class PendingApproval(BaseModel):
    """A study version or a workflow waiting for this node's data manager"""

    kind: Literal["study", "workflow"]
    study_id: str
    version: int = Field(description="The study version.")
    digest: Digest = Field(description="The study version's digest, or the workflow's.")


class ControlMessage(BaseModel):
    """An instruction for the agent: stop this attempt of a task"""

    type: Literal["cancel"]
    task_id: str
    attempt: int


class PollResponse(BaseModel):
    server_time: datetime
    next_poll_after_s: int
    leases: list[Lease]
    tasks: list[TaskEnvelope]
    pending_approvals: list[PendingApproval]
    control: list[ControlMessage]


# Approvals


class Approval(Signed):
    """A data manager's decision on a study version or a workflow, signed with the node key"""

    kind: Literal["study", "workflow"]
    study_id: str
    study_version: int
    study_digest: Digest
    workflow_digest: Digest | None = Field(None, description="Only for a workflow.")
    node: str
    decision_id: int = Field(description="The node's own id for it, unique only within the node.")
    decision: Literal["approved", "refused", "withdrawn"]
    at: Timestamp
    signature: str


# Tasks

RefusalReason = Literal[
    "bad_signature",
    "key_not_in_study",
    "wrong_node",
    "study_not_approved",
    "workflow_not_approved",
    "workflow_digest_mismatch",
    "request_replayed",
    "expired",
    "visa_missing",
    "visa_expired",
    "visa_untrusted_issuer",
    "visa_subject_mismatch",
    "dataset_unknown",
    "no_capacity",
]
"""Why an agent refuses a task. A code only, so nothing about the data leaves the node."""


class TaskDecision(BaseModel):
    """The agent's answer to a delivered task, after its local checks"""

    decision: Literal["accept", "refuse"]
    reason: RefusalReason | None = Field(None, description="Only when refusing.")


class TaskEvent(BaseModel):
    """A state change, reported at once instead of on the next poll"""

    seq: int = Field(description="Increases within each attempt, to drop duplicates and spot gaps.")
    at: datetime
    state: AgentTaskState
    reason: str | None = Field(
        None, description="Only when failed: a code, such as tool_verification_failed."
    )


class PartialCommit(Signed):
    """The node's outer statement on a partial, signed with the node key"""

    decision: Literal["released", "withheld"]
    statement: Statement
    signature: str
