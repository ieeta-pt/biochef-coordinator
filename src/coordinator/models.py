"""The JSON bodies the API sends and receives, as Pydantic models.

These are API documents, not database tables. The shapes come from the spec
("BioChef Coordination Hub API"); the numbers in the docstrings are its sections.
"""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

Digest = str
"""A SHA-256 digest, written sha256:<hex>."""


# Members and their keys


class SigningKey(BaseModel):
    """A member's public signing key, as a P-256 JWK."""

    kty: Literal["EC"]
    crv: Literal["P-256"]
    x: str
    y: str


class KeyRegistration(BaseModel):
    """PUT /me/keys (7.1)."""

    signing_key: SigningKey
    result_key: str = Field(description="The age public key that partials are encrypted for.")
    binding_token: str = Field(
        description="LS Login ID token whose nonce is the hash of both keys (8)."
    )


class Member(BaseModel):
    """A researcher as listed in a study version (7.1)."""

    member: str
    ls_aai_id: str
    signing_key: SigningKey
    result_key: str
    binding_token: str


# Studies


class StudyNode(BaseModel):
    node: str
    encryption_key: Digest = Field(description="Fingerprint of the node's encryption key.")
    datasets: list[str]


class OutputRules(BaseModel):
    aggregates_only: bool
    min_count: int
    types: list[str]
    max_bytes: int


class StudyVersion(BaseModel):
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


class ToolData(BaseModel):
    repo: str = Field(description="The tool, pinned by digest.")
    paramValues: dict[str, Any]


class WorkflowNode(BaseModel):
    id: str
    type: Literal["workflowNode", "inputWorkflowNode", "outputWorkflowNode"]
    data: ToolData | None = Field(None, description="Only on tool nodes (workflowNode).")


class WorkflowEdge(BaseModel):
    source: str
    sourceHandle: str
    target: str
    targetHandle: str | None = None


class Workflow(BaseModel):
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


class JobRequest(BaseModel):
    """What the member signs, once per node"""

    request_id: str
    study_id: str
    study_version: int
    study_digest: Digest
    workflow_digest: Digest
    member: str
    node: str
    datasets: list[str]
    not_after: datetime
    payload_digest: Digest


class Signature(BaseModel):
    alg: Literal["ES256"]
    key: str
    sig: str


class EncryptedPayload(BaseModel):
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


class StatementSubject(BaseModel):
    name: str
    digest: dict[str, str]


class PartialPredicate(BaseModel):
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


class Statement(BaseModel):
    """A node's outer statement on a partial, as an in-toto Statement"""

    type: str = Field("https://in-toto.io/Statement/v1", alias="_type")
    subject: list[StatementSubject] = Field(
        default_factory=list, description="Empty when the result was withheld."
    )
    predicateType: str = "https://biochef.app/partial/v1"
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


class Approval(BaseModel):
    """A data manager's decision on a study version or a workflow, signed with the node key"""

    kind: Literal["study", "workflow"]
    study_id: str
    study_version: int
    study_digest: Digest
    workflow_digest: Digest | None = Field(None, description="Only for a workflow.")
    node: str
    decision_id: int = Field(description="The node's own id for it, unique only within the node.")
    decision: Literal["approved", "refused", "withdrawn"]
    at: datetime
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


class PartialCommit(BaseModel):
    """The node's outer statement on a partial, signed with the node key"""

    decision: Literal["released", "withheld"]
    statement: Statement
    signature: str
