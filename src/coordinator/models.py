"""The JSON bodies the API sends and receives, as Pydantic models.

These are API documents, not database tables.
"""

import base64
from datetime import datetime
from typing import Annotated, Any, Literal, Self

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    WithJsonSchema,
    model_validator,
)

Digest = str
"""A SHA-256 digest: sha256: and 64 lowercase hex digits."""

Fingerprint = str
"""A public key's fingerprint: sha256: and the SHA-256, in lowercase hex, of the key
exactly as the site list writes it. For an age key, that is its recipient string."""


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


Ed25519Signature = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{86}$")]
"""A node's Ed25519 signature: 64 bytes in base64url without padding."""


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
        description="LS Login ID token whose nonce is the hash of both keys."
    )


class Member(Signed):
    """A researcher as listed in a study version"""

    member: str = Field(
        description="The member's id in the study, an opaque value such as m-02. Never "
        "shown as a name."
    )
    ls_aai_id: str
    signing_key: SigningKey
    result_key: AgeRecipient
    binding_token: str


class StudyNode(Signed):
    node: str
    encryption_key: Fingerprint = Field(
        description="Fingerprint of the node's encryption key, the age recipient on the site list."
    )
    datasets: list[str]


class OutputRules(Signed):
    aggregates_only: bool
    min_count: int
    types: list[str] = Field(
        description="File name suffixes allowed to leave, compared exactly with what follows "
        "the last dot, such as tsv."
    )
    max_bytes: int


class StudyVersion(Signed):
    """One version of a study, signed by its proposer.

    Each node approves its digest: the SHA-256 of its RFC 8785 form without signature.
    """

    study_id: str
    version: int
    previous_digest: Digest | None = None
    goal: str
    members: list[Member]
    nodes: list[StudyNode]
    output_rules: OutputRules
    result_recipients: Literal["submitter", "all_members"] = Field(
        description="Who can read the results: the member who submitted the job, or every "
        "member. The nodes approve it with the rest of the version, and each partial is "
        "encrypted for these members' result keys."
    )
    proposer: str
    signature: str


class NodeApproval(BaseModel):
    """Where one node stands on a study version or a workflow.

    A node approves one version of a study at a time. Approving a newer version makes
    the one it replaces superseded, with that version's workflows, and so does any
    older version still pending there: it can no longer be approved. A node signs no
    decision for a version it only skipped.
    """

    node: str
    decision: Literal["pending", "approved", "refused", "withdrawn", "superseded"]
    at: datetime | None = None


class StudyVersionStatus(BaseModel):
    version: int
    digest: Digest
    approvals: list[NodeApproval]


class Study(BaseModel):
    """GET /studies/{id}: the versions and each node's approval"""

    study_id: str
    versions: list[StudyVersionStatus]


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
    """A BioChef workflow, exactly as the member signs it.

    Its digest identifies it: the SHA-256 of its RFC 8785 form.
    """

    nodes: list[WorkflowNode]
    edges: list[WorkflowEdge]


class AddWorkflow(BaseModel):
    """POST /studies/{id}/workflows"""

    study_version: int
    workflow: Workflow


class WorkflowStatus(BaseModel):
    """A workflow of a study and each node's approval"""

    digest: Digest
    study_version: int
    withdrawn: bool
    approvals: list[NodeApproval]


class JobRequest(Signed):
    """What the member signs, once per node, with ES256 over its RFC 8785 form"""

    request_id: str
    study_id: str
    study_version: int
    study_digest: Digest
    workflow_digest: Digest
    member: str
    node: str
    datasets: list[str]
    not_after: Timestamp
    payload_digest: Digest = Field(description="The SHA-256 of the decrypted payload.")


class Signature(Signed):
    """The member's signature on job_request"""

    alg: Literal["ES256"]
    key: str | None = Field(
        None,
        description="Informative only: the node checks the signature with the signing key "
        "the study version lists for member.",
    )
    sig: str = Field(
        pattern=r"^[A-Za-z0-9_-]{86}$",
        description="r and s, 32 bytes each, in base64url without padding.",
    )


class EncryptedPayload(Signed):
    """The task's payload, encrypted for the node with age.

    Decrypted, it is a JSON object: workflow, the workflow to run, whose digest must be
    workflow_digest, and visas, the member's GA4GH visas as JWTs.
    """

    enc: Literal["age-x25519"]
    ciphertext: str = Field(description="The age ciphertext, in its binary form, in base64.")


class SignedJobRequest(BaseModel):
    job_request: JobRequest
    signature: Signature
    payload: EncryptedPayload


class JobSubmission(BaseModel):
    """POST /studies/{id}/jobs: one signed request and payload per node"""

    request_id: str
    tasks: list[SignedJobRequest] = Field(min_length=1)

    @model_validator(mode="after")
    def _one_job_one_request_per_node(self) -> Self:
        requests = [task.job_request for task in self.tasks]
        if any(request.request_id != self.request_id for request in requests):
            raise ValueError("every task carries the job's request_id")
        nodes = [request.node for request in requests]
        if len(set(nodes)) != len(nodes):
            raise ValueError("a job has one task per node")
        named = {
            (r.study_id, r.study_version, r.study_digest, r.workflow_digest, r.member)
            for r in requests
        }
        if len(named) != 1:
            raise ValueError("every task names the same study version, workflow and member")
        return self


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
    decision: Literal["released", "withheld"] = Field(
        description="Whether the result left the node. Inside the predicate, so the node's "
        "signature covers it and nobody passing the partial on can relabel it."
    )
    ciphertext_digest: Digest | None = Field(
        None,
        description="The SHA-256 of the age ciphertext in its binary form, as uploaded. Only "
        "when released.",
    )
    ciphertext_size: int | None = Field(
        None, description="The length in bytes of the age ciphertext in its binary form."
    )
    recipient_keys: list[Fingerprint] | None = Field(
        None,
        description="The result keys the partial is encrypted for: the submitter's, or every "
        "member's (result_recipients).",
    )


class Statement(Signed):
    """A node's outer statement on a partial, as an in-toto Statement.

    Released, it names the files that left and the ciphertext that holds them. Withheld,
    it names neither.
    """

    type: Literal["https://in-toto.io/Statement/v1"] = Field(alias="_type")
    subject: list[StatementSubject] = Field(
        description="The files in the partial, each with the SHA-256 of its contents. Empty "
        "when the result was withheld."
    )
    predicateType: Literal["https://biochef.app/partial/v1"]
    predicate: PartialPredicate

    @model_validator(mode="after")
    def _released_names_its_ciphertext(self) -> Self:
        predicate = self.predicate
        ciphertext = (predicate.ciphertext_digest, predicate.ciphertext_size)
        if predicate.decision == "released":
            if not self.subject or None in ciphertext:
                raise ValueError(
                    "a released partial names its files, ciphertext_digest and ciphertext_size"
                )
        elif self.subject or ciphertext != (None, None):
            raise ValueError("a withheld partial names no files and no ciphertext")
        return self


class Partial(BaseModel):
    """One node's result for a job, encrypted for the study's result recipients"""

    node: str
    attempt: int
    statement: Statement
    signature: Ed25519Signature = Field(
        description="The node's signature over the RFC 8785 form of statement."
    )
    ciphertext: str | None = Field(
        None,
        description="The age ciphertext, in its binary form, in base64. Its SHA-256 is "
        "ciphertext_digest. None when withheld.",
    )

    @model_validator(mode="after")
    def _ciphertext_only_when_released(self) -> Self:
        released = self.statement.predicate.decision == "released"
        if released != (self.ciphertext is not None):
            raise ValueError("a released partial carries its ciphertext, a withheld one has none")
        return self


class SiteStatus(BaseModel):
    """A node's status, derived from its polls"""

    node: str
    status: Literal["online", "degraded", "offline"]
    last_poll_at: datetime | None
    queue_length: int


class SiteListNode(BaseModel):
    """One node on the site list, with its keys"""

    node: str
    encryption_key: str = Field(
        description="The age X25519 recipient, in lowercase, that job payloads are encrypted "
        "for. Studies name it by its fingerprint."
    )
    signing_key: str = Field(
        description="The Ed25519 public key that checks the node's decisions and partials, as "
        "base64 of its DER SubjectPublicKeyInfo: the body of its PEM file."
    )
    certificate: Digest = Field(
        description="sha256: and the SHA-256, in lowercase hex, of the node's client certificate "
        "in DER."
    )


class LsLoginKey(BaseModel):
    """A key LS Login signs ID tokens with, now or in the past"""

    jwk: dict[str, Any] = Field(description="The public key as LS Login published it, with kid.")
    published_from: datetime = Field(description="When LS Login started publishing it.")
    published_until: datetime | None = Field(
        None, description="When LS Login stopped publishing it. Absent while it still does."
    )


class SiteList(BaseModel):
    """The federation's site list. The coordinator serves it byte for byte, as it was signed"""

    version: int = Field(description="Increases with every new list.")
    expires_at: datetime = Field(description="ISO 8601, with its zone.")
    nodes: list[SiteListNode]
    ls_login_keys: list[LsLoginKey] = Field(
        description="The history of LS Login's signing keys. A node checks each member's "
        "binding_token against it, so the token can still be checked after LS Login rotates "
        "its keys."
    )


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
    """An attempt's hold on its task. An attempt has one lease at a time, so the routes
    under /tasks/{task_id}/attempts/{attempt} name it by task and attempt."""

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
    """A study version or a workflow waiting for this node's data manager.

    Once the node approves a version of a study, older versions it never decided
    leave its list: the agent marks them superseded and sends no decision for them.
    """

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
    site_list_version: int = Field(
        description="The version of the site list the coordinator serves. When it is newer "
        "than the agent's, the agent fetches GET /site-list."
    )
    next_poll_after_s: int = Field(
        description="Seconds to wait before the next poll; 30 unless the coordinator is "
        "slowing agents down. A lease lasts three of these intervals, so an agent that polls "
        "less often than this loses its tasks."
    )
    leases: list[Lease]
    tasks: list[TaskEnvelope]
    pending_approvals: list[PendingApproval]
    control: list[ControlMessage]


class NodeDecision(Signed):
    """A decision exactly as the agent builds and signs it (biochef.node-decision.v1).

    The node signs its RFC 8785 form with its Ed25519 key. Decisions on study versions,
    workflow versions and requests leave the node; those on runs, egress and dataset
    bindings stay in it.
    """

    schema_: Literal["biochef.node-decision.v1"] = Field(alias="schema")
    node: str
    subject_id: str = Field(
        description="The node's own id for the subject: its row id for a study or workflow "
        "version, the request_id for a request."
    )
    subject_hash: Digest | None = Field(
        description="The digest of the study version or the workflow."
    )
    user: str = Field(
        description='Who decided, as the TRE\'s login names them; "agent" when the agent did.'
    )
    comment: str | None = Field(description="What the data manager wrote, if anything.")
    at: Timestamp


class VersionDecision(NodeDecision):
    """A data manager's approval, refusal or withdrawal of a study or workflow version"""

    subject_type: Literal["study_version", "workflow_version"]
    action: Literal["approve", "refuse", "withdraw"]
    reason: Literal["superseded"] | None = Field(
        description="superseded when approving a newer version of the study withdrew this one."
    )
    dac_confirmed: Literal[True] | None = Field(
        None,
        description="Only on approving a study version, and then required: the data access "
        "committee has granted access.",
    )

    @model_validator(mode="after")
    def _dac_only_on_study_approval(self) -> Self:
        study_approval = self.subject_type == "study_version" and self.action == "approve"
        if study_approval != (self.dac_confirmed is True):
            raise ValueError("dac_confirmed belongs to a study approval, which needs it")
        return self


class Approval(Signed):
    """POST /approvals: a decision on a study or workflow version, as the node sends it"""

    decision_id: int = Field(
        description="The node's id for the decision, unique only within the node. With the "
        "calling node it names the decision, so sending it again is harmless."
    )
    decision: VersionDecision
    signature: Ed25519Signature = Field(
        description="The node's signature over the RFC 8785 form of decision."
    )


RefusalReason = Literal[
    "bad_signature",
    "wrong_node",
    "study_not_approved",
    "workflow_not_approved",
    "dataset_not_in_study",
    "expired",
    "replay",
    "cannot_decrypt",
    "hash_mismatch",
    "visa_missing",
    "dataset_not_bound",
]
"""Why an agent refuses a task: the first of its checks that failed, in the order it runs
them (biochef-agent docs/agent-ui/SPEC.md section 6.3). A code only, so nothing about
the data leaves the node."""

FailureReason = Literal[
    "tool_unavailable",
    "tool_verification_failed",
    "executor_error",
    "system_error",
]
"""Why an accepted task failed: a tool could not be fetched or verified, a step failed
(the agent's EXECUTOR_ERROR) or the agent did (SYSTEM_ERROR). A code only: logs and step
output never leave the node."""


class RequestRefusal(NodeDecision):
    """The agent's own refusal of a request, signed like any decision of the node"""

    subject_type: Literal["request"]
    action: Literal["refuse"]
    subject_hash: None = Field(description="Always null: a request has no digest here.")
    reason: RefusalReason


class TaskRefusal(Signed):
    """A refusal as the node sends it. Its subject_id is the task's request_id"""

    decision_id: int = Field(
        description="The node's id for the decision, unique only within the node."
    )
    decision: RequestRefusal
    signature: Ed25519Signature = Field(
        description="The node's signature over the RFC 8785 form of decision."
    )


class TaskDecision(BaseModel):
    """The agent's verdict on a delivered task, after its checks"""

    verdict: Literal["accepted", "refused"]
    refusal: TaskRefusal | None = Field(
        None,
        description="Only when refused, and then required: the node's signed refusal, so the "
        "member sees why and the coordinator cannot make one up.",
    )

    @model_validator(mode="after")
    def _refusal_only_when_refused(self) -> Self:
        if (self.verdict == "refused") != (self.refusal is not None):
            raise ValueError("a refused verdict needs its signed refusal, an accepted one has none")
        return self


class TaskEvent(BaseModel):
    """A state change, reported at once instead of on the next poll"""

    seq: int = Field(description="Increases within each attempt, to drop duplicates and spot gaps.")
    at: datetime
    state: AgentTaskState
    reason: FailureReason | None = Field(
        None, description="Only when failed, and then required. Never free text."
    )

    @model_validator(mode="after")
    def _reason_only_when_failed(self) -> Self:
        if (self.state == "failed") != (self.reason is not None):
            raise ValueError("a failed state needs a reason, and no other state has one")
        return self


class PartialCommit(Signed):
    """The node's outer statement on a partial, signed with the node key"""

    statement: Statement
    signature: Ed25519Signature = Field(
        description="The node's signature over the RFC 8785 form of statement."
    )
