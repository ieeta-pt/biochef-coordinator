"""The rules the request and response models enforce."""

import json

import pytest
import rfc8785
from pydantic import ValidationError

from coordinator.models import (
    Approval,
    JobSubmission,
    KeyRegistration,
    Partial,
    Statement,
    TaskDecision,
    TaskEvent,
    TaskRefusal,
)
from tests.documents import (
    MEMBER_KEYS,
    SIGNATURE,
    node_decision,
    request_refusal,
    statement,
    task,
)


def dump(model):
    return model.model_dump(mode="json", by_alias=True, exclude_unset=True)


def keys(**changes):
    return {**MEMBER_KEYS, "binding_token": "eyJhbGciOiJSUzI1NiIs..."} | changes


def signing_key(**changes):
    return MEMBER_KEYS["signing_key"] | changes


# Member keys: hashed exactly as sent into the binding token's nonce, so never normalised.


def test_the_identity_test_vector_is_accepted_and_kept_as_sent():
    body = keys()
    assert dump(KeyRegistration.model_validate(body)) == body


def test_a_coordinate_whose_last_bits_are_set_is_refused():
    # 43 characters hold 258 bits, so "t" decodes to the same bytes as "s".
    x = MEMBER_KEYS["signing_key"]["x"]
    assert x.endswith("s")
    with pytest.raises(ValidationError, match="canonical"):
        KeyRegistration.model_validate(keys(signing_key=signing_key(x=x[:-1] + "t")))


@pytest.mark.parametrize("field", ["kid", "alg", "use"])
def test_a_signing_key_with_more_than_kty_crv_x_and_y_is_refused(field):
    with pytest.raises(ValidationError, match="Extra inputs"):
        KeyRegistration.model_validate(keys(signing_key=signing_key(**{field: "x"})))


def test_a_result_key_in_uppercase_is_refused():
    with pytest.raises(ValidationError):
        KeyRegistration.model_validate(keys(result_key=MEMBER_KEYS["result_key"].upper()))


# Node decisions: the coordinator passes them on, so it must keep them as signed.


@pytest.mark.parametrize(
    "decision",
    [
        node_decision(at="2026-10-29T00:00:00.000Z"),
        node_decision(subject_type="workflow_version", user="agent", dac_confirmed=None),
        node_decision(action="withdraw", reason="superseded", dac_confirmed=None),
    ],
    ids=["study approval", "workflow approval by the agent", "superseded withdrawal"],
)
def test_a_decision_comes_back_byte_for_byte_as_the_node_signed_it(decision):
    if decision["dac_confirmed"] is None:
        del decision["dac_confirmed"]  # the agent leaves it out of other decisions
    signed = rfc8785.dumps(decision)
    approval = Approval.model_validate(
        {"decision_id": 1, "decision": json.loads(signed), "signature": SIGNATURE}
    )
    assert rfc8785.dumps(dump(approval)["decision"]) == signed


def test_a_number_written_as_a_string_is_refused_not_converted():
    with pytest.raises(ValidationError):
        Approval.model_validate(
            {"decision_id": "1", "decision": node_decision(), "signature": SIGNATURE}
        )


def test_a_decision_time_without_its_zone_is_refused():
    with pytest.raises(ValidationError, match="zone"):
        Approval.model_validate(
            {
                "decision_id": 1,
                "decision": node_decision(at="2026-10-29T00:00:00"),
                "signature": SIGNATURE,
            }
        )


@pytest.mark.parametrize(
    "decision",
    [
        {k: v for k, v in node_decision().items() if k != "dac_confirmed"},
        node_decision(subject_type="workflow_version"),
        node_decision(action="refuse"),
    ],
    ids=["study approval without it", "workflow approval with it", "study refusal with it"],
)
def test_dac_confirmed_comes_with_a_study_approval_and_nothing_else(decision):
    with pytest.raises(ValidationError, match="dac_confirmed"):
        Approval.model_validate({"decision_id": 1, "decision": decision, "signature": SIGNATURE})


# Task verdicts and events: codes only, so nothing about the data leaves the node.


def refusal(**changes):
    return {"decision_id": 9, "decision": request_refusal(**changes), "signature": SIGNATURE}


def test_a_refused_verdict_carries_the_nodes_signed_refusal():
    TaskDecision.model_validate({"verdict": "refused", "refusal": refusal()})
    with pytest.raises(ValidationError, match="signed refusal"):
        TaskDecision.model_validate({"verdict": "refused"})
    with pytest.raises(ValidationError, match="signed refusal"):
        TaskDecision.model_validate({"verdict": "accepted", "refusal": refusal()})


@pytest.mark.parametrize(
    "changes",
    [{"reason": "the file was too big"}, {"subject_hash": "sha256:" + "a" * 64}],
    ids=["free text reason", "subject_hash"],
)
def test_a_refusal_is_a_known_code_on_a_request_with_no_digest(changes):
    with pytest.raises(ValidationError):
        TaskRefusal.model_validate(refusal(**changes))


def test_a_failed_state_and_only_a_failed_state_has_a_reason():
    TaskEvent.model_validate(
        {"seq": 1, "at": "2026-11-26T10:00:00Z", "state": "failed", "reason": "executor_error"}
    )
    for event in [
        {"state": "failed"},
        {"state": "running", "reason": "executor_error"},
        {"state": "failed", "reason": "Traceback (most recent call last)"},
    ]:
        with pytest.raises(ValidationError):
            TaskEvent.model_validate({"seq": 1, "at": "2026-11-26T10:00:00Z"} | event)


# Partials: the node's signature covers whether a result left and which bytes hold it.


@pytest.mark.parametrize("decision", ["released", "withheld"])
def test_a_statement_comes_back_byte_for_byte_as_the_node_signed_it(decision):
    signed = rfc8785.dumps(statement(decision))
    assert rfc8785.dumps(dump(Statement.model_validate(json.loads(signed)))) == signed


@pytest.mark.parametrize(
    "document",
    [
        statement("released", ciphertext_digest=None),
        statement("released", ciphertext_size=None),
        statement("released") | {"subject": []},
    ],
    ids=["no ciphertext_digest", "no ciphertext_size", "no files"],
)
def test_a_released_statement_names_its_files_and_its_ciphertext(document):
    with pytest.raises(ValidationError, match="released"):
        Statement.model_validate(document)


@pytest.mark.parametrize(
    "document",
    [
        statement("withheld", ciphertext_digest="sha256:" + "a" * 64),
        statement("withheld", ciphertext_size=10),
        statement("withheld") | {"subject": statement("released")["subject"]},
    ],
    ids=["ciphertext_digest", "ciphertext_size", "files"],
)
def test_a_withheld_statement_names_no_files_and_no_ciphertext(document):
    with pytest.raises(ValidationError, match="withheld"):
        Statement.model_validate(document)


def test_a_withheld_statement_may_say_its_ciphertext_is_null():
    # The agent writes the absent values as null, and signs them that way.
    Statement.model_validate(statement("withheld", ciphertext_digest=None, ciphertext_size=None))


def test_the_decision_is_not_outside_the_signed_statement():
    with pytest.raises(ValidationError, match="Extra inputs"):
        Statement.model_validate(statement("released") | {"decision": "released"})


def partial(decision, ciphertext):
    return {
        "node": "biodata-pt",
        "attempt": 1,
        "statement": statement(decision),
        "signature": SIGNATURE,
        "ciphertext": ciphertext,
    }


def test_a_partial_carries_its_ciphertext_only_when_released():
    Partial.model_validate(partial("released", "YWdl"))
    Partial.model_validate(partial("withheld", None))
    with pytest.raises(ValidationError, match="ciphertext"):
        Partial.model_validate(partial("released", None))
    with pytest.raises(ValidationError, match="ciphertext"):
        Partial.model_validate(partial("withheld", "YWdl"))


# Jobs: one request, signed once per node.


def test_a_job_has_one_task_per_node_under_its_request_id():
    JobSubmission.model_validate({"request_id": "rq_1", "tasks": [task("a"), task("b")]})


@pytest.mark.parametrize(
    ("tasks", "message"),
    [
        ([task("a"), task("b", request_id="rq_2")], "request_id"),
        ([task("a"), task("a")], "one task per node"),
        ([task("a"), task("b", workflow_digest="sha256:" + "c" * 64)], "same study version"),
        ([task("a"), task("b", study_version=2)], "same study version"),
        ([task("a"), task("b", member="m-01")], "same study version"),
    ],
    ids=[
        "another request_id",
        "a node twice",
        "another workflow",
        "another version",
        "another member",
    ],
)
def test_a_job_whose_tasks_disagree_is_refused(tasks, message):
    with pytest.raises(ValidationError, match=message):
        JobSubmission.model_validate({"request_id": "rq_1", "tasks": tasks})
