"""Example documents for the tests, shaped as the agent and the editor build them.

Synthetic throughout: no real keys, people or data.
"""

DIGEST = "sha256:" + "a" * 64
SIGNATURE = "A" * 86
"""Any 64 bytes in base64url: nothing here checks signatures yet."""

# The nonce test vector in biochef-infra docs/identity.md. x starts with a zero byte.
MEMBER_KEYS = {
    "signing_key": {
        "kty": "EC",
        "crv": "P-256",
        "x": "AO1cfutKPq_Pj_qgqcxF6mw7pf0zvS0bOTf3G-GON1s",
        "y": "HjpzF_k9FmBSD7iiJq3QrtNRFM_uF0xVckpsACGAf38",
    },
    "result_key": "age1vpw3jerf7764tnxv0jvwg9umcmstqf2zxwvezp4xpeetjxwsgsdsesfryj",
}


def node_decision(**changes):
    """A study approval as the agent's node/decisions.py builds it, with every field."""
    return {
        "schema": "biochef.node-decision.v1",
        "node": "biodata-pt",
        "subject_type": "study_version",
        "subject_id": "12",
        "subject_hash": DIGEST,
        "action": "approve",
        "user": "dm.silva",
        "comment": None,
        "at": "2026-10-29T00:00:00Z",
        "reason": None,
        "dac_confirmed": True,
    } | changes


def request_refusal(**changes):
    """The agent's own refusal of a request, as node/requests.py decides it."""
    decision = node_decision(
        subject_type="request",
        subject_id="rq_1",
        subject_hash=None,
        action="refuse",
        user="agent",
        reason="expired",
    )
    del decision["dac_confirmed"]
    return decision | changes


def statement(decision="released", **predicate):
    """A node's statement on a partial: released with one file, or withheld."""
    released = decision == "released"
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "counts.tsv", "digest": {"sha256": "b" * 64}}] if released else [],
        "predicateType": "https://biochef.app/partial/v1",
        "predicate": {
            "request_id": "rq_1",
            "task_id": "tk_1",
            "attempt": 1,
            "study_id": "st-01",
            "study_version": 3,
            "study_digest": DIGEST,
            "workflow_digest": DIGEST,
            "node": "biodata-pt",
            "decision": decision,
            **({"ciphertext_digest": DIGEST, "ciphertext_size": 13672} if released else {}),
            "recipient_keys": [DIGEST],
        }
        | predicate,
    }


def task(node, **job_request):
    """One node's signed request and encrypted payload, as the editor submits it."""
    return {
        "job_request": {
            "request_id": "rq_1",
            "study_id": "st-01",
            "study_version": 3,
            "study_digest": DIGEST,
            "workflow_digest": DIGEST,
            "member": "m-02",
            "node": node,
            "datasets": ["EGAD00001001234"],
            "not_after": "2026-12-01T00:00:00Z",
            "payload_digest": DIGEST,
        }
        | job_request,
        "signature": {"alg": "ES256", "sig": SIGNATURE},
        "payload": {"enc": "age-x25519", "ciphertext": "YWdlLWVuY3J5cHRpb24="},
    }
