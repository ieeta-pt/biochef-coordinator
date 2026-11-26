"""Every route answers with its mock, and openapi.json describes what the app serves."""

import base64
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import rfc8785
from fastapi.testclient import TestClient

from coordinator import agent, researcher
from coordinator.main import app
from tests.documents import MEMBER_KEYS, SIGNATURE, node_decision, statement, task

# Without `with`, the lifespan never runs, so no database is needed.
client = TestClient(app)


def dump(model):
    return model.model_dump(mode="json", by_alias=True, exclude_unset=True)


PATH = {
    "study_id": "st-01",
    "version": 3,
    "digest": "sha256:" + "a" * 64,
    "job_id": "j-19c",
    "task_id": "tk_1",
    "attempt": 1,
}
STUDY = dump(agent.study_version("st-01", 3))
POLL = {
    "api_version": "1",
    "agent": {
        "version": "0.1.0",
        "profile": "tre",
        "runner": "apptainer",
        "signing_mode": "strict",
        "state": "alive",
    },
    "site_list_version": 14,
    "capacity": {"slots_total": 2, "slots_free": 1, "accepting": True},
    "active": [{"task_id": "tk_1", "attempt": 1, "lease_id": "ls_1", "state": "running"}],
}
CIPHERTEXT = b"age-encryption.org/v1..."
CIPHERTEXT_SHA256 = base64.b64encode(hashlib.sha256(CIPHERTEXT).digest()).decode()
UPLOAD = {"content": CIPHERTEXT, "headers": {"Content-Digest": f"sha-256=:{CIPHERTEXT_SHA256}:"}}

R, A, T = "/api/v1", "/api/agent/v1", "/api/agent/v1/tasks/{task_id}/attempts/{attempt}"
CALLS = [
    ("GET", f"{R}/sites", {}, 200),
    ("PUT", f"{R}/me/keys", {"json": {**MEMBER_KEYS, "binding_token": "eyJ..."}}, 200),
    ("POST", f"{R}/studies", {"json": STUDY}, 201),
    ("POST", f"{R}/studies/{{study_id}}/versions", {"json": STUDY}, 201),
    ("GET", f"{R}/studies/{{study_id}}", {}, 200),
    (
        "POST",
        f"{R}/studies/{{study_id}}/workflows",
        {"json": {"study_version": 3, "workflow": dump(researcher.WORKFLOW)}},
        201,
    ),
    ("GET", f"{R}/studies/{{study_id}}/workflows", {}, 200),
    ("POST", f"{R}/studies/{{study_id}}/workflows/{{digest}}/withdraw", {}, 200),
    (
        "POST",
        f"{R}/studies/{{study_id}}/jobs",
        {"json": {"request_id": "rq_1", "tasks": [task("biodata-pt"), task("ifb-fr")]}},
        201,
    ),
    ("GET", f"{R}/jobs/{{job_id}}", {}, 200),
    ("GET", f"{R}/jobs/{{job_id}}/events", {}, 200),
    ("POST", f"{R}/jobs/{{job_id}}/cancel", {}, 202),
    ("GET", f"{R}/jobs/{{job_id}}/partials", {}, 200),
    ("GET", f"{A}/site-list", {}, 200),
    ("POST", f"{A}/poll", {"json": POLL}, 200),
    ("GET", f"{A}/studies/{{study_id}}/versions/{{version}}", {}, 200),
    ("GET", f"{A}/workflows/{{digest}}", {}, 200),
    (
        "POST",
        f"{A}/approvals",
        {"json": {"decision_id": 1, "decision": node_decision(), "signature": SIGNATURE}},
        204,
    ),
    ("POST", f"{T}/decision", {"json": {"verdict": "accepted"}}, 204),
    (
        "POST",
        f"{T}/events",
        {"json": {"seq": 1, "at": "2026-11-26T10:00:00Z", "state": "running"}},
        204,
    ),
    ("PUT", f"{T}/partial", UPLOAD, 204),
    (
        "POST",
        f"{T}/commit",
        {"json": {"statement": statement("withheld"), "signature": SIGNATURE}},
        200,
    ),
]


@pytest.fixture(autouse=True)
def no_waiting(monkeypatch):
    """The scripted job events pause between states; the tests need not."""

    async def sleep(seconds):
        pass

    monkeypatch.setattr(researcher, "asyncio", SimpleNamespace(sleep=sleep))


@pytest.mark.parametrize(
    ("method", "path", "call", "status"), CALLS, ids=[f"{m} {p}" for m, p, _, _ in CALLS]
)
def test_every_route_answers_with_its_mock(method, path, call, status):
    response = client.request(method, path.format(**PATH), **call)
    assert response.status_code == status, response.text


def test_every_route_is_called_above():
    served = {
        (method.upper(), path)
        for path, operations in app.openapi()["paths"].items()
        for method in operations
    }
    assert {(m, p) for m, p, _, _ in CALLS} == served - {("GET", "/healthz")}


def test_the_job_events_are_server_sent_states_that_end_complete():
    response = client.get(f"{R}/jobs/j-19c/events")
    assert response.headers["content-type"].startswith("text/event-stream")
    states = [
        json.loads(line[5:])["state"]
        for line in response.text.splitlines()
        if line.startswith("data:")
    ]
    assert states[-1] == "complete" and set(states[:-1]) == {"running"}


def test_the_site_list_is_served_exactly_as_it_was_signed():
    response = client.get(f"{A}/site-list")
    assert response.content == agent.SITE_LIST
    assert response.headers["BioChef-Signature"] == agent.SITE_LIST_SIGNATURE


def test_a_poll_names_the_version_of_the_site_list_it_would_get():
    served = json.loads(client.get(f"{A}/site-list").content)["version"]
    assert client.post(f"{A}/poll", json=POLL).json()["site_list_version"] == served


@pytest.mark.parametrize("decision", ["released", "withheld"])
def test_a_commit_comes_back_byte_for_byte_as_the_node_signed_it(decision):
    sent = statement(decision)
    response = client.post(
        f"{A}/tasks/tk_1/attempts/1/commit", json={"statement": sent, "signature": SIGNATURE}
    )
    assert response.status_code == 200, response.text
    assert rfc8785.dumps(response.json()["statement"]) == rfc8785.dumps(sent)


def test_an_upload_says_its_content_digest():
    response = client.put(f"{A}/tasks/tk_1/attempts/1/partial", content=UPLOAD["content"])
    assert response.status_code == 422


def test_an_invalid_request_is_a_problem_that_does_not_echo_its_input():
    body = {**MEMBER_KEYS, "binding_token": "eyJ-do-not-echo-me", "extra": "eyJ-nor-me"}
    response = client.put(f"{R}/me/keys", json=body)
    assert response.status_code == 422
    assert response.headers["content-type"] == "application/problem+json"
    assert "do-not-echo-me" not in response.text and "nor-me" not in response.text


def test_openapi_json_describes_the_api_this_app_serves():
    # Regenerate it with: uv run python -m coordinator.openapi
    committed = (Path(__file__).parents[1] / "openapi.json").read_text()
    assert json.dumps(app.openapi(), indent=2, sort_keys=True) + "\n" == committed
