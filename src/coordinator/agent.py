"""The agent-facing API (spec section 3), with mock responses.

Every operation answers with fixed example data taken from the spec. Nothing is
checked or stored yet.
"""

from fastapi import APIRouter, Response

from coordinator.models import SiteList
from coordinator.problems import INVALID_REQUEST

router = APIRouter(prefix="/api/agent/v1", tags=["agent"], responses=INVALID_REQUEST)


# Mock data, from the spec's examples.

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
