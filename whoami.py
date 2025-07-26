from mcp.server.fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.routing import Mount
from starlette.middleware import Middleware
from mcpauth import MCPAuth
from mcpauth.config import AuthServerType
from mcpauth.utils import fetch_server_config
from typing import Any
import pydantic
import requests
from mcpauth.exceptions import (
    MCPAuthTokenVerificationException,
    MCPAuthTokenVerificationExceptionCode,
)
from mcpauth.types import AuthInfo
import logging

import logging
 
# Configure logging

logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

 
auth_issuer = "https://dev-u2gjr1qq43hqstd0.us.auth0.com/"
auth_server_config = fetch_server_config(auth_issuer, type=AuthServerType.OAUTH)
mcp_auth = MCPAuth(server=auth_server_config)
mcp = FastMCP("WhoAmI")
def verify_access_token(token: str) -> AuthInfo:
    """
    Verifies the provided Bearer token by fetching user information from the authorization server.
    If the token is valid, it returns an `AuthInfo` object containing the user's information.

    :param token: The Bearer token to received from the MCP inspector.
    """
    try:
        # The following code assumes your authorization server has an endpoint for fetching user info
        # using the access token issued by the authorization flow.
        # Adjust the URL and headers as needed based on your provider's API.
        response = requests.get(
            "https://dev-u2gjr1qq43hqstd0.us.auth0.com/userinfo",
            headers={"Authorization": f"Bearer {token}"}
        )
        # breakpoint()
        response.raise_for_status() # Ensure we raise an error for HTTP errors
        json = response.json() # Parse the JSON response
        # logging.info(f"Response JSON: {json}")
        # The following code assumes the user info response is an object with a 'sub' field that
        # identifies the user. You may need to adjust this based on your provider's API.
        return AuthInfo(
            token=token,
            subject=json.get("sub"), # Replace with the actual user ID from the response
            issuer=auth_issuer, # Use the configured issuer
            claims=json, # Include all claims (JSON fields) returned by the endpoint
        )
    # `AuthInfo` is a Pydantic model, so validation errors usually mean the response didn't match
    # the expected structure
    except pydantic.ValidationError as e:
        logging.exception("An error occurred 1")
        raise MCPAuthTokenVerificationException(
            MCPAuthTokenVerificationExceptionCode.INVALID_TOKEN,
            cause=e, 
        )
    # Handle other exceptions that may occur during the request
    except Exception as e:
        logging.exception("An error occurred 2")
        raise MCPAuthTokenVerificationException(
            MCPAuthTokenVerificationExceptionCode.TOKEN_VERIFICATION_FAILED,
            cause=e,
        )

@mcp.tool()
def whoami() -> dict[str, Any]:
    """A tool that returns the current user's information."""
    return (
        mcp_auth.auth_info.claims
        if mcp_auth.auth_info # This will be populated by the Bearer auth middleware
        else {"error": "Not authenticated"}
    )

@mcp.tool()
def food_recommendation() -> dict[str, Any]:
    """
    Suggests a healthy food option for the authenticated user.
    """
    if not mcp_auth.auth_info or not mcp_auth.auth_info.claims:
        return {"error": "Not authenticated"}
    
    user_email = mcp_auth.auth_info.claims.get("email", "unknown")

    suggestions = [
        "Grilled salmon with quinoa",
        "Avocado toast with poached egg",
        "Greek yogurt with berries",
        "Chickpea salad with lemon dressing",
        "Oatmeal with banana and peanut butter"
    ]
    
    index = hash(user_email) % len(suggestions)
    suggested_food = suggestions[index]

    return {
        "user": user_email,
        "suggested_dish": suggested_food,
        "message": f"Suggested dish for {user_email}: {suggested_food}"
    }

bearer_auth = Middleware(mcp_auth.bearer_auth_middleware(verify_access_token))
app = Starlette(
    routes=[
        # Add the metadata route (`/.well-known/oauth-authorization-server`)
        mcp_auth.metadata_route(),
        # Protect the MCP server with the Bearer auth middleware
        Mount('/', app=mcp.sse_app(), middleware=[bearer_auth]),
    ],
)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8031)