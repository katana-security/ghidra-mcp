"""Comment tools -- set comments at addresses and on functions."""

import sys
from typing import Any

from fastmcp import FastMCP
from pydantic import Field

from http_client import error_response, safe_patch, safe_post, simplify_response
from state import get_instance_port


def register_comment_tools(server: FastMCP) -> None:

    @server.tool
    def comments_set(
        address: str = Field(description="Memory address in hex format"),
        comment: str = Field(default="", description="Comment text (empty string removes comment)"),
        comment_type: str = Field(
            default="plate",
            description='Type of comment - "plate", "pre", "post", "eol", "repeatable" (default: "plate")',
        ),
        port: int | None = Field(default=None, description="Specific Ghidra instance port (optional)"),
    ) -> dict[str, Any]:
        """Set a comment at the specified address."""
        if not address:
            return error_response("MISSING_PARAMETER", "Address parameter is required")

        port = get_instance_port(port)
        payload = {"comment": comment}
        response = safe_post(port, f"memory/{address}/comments/{comment_type}", payload)
        return simplify_response(response)

    @server.tool
    def functions_set_comment(
        address: str = Field(description="Memory address in hex format (preferably function entry point)"),
        comment: str = Field(default="", description="Comment text (empty string removes comment)"),
        port: int | None = Field(default=None, description="Specific Ghidra instance port (optional)"),
    ) -> dict[str, Any]:
        """Set a decompiler-friendly comment (tries function comment, falls back to pre-comment)."""
        if not address:
            return error_response("MISSING_PARAMETER", "Address parameter is required")

        port_to_use = get_instance_port(port)

        try:
            patch_response = safe_patch(port_to_use, f"functions/{address}", {"comment": comment})
            if patch_response.get("success", False):
                return simplify_response(patch_response)
            else:
                print(
                    f"Note: Failed to set function comment via PATCH on {address}, falling back. "
                    f"Error: {patch_response.get('error')}",
                    file=sys.stderr,
                )
        except Exception as e:
            print(f"Exception trying function comment PATCH: {e}. Falling back.", file=sys.stderr)

        print(f"Falling back to setting 'pre' comment for address {address}", file=sys.stderr)
        return comments_set(
            address=address, comment=comment, comment_type="pre", port=port_to_use
        )
