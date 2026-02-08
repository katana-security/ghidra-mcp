"""HTTP helpers, response simplification, and shared fetchers."""

import os
import time
from typing import Any
from urllib.parse import quote, urlparse

import requests

from state import get_instance_url, get_instance_port

ALLOWED_ORIGINS = os.environ.get("GHIDRA_ALLOWED_ORIGINS", "http://localhost").split(",")


# ---------------------------------------------------------------------------
# Origin validation
# ---------------------------------------------------------------------------

def validate_origin(headers: dict) -> bool:
    """Validate request origin against allowed origins."""
    origin = headers.get("Origin")
    if not origin:
        return True
    try:
        parsed = urlparse(origin)
        origin_base = f"{parsed.scheme}://{parsed.hostname}"
        if parsed.port:
            origin_base += f":{parsed.port}"
    except Exception:
        return False
    return origin_base in ALLOWED_ORIGINS


# ---------------------------------------------------------------------------
# Core request helper
# ---------------------------------------------------------------------------

def _make_request(
    method: str,
    port: int,
    endpoint: str,
    params: dict | None = None,
    json_data: dict | None = None,
    data: str | None = None,
    headers: dict | None = None,
) -> dict:
    """Internal helper to make HTTP requests and handle common errors."""
    url = f"{get_instance_url(port)}/{endpoint}"

    request_headers = {
        "Accept": "application/json",
        "X-Request-ID": f"mcp-bridge-{int(time.time() * 1000)}",
    }
    if headers:
        request_headers.update(headers)

    is_state_changing = method.upper() in ("POST", "PUT", "PATCH", "DELETE")
    if is_state_changing:
        check_headers = (
            json_data.get("headers", {}) if isinstance(json_data, dict) else (headers or {})
        )
        if not validate_origin(check_headers):
            return error_response("ORIGIN_NOT_ALLOWED", "Origin not allowed for state-changing request", 403)
        if json_data is not None:
            request_headers["Content-Type"] = "application/json"
        elif data is not None:
            request_headers["Content-Type"] = "text/plain"

    try:
        response = requests.request(
            method,
            url,
            params=params,
            json=json_data,
            data=data,
            headers=request_headers,
            timeout=60,
        )

        try:
            parsed_json = response.json()
            if isinstance(parsed_json, dict) and "timestamp" not in parsed_json:
                parsed_json["timestamp"] = int(time.time() * 1000)

            if (
                not response.ok
                and isinstance(parsed_json, dict)
                and "success" in parsed_json
                and not parsed_json["success"]
            ):
                if "error" in parsed_json and not isinstance(parsed_json["error"], dict):
                    error_message = parsed_json["error"]
                    parsed_json["error"] = {
                        "code": f"HTTP_{response.status_code}",
                        "message": error_message,
                    }
            return parsed_json

        except ValueError:
            if response.ok:
                return {
                    "success": False,
                    "error": {
                        "code": "NON_JSON_RESPONSE",
                        "message": "Received non-JSON success response from Ghidra plugin",
                    },
                    "status_code": response.status_code,
                    "response_text": response.text[:500],
                    "timestamp": int(time.time() * 1000),
                }
            return {
                "success": False,
                "error": {
                    "code": f"HTTP_{response.status_code}",
                    "message": f"Non-JSON error response: {response.text[:100]}...",
                },
                "status_code": response.status_code,
                "response_text": response.text[:500],
                "timestamp": int(time.time() * 1000),
            }

    except requests.exceptions.Timeout:
        return error_response("REQUEST_TIMEOUT", "Request timed out", 408)
    except requests.exceptions.ConnectionError:
        return error_response("CONNECTION_ERROR", f"Failed to connect to Ghidra instance at {url}", 503)
    except Exception as e:
        return {
            "success": False,
            "error": {"code": "UNEXPECTED_ERROR", "message": f"An unexpected error occurred: {str(e)}"},
            "exception": e.__class__.__name__,
            "timestamp": int(time.time() * 1000),
        }


# ---------------------------------------------------------------------------
# Convenience HTTP verbs
# ---------------------------------------------------------------------------

def safe_get(port: int, endpoint: str, params: dict | None = None) -> dict:
    """Make GET request to Ghidra instance."""
    return _make_request("GET", port, endpoint, params=params)


def safe_post(port: int, endpoint: str, data: dict | str) -> dict:
    """Make POST request with JSON or text payload."""
    headers = None
    json_payload = None
    text_payload = None
    if isinstance(data, dict):
        headers = data.pop("headers", None)
        json_payload = data
    else:
        text_payload = data
    return _make_request("POST", port, endpoint, json_data=json_payload, data=text_payload, headers=headers)


def safe_put(port: int, endpoint: str, data: dict) -> dict:
    """Make PUT request with JSON payload."""
    headers = data.pop("headers", None) if isinstance(data, dict) else None
    return _make_request("PUT", port, endpoint, json_data=data, headers=headers)


def safe_patch(port: int, endpoint: str, data: dict) -> dict:
    """Make PATCH request with JSON payload."""
    headers = data.pop("headers", None) if isinstance(data, dict) else None
    return _make_request("PATCH", port, endpoint, json_data=data, headers=headers)


def safe_delete(port: int, endpoint: str) -> dict:
    """Make DELETE request."""
    return _make_request("DELETE", port, endpoint)


# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------

def error_response(code: str, message: str, status_code: int | None = None) -> dict:
    """Build a standard error response dict."""
    resp: dict[str, Any] = {
        "success": False,
        "error": {"code": code, "message": message},
        "timestamp": int(time.time() * 1000),
    }
    if status_code is not None:
        resp["status_code"] = status_code
    return resp


def simplify_response(response: dict) -> dict:
    """Simplify HATEOAS response for AI agent consumption."""
    if not isinstance(response, dict):
        return response

    result = response.copy()

    api_metadata: dict[str, Any] = {}
    for key in ("id", "instance", "timestamp", "size", "offset", "limit"):
        if key in result:
            api_metadata[key] = result.get(key)

    if "result" in result:
        if isinstance(result["result"], list):
            simplified_items = []
            for item in result["result"]:
                if isinstance(item, dict):
                    item_copy = item.copy()
                    links = item_copy.pop("_links", None)
                    if isinstance(links, dict):
                        for link_name, link_data in links.items():
                            if isinstance(link_data, dict) and "href" in link_data:
                                item_copy[f"{link_name}_url"] = link_data["href"]
                    simplified_items.append(item_copy)
                else:
                    simplified_items.append(item)
            result["result"] = simplified_items

        elif isinstance(result["result"], dict):
            result_copy = result["result"].copy()
            links = result_copy.pop("_links", None)

            if isinstance(links, dict):
                for link_name, link_data in links.items():
                    if isinstance(link_data, dict) and "href" in link_data:
                        result_copy[f"{link_name}_url"] = link_data["href"]

            if "instructions" in result_copy and isinstance(result_copy["instructions"], list):
                disasm_text = ""
                for instr in result_copy["instructions"]:
                    if isinstance(instr, dict):
                        addr = instr.get("address", "")
                        mnemonic = instr.get("mnemonic", "")
                        operands = instr.get("operands", "")
                        bytes_str = instr.get("bytes", "")
                        disasm_text += f"{addr}: {bytes_str.ljust(10)}  {mnemonic} {operands}\n"
                result_copy["disassembly_text"] = disasm_text
                result_copy.pop("instructions", None)

            if "ccode" in result_copy:
                result_copy["decompiled_text"] = result_copy["ccode"]
            elif "decompiled" in result_copy:
                result_copy["decompiled_text"] = result_copy["decompiled"]

            result["result"] = result_copy

    links = result.pop("_links", None)
    if isinstance(links, dict):
        api_links: dict[str, str] = {}
        for link_name, link_data in links.items():
            if isinstance(link_data, dict) and "href" in link_data:
                api_links[link_name] = link_data["href"]
        if api_links:
            result["api_links"] = api_links

    for key, value in api_metadata.items():
        if key not in result:
            result[key] = value

    return result


# ---------------------------------------------------------------------------
# Shared fetchers (used by resources + tools)
# ---------------------------------------------------------------------------

def _extract_error_message(simplified: dict, default: str) -> str:
    """Pull the human-readable error out of a simplified response."""
    if isinstance(simplified, dict) and "error" in simplified:
        err = simplified["error"]
        if isinstance(err, dict):
            return err.get("message", default)
        return str(err)
    return default


def fetch_decompiled(port: int, address: str | None = None, name: str | None = None) -> str:
    """Fetch decompiled C code for a function (shared by resources + tools)."""
    port = get_instance_port(port)
    params = {"syntax_tree": "false", "style": "normalize"}

    if address:
        endpoint = f"functions/{address}/decompile"
    elif name:
        endpoint = f"functions/by-name/{quote(name)}/decompile"
    else:
        return "Error: Either address or name is required"

    response = safe_get(port, endpoint, params)
    simplified = simplify_response(response)

    if (
        not isinstance(simplified, dict)
        or not simplified.get("success", False)
        or "result" not in simplified
    ):
        return _extract_error_message(simplified, "Error: Could not decompile function")

    result = simplified["result"]
    if isinstance(result, dict):
        for key in ("decompiled_text", "ccode", "decompiled"):
            if key in result:
                return result[key]

    return "Error: Could not extract decompiled code from response"


def fetch_function_info(port: int, address: str | None = None, name: str | None = None) -> dict:
    """Fetch function metadata (shared by resources + tools)."""
    port = get_instance_port(port)

    if address:
        endpoint = f"functions/{address}"
    elif name:
        endpoint = f"functions/by-name/{quote(name)}"
    else:
        return error_response("MISSING_PARAMETER", "Either address or name is required")

    response = safe_get(port, endpoint)
    simplified = simplify_response(response)

    if (
        not isinstance(simplified, dict)
        or not simplified.get("success", False)
        or "result" not in simplified
    ):
        return {
            "success": False,
            "error": {
                "code": "FUNCTION_NOT_FOUND",
                "message": "Could not get function information",
                "details": simplified.get("error") if isinstance(simplified, dict) else None,
            },
            "timestamp": int(time.time() * 1000),
        }

    return simplified["result"]


def fetch_disassembly(port: int, address: str | None = None, name: str | None = None) -> str:
    """Fetch formatted disassembly listing (shared by resources + tools)."""
    port = get_instance_port(port)

    if address:
        endpoint = f"functions/{address}/disassembly"
    elif name:
        endpoint = f"functions/by-name/{quote(name)}/disassembly"
    else:
        return "Error: Either address or name is required"

    response = safe_get(port, endpoint)
    simplified = simplify_response(response)

    if (
        not isinstance(simplified, dict)
        or not simplified.get("success", False)
        or "result" not in simplified
    ):
        return _extract_error_message(simplified, "Error: Could not get disassembly")

    result = simplified["result"]

    if isinstance(result, dict) and "disassembly_text" in result:
        return result["disassembly_text"]

    if isinstance(result, dict) and "instructions" in result and isinstance(result["instructions"], list):
        disasm_text = ""
        for instr in result["instructions"]:
            if isinstance(instr, dict):
                addr = instr.get("address", "")
                mnemonic = instr.get("mnemonic", "")
                operands = instr.get("operands", "")
                bytes_str = instr.get("bytes", "")
                disasm_text += f"{addr}: {bytes_str.ljust(10)}  {mnemonic} {operands}\n"
        return disasm_text

    if isinstance(result, dict) and "disassembly" in result:
        return result["disassembly"]

    return "Error: Could not extract disassembly from response"
