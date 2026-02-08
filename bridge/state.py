"""Instance registry, discovery, and shared state for the Ghidra MCP bridge."""

import os
import sys
import threading
import time
from typing import Any

import requests

BRIDGE_VERSION = "v2.1.0"
REQUIRED_API_VERSION = 2010

DEFAULT_GHIDRA_PORT = 8192
DEFAULT_GHIDRA_HOST = "localhost"
GHIDRA_HOST = os.environ.get("GHIDRA_HYDRA_HOST", DEFAULT_GHIDRA_HOST)

QUICK_DISCOVERY_RANGE = range(DEFAULT_GHIDRA_PORT, DEFAULT_GHIDRA_PORT + 10)
FULL_DISCOVERY_RANGE = range(DEFAULT_GHIDRA_PORT, DEFAULT_GHIDRA_PORT + 20)

active_instances: dict[int, dict] = {}
instances_lock = threading.Lock()
current_instance_port = DEFAULT_GHIDRA_PORT


def get_instance_port(port: int | None = None) -> int:
    """Get the current instance port or validate a specific port."""
    port = port or current_instance_port
    if port not in active_instances:
        register_instance(port)
        if port not in active_instances:
            raise ValueError(f"No active Ghidra instance on port {port}")
    return port


def get_instance_url(port: int) -> str:
    """Get URL for a Ghidra instance by port."""
    with instances_lock:
        if port in active_instances:
            return active_instances[port]["url"]
        if 8192 <= port <= 65535:
            register_instance(port)
            if port in active_instances:
                return active_instances[port]["url"]
    return f"http://{GHIDRA_HOST}:{port}"


def set_current_port(port: int) -> None:
    """Set the current working instance port."""
    global current_instance_port
    current_instance_port = port


def get_current_port() -> int:
    """Get the current working instance port."""
    return current_instance_port


def register_instance(port: int, url: str | None = None) -> str:
    """Register a new Ghidra instance by validating its HATEOAS API."""
    if url is None:
        url = f"http://{GHIDRA_HOST}:{port}"

    try:
        test_url = f"{url}/plugin-version"
        response = requests.get(test_url, timeout=10)

        if not response.ok:
            return f"Error: Instance at {url} is not responding properly to HATEOAS API"

        project_info: dict[str, Any] = {"url": url}

        try:
            try:
                version_data = response.json()
                if "result" in version_data:
                    result = version_data["result"]
                    if isinstance(result, dict):
                        plugin_version = result.get("plugin_version", "")
                        api_version = result.get("api_version", 0)

                        project_info["plugin_version"] = plugin_version
                        project_info["api_version"] = api_version

                        if api_version != REQUIRED_API_VERSION:
                            error_msg = (
                                f"API version mismatch: Plugin reports version {api_version}, "
                                f"but bridge requires version {REQUIRED_API_VERSION}"
                            )
                            print(error_msg, file=sys.stderr)
                            return error_msg

                        print(
                            f"Connected to Ghidra plugin version {plugin_version} "
                            f"with API version {api_version}"
                        )
            except Exception as e:
                print(f"Error parsing plugin version: {e}", file=sys.stderr)

            try:
                info_url = f"{url}/program"
                info_response = requests.get(info_url, timeout=10)
                if info_response.ok:
                    try:
                        info_data = info_response.json()
                        if "result" in info_data:
                            result = info_data["result"]
                            if isinstance(result, dict):
                                program_id = result.get("programId", "")
                                if ":" in program_id:
                                    project_name, file_path = program_id.split(":", 1)
                                    project_info["project"] = project_name
                                    if file_path.startswith("/"):
                                        file_path = file_path[1:]
                                    project_info["path"] = file_path

                                project_info["file"] = result.get("name", "")
                                project_info["language_id"] = result.get("languageId", "")
                                project_info["compiler_spec_id"] = result.get("compilerSpecId", "")
                                project_info["image_base"] = result.get("image_base", "")

                                if "_links" in result:
                                    project_info["_links"] = result.get("_links", {})
                    except Exception as e:
                        print(f"Error parsing info endpoint: {e}", file=sys.stderr)
            except Exception as e:
                print(f"Error connecting to info endpoint: {e}", file=sys.stderr)
        except Exception:
            pass

        with instances_lock:
            active_instances[port] = project_info

        return f"Registered instance on port {port} at {url}"
    except Exception as e:
        return f"Error: Could not connect to instance at {url}: {str(e)}"


def _discover_instances(port_range: range, host: str | None = None, timeout: int = 5) -> dict:
    """Discover NEW Ghidra instances by scanning ports."""
    found_instances: list[dict] = []
    scan_host = host if host is not None else GHIDRA_HOST

    for port in port_range:
        if port in active_instances:
            continue

        url = f"http://{scan_host}:{port}"
        try:
            test_url = f"{url}/plugin-version"
            response = requests.get(
                test_url,
                headers={
                    "Accept": "application/json",
                    "X-Request-ID": f"discovery-{int(time.time() * 1000)}",
                },
                timeout=timeout,
            )

            if response.ok:
                try:
                    json_data = response.json()
                    if "success" in json_data and json_data["success"] and "result" in json_data:
                        result = register_instance(port, url)
                        instance_info: dict[str, Any] = {"port": port, "url": url}

                        if isinstance(json_data["result"], dict):
                            instance_info["plugin_version"] = json_data["result"].get(
                                "plugin_version", "unknown"
                            )
                            instance_info["api_version"] = json_data["result"].get(
                                "api_version", "unknown"
                            )
                        else:
                            instance_info["plugin_version"] = "unknown"
                            instance_info["api_version"] = "unknown"

                        if port in active_instances:
                            instance_info["project"] = active_instances[port].get("project", "")
                            instance_info["file"] = active_instances[port].get("file", "")

                        instance_info["result"] = result
                        found_instances.append(instance_info)
                except (ValueError, KeyError):
                    print(f"Port {port} returned non-HATEOAS response", file=sys.stderr)
                    continue
        except requests.exceptions.RequestException:
            continue

    return {"found": len(found_instances), "instances": found_instances}


def periodic_discovery() -> None:
    """Background thread: discover new instances and prune dead ones every 30s."""
    while True:
        try:
            _discover_instances(FULL_DISCOVERY_RANGE, timeout=5)

            with instances_lock:
                ports_to_remove: list[int] = []
                for port, info in active_instances.items():
                    url = info["url"]
                    try:
                        response = requests.get(f"{url}/plugin-version", timeout=5)
                        if not response.ok:
                            ports_to_remove.append(port)
                            continue

                        try:
                            info_url = f"{url}/program"
                            info_response = requests.get(info_url, timeout=5)
                            if info_response.ok:
                                try:
                                    info_data = info_response.json()
                                    if "result" in info_data:
                                        result = info_data["result"]
                                        if isinstance(result, dict):
                                            program_id = result.get("programId", "")
                                            if ":" in program_id:
                                                project_name, file_path = program_id.split(":", 1)
                                                info["project"] = project_name
                                                if file_path.startswith("/"):
                                                    file_path = file_path[1:]
                                                info["path"] = file_path
                                            info["file"] = result.get("name", "")
                                            info["language_id"] = result.get("languageId", "")
                                            info["compiler_spec_id"] = result.get(
                                                "compilerSpecId", ""
                                            )
                                            info["image_base"] = result.get("image_base", "")
                                except Exception as e:
                                    print(
                                        f"Error parsing info endpoint during discovery: {e}",
                                        file=sys.stderr,
                                    )
                        except Exception:
                            pass
                    except requests.exceptions.RequestException:
                        ports_to_remove.append(port)

                for port in ports_to_remove:
                    del active_instances[port]
                    print(f"Removed unreachable instance on port {port}")
        except Exception as e:
            print(f"Error in periodic discovery: {e}")

        time.sleep(30)


def bootstrap_instances() -> None:
    """Initial registration and discovery at startup."""
    register_instance(DEFAULT_GHIDRA_PORT, f"http://{GHIDRA_HOST}:{DEFAULT_GHIDRA_PORT}")
    _discover_instances(QUICK_DISCOVERY_RANGE)


def get_instance_info(port: int | None = None) -> dict:
    """Get detailed info about an instance (used by tools and resources)."""
    from http_client import safe_get

    port = get_instance_port(port)
    response = safe_get(port, "program")

    if not isinstance(response, dict) or not response.get("success", False):
        return {"error": f"Unable to access Ghidra instance on port {port}"}

    result = response.get("result", {})
    if not isinstance(result, dict):
        return error_response("INVALID_RESPONSE", "Invalid response format from Ghidra instance")

    instance_info = {
        "port": port,
        "url": get_instance_url(port),
        "program_name": result.get("name", "unknown"),
        "program_id": result.get("programId", "unknown"),
        "language": result.get("languageId", "unknown"),
        "compiler": result.get("compilerSpecId", "unknown"),
        "base_address": result.get("imageBase", "0x0"),
        "memory_size": result.get("memorySize", 0),
        "analysis_complete": result.get("analysisComplete", False),
    }

    with instances_lock:
        if port in active_instances and "project" in active_instances[port]:
            instance_info["project"] = active_instances[port]["project"]

    return instance_info


def error_response(code: str, message: str) -> dict:
    """Build a standard error dict (convenience, also importable from http_client)."""
    return {
        "success": False,
        "error": {"code": code, "message": message},
        "timestamp": int(time.time() * 1000),
    }
