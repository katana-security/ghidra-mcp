"""Instance management tools -- list, discover, register, unregister, use, current."""

from typing import Any

from fastmcp import FastMCP
from pydantic import Field

from state import (
    QUICK_DISCOVERY_RANGE,
    active_instances,
    get_instance_info,
    get_instance_port,
    instances_lock,
    register_instance,
    set_current_port,
    get_current_port,
    _discover_instances,
)


def register_instance_tools(server: FastMCP) -> None:

    @server.tool
    def instances_list() -> dict[str, Any]:
        """List all active Ghidra instances.

        Automatically discovers new instances on the default host before listing.
        Use instances_discover(host) only if you need to scan a different host.
        """
        _discover_instances(QUICK_DISCOVERY_RANGE, host=None, timeout=5)

        with instances_lock:
            return {
                "instances": [
                    {
                        "port": port,
                        "url": info["url"],
                        "project": info.get("project", ""),
                        "file": info.get("file", ""),
                    }
                    for port, info in active_instances.items()
                ]
            }

    @server.tool
    def instances_discover(
        host: str | None = Field(
            default=None,
            description="Host to scan for Ghidra instances (default: configured ghidra_host)",
        ),
    ) -> dict[str, Any]:
        """Discover Ghidra instances on a specific host.

        Use this ONLY when you need to discover instances on a different host.
        For normal usage, just use instances_list() which auto-discovers on the default host.
        """
        _discover_instances(QUICK_DISCOVERY_RANGE, host=host, timeout=5)

        with instances_lock:
            return {
                "instances": [
                    {
                        "port": port,
                        "url": info["url"],
                        "project": info.get("project", ""),
                        "file": info.get("file", ""),
                    }
                    for port, info in active_instances.items()
                ]
            }

    @server.tool
    def instances_register(
        port: int = Field(description="Port number of the Ghidra instance"),
        url: str | None = Field(default=None, description="Optional URL if different from default http://host:port"),
    ) -> str:
        """Register a new Ghidra instance."""
        return register_instance(port, url)

    @server.tool
    def instances_unregister(
        port: int = Field(description="Port number of the instance to unregister"),
    ) -> str:
        """Unregister a Ghidra instance."""
        with instances_lock:
            if port in active_instances:
                del active_instances[port]
                return f"Unregistered instance on port {port}"
            return f"No instance found on port {port}"

    @server.tool
    def instances_use(
        port: int = Field(description="Port number of the instance to use"),
    ) -> str:
        """Set the current working Ghidra instance."""
        if port not in active_instances:
            register_instance(port)
            if port not in active_instances:
                return f"Error: No active Ghidra instance found on port {port}"

        set_current_port(port)

        with instances_lock:
            info = active_instances[port]
            program = info.get("file", "unknown program")
            project = info.get("project", "unknown project")
            return f"Now using Ghidra instance on port {port} with {program} in project {project}"

    @server.tool
    def instances_current() -> dict[str, Any]:
        """Get information about the current working Ghidra instance."""
        return get_instance_info(port=get_current_port())
