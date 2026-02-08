# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "fastmcp",
#     "requests>=2.32",
# ]
# ///
"""GhidraMCP Bridge -- MCP server for Ghidra reverse engineering."""

import os
import signal
import threading

from fastmcp import FastMCP

from state import BRIDGE_VERSION, bootstrap_instances, periodic_discovery
from resources import register_resources
from prompts import register_prompts
from tools import (
    register_instance_tools,
    register_function_tools,
    register_data_tools,
    register_struct_tools,
    register_memory_tools,
    register_xref_tools,
    register_analysis_tools,
    register_ui_tools,
    register_comment_tools,
)

instructions = """
GhidraMCP allows interacting with multiple Ghidra SRE instances. Ghidra SRE is a tool for reverse engineering and analyzing binaries, e.g. malware.

First, run `instances_list()` to see all available Ghidra instances (automatically discovers instances on the default host).
Then use `instances_use(port)` to set your working instance.

Note: Use `instances_discover(host)` only if you need to scan a different host.

The API is organized into namespaces for different types of operations:
- instances_* : For managing Ghidra instances
- functions_* : For working with functions
- data_* : For working with data items
- structs_* : For creating and managing struct data types
- memory_* : For memory access
- xrefs_* : For cross-references
- analysis_* : For program analysis
"""

server = FastMCP("GhidraMCP", version=BRIDGE_VERSION, instructions=instructions)

# Wire tools
register_instance_tools(server)
register_function_tools(server)
register_data_tools(server)
register_struct_tools(server)
register_memory_tools(server)
register_xref_tools(server)
register_analysis_tools(server)
register_ui_tools(server)
register_comment_tools(server)

# Wire resources & prompts
register_resources(server)
register_prompts(server)


def main() -> None:
    """Bootstrap instances, start background discovery, and run the MCP server."""
    bootstrap_instances()

    discovery_thread = threading.Thread(
        target=periodic_discovery, daemon=True, name="GhidraMCP-Discovery"
    )
    discovery_thread.start()

    signal.signal(signal.SIGINT, lambda *_: os._exit(0))

    server.run(transport="stdio")


if __name__ == "__main__":
    main()
