"""MCP resources -- loadable context data for Ghidra instances and functions."""

from fastmcp import FastMCP

from http_client import fetch_decompiled, fetch_disassembly, fetch_function_info
from state import get_instance_info


def register_resources(server: FastMCP) -> None:

    @server.resource(uri="/instance/{port}")
    def ghidra_instance(port: int = None) -> dict:
        """Get detailed information about a Ghidra instance and the loaded program."""
        return get_instance_info(port)

    @server.resource(uri="/instance/{port}/function/decompile/address/{address}")
    def decompiled_function_by_address(port: int = None, address: str = None) -> str:
        """Get decompiled C code for a function by address."""
        if not address:
            return "Error: Address parameter is required"
        return fetch_decompiled(port, address=address)

    @server.resource(uri="/instance/{port}/function/decompile/name/{name}")
    def decompiled_function_by_name(port: int = None, name: str = None) -> str:
        """Get decompiled C code for a function by name."""
        if not name:
            return "Error: Name parameter is required"
        return fetch_decompiled(port, name=name)

    @server.resource(uri="/instance/{port}/function/info/address/{address}")
    def function_info_by_address(port: int = None, address: str = None) -> dict:
        """Get detailed information about a function by address."""
        if not address:
            return {"success": False, "error": {"code": "MISSING_PARAMETER", "message": "Address parameter is required"}}
        return fetch_function_info(port, address=address)

    @server.resource(uri="/instance/{port}/function/info/name/{name}")
    def function_info_by_name(port: int = None, name: str = None) -> dict:
        """Get detailed information about a function by name."""
        if not name:
            return {"success": False, "error": {"code": "MISSING_PARAMETER", "message": "Name parameter is required"}}
        return fetch_function_info(port, name=name)

    @server.resource(uri="/instance/{port}/function/disassembly/address/{address}")
    def disassembly_by_address(port: int = None, address: str = None) -> str:
        """Get disassembled instructions for a function by address."""
        if not address:
            return "Error: Address parameter is required"
        return fetch_disassembly(port, address=address)

    @server.resource(uri="/instance/{port}/function/disassembly/name/{name}")
    def disassembly_by_name(port: int = None, name: str = None) -> str:
        """Get disassembled instructions for a function by name."""
        if not name:
            return "Error: Name parameter is required"
        return fetch_disassembly(port, name=name)
