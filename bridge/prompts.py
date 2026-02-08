"""MCP prompts -- reusable LLM analysis templates."""

from fastmcp import FastMCP

from http_client import fetch_decompiled, fetch_disassembly, fetch_function_info
from state import get_instance_info, get_instance_port


def register_prompts(server: FastMCP) -> None:

    @server.prompt("analyze_function")
    def analyze_function_prompt(
        name: str = None, address: str = None, port: int = None
    ) -> dict:
        """Guide the LLM through analyzing a function."""
        port = get_instance_port(port)

        if address and not name:
            fn_info = fetch_function_info(port, address=address)
            if isinstance(fn_info, dict) and "name" in fn_info:
                name = fn_info["name"]

        decompiled = ""
        disasm = ""
        fn_info = None

        if address:
            decompiled = fetch_decompiled(port, address=address)
            disasm = fetch_disassembly(port, address=address)
            fn_info = fetch_function_info(port, address=address)
        elif name:
            decompiled = fetch_decompiled(port, name=name)
            disasm = fetch_disassembly(port, name=name)
            fn_info = fetch_function_info(port, name=name)

        return {
            "prompt": f"""
        Analyze the following function: {name or address}

        Decompiled code:
        ```c
        {decompiled}
        ```

        Disassembly:
        ```
        {disasm}
        ```

        1. What is the purpose of this function?
        2. What are the key parameters and their uses?
        3. What are the return values and their meanings?
        4. Are there any security concerns in this implementation?
        5. Describe the algorithm or process being implemented.
        """,
            "context": {"function_info": fn_info},
        }

    @server.prompt("identify_vulnerabilities")
    def identify_vulnerabilities_prompt(
        name: str = None, address: str = None, port: int = None
    ) -> dict:
        """Help identify potential vulnerabilities in a function."""
        port = get_instance_port(port)

        if address and not name:
            fn_info = fetch_function_info(port, address=address)
            if isinstance(fn_info, dict) and "name" in fn_info:
                name = fn_info["name"]

        decompiled = ""
        disasm = ""
        fn_info = None

        if address:
            decompiled = fetch_decompiled(port, address=address)
            disasm = fetch_disassembly(port, address=address)
            fn_info = fetch_function_info(port, address=address)
        elif name:
            decompiled = fetch_decompiled(port, name=name)
            disasm = fetch_disassembly(port, name=name)
            fn_info = fetch_function_info(port, name=name)

        return {
            "prompt": f"""
        Analyze the following function for security vulnerabilities: {name or address}

        Decompiled code:
        ```c
        {decompiled}
        ```

        Look for these vulnerability types:
        1. Buffer overflows or underflows
        2. Integer overflow/underflow
        3. Use-after-free or double-free bugs
        4. Format string vulnerabilities
        5. Missing bounds checks
        6. Insecure memory operations
        7. Race conditions or timing issues
        8. Input validation problems

        For each potential vulnerability:
        - Describe the vulnerability and where it occurs
        - Explain the security impact
        - Suggest how it could be exploited
        - Recommend a fix
        """,
            "context": {"function_info": fn_info, "disassembly": disasm},
        }

    @server.prompt("reverse_engineer_binary")
    def reverse_engineer_binary_prompt(port: int = None) -> dict:
        """Comprehensive guide to reverse engineering an entire binary."""
        port = get_instance_port(port)
        program_info = get_instance_info(port=port)

        return {
            "prompt": f"""
        # Comprehensive Binary Reverse Engineering Plan

        Begin reverse engineering the binary {program_info.get('program_name', 'unknown')} using a methodical approach.

        ## Phase 1: Initial Reconnaissance
        1. Analyze entry points and the main function
        2. Identify and catalog key functions and libraries
        3. Map the overall program structure
        4. Identify important data structures

        ## Phase 2: Functional Analysis
        1. Start with main() or entry point functions and trace the control flow
        2. Find and rename all unnamed functions (FUN_*) called from main
        3. For each function:
           - Decompile and analyze its purpose
           - Rename with descriptive names following consistent patterns
           - Add comments for complex logic
           - Identify parameters and return values
        4. Follow cross-references (xrefs) to understand context of function usage
        5. Pay special attention to:
           - File I/O operations
           - Network communication
           - Memory allocation/deallocation
           - Authentication/encryption routines
           - Data processing algorithms

        ## Phase 3: Data Flow Mapping
        1. Identify key data structures and rename them meaningfully
        2. Track global variables and their usage across functions
        3. Map data transformations through the program
        4. Identify sensitive data handling (keys, credentials, etc.)

        ## Phase 4: Deep Analysis
        1. For complex functions, perform deeper analysis using:
           - Data flow analysis
           - Call graph analysis
           - Security vulnerability scanning
        2. Look for interesting patterns:
           - Command processing routines
           - State machines
           - Protocol implementations
           - Cryptographic operations

        ## Implementation Strategy
        1. Start with functions called from main
        2. Search for unnamed functions with pattern "FUN_*"
        3. Decompile each function and analyze its purpose
        4. Look at its call graph and cross-references to understand context
        5. Rename the function based on its behavior
        6. Document key insights
        7. Continue iteratively until the entire program flow is mapped

        ## Function Prioritization
        1. Start with entry points and initialization functions
        2. Focus on functions with high centrality in the call graph
        3. Pay special attention to functions with:
           - Command processing logic
           - Error handling
           - Security checks
           - Data transformation

        Remember to use the available GhidraMCP tools:
        - Use functions_list to find functions matching patterns
        - Use xrefs_list to find cross-references
        - Use functions_decompile for C-like representations
        - Use functions_disassemble for lower-level analysis
        - Use functions_rename to apply meaningful names
        - Use data_* tools to work with program data
        """,
            "context": {"program_info": program_info},
        }
