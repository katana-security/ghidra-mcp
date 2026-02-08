# ghidra-mcp

MCP (Model Context Protocol) bridge for Ghidra SRE -- interact with Ghidra's reverse engineering capabilities from AI agents.

## Architecture

```
ghidra-mcp/
├── plugin/          # Ghidra Java plugin (HATEOAS HTTP API)
└── bridge/          # Python MCP bridge (connects AI agents to the plugin)
```

**plugin/** is a Ghidra extension that exposes a HATEOAS REST API over HTTP.
**bridge/** is a modular Python MCP server that translates MCP tool/resource/prompt calls into HTTP requests to the plugin.

## Prerequisites

- [Ghidra](https://ghidra-sre.org) (11.x+)
- Java 21+ and Maven (to build the plugin)
- [uv](https://docs.astral.sh/uv/) (to run the bridge)

## Installation

### 1. Build the Ghidra plugin

```bash
cd plugin
mvn package -P plugin-only
```

This produces `target/GhidraMCP-dev.zip`.

### 2. Install the extension in Ghidra

1. Open Ghidra
2. Go to `File` -> `Install Extensions`
3. Click the `+` button
4. Select the `GhidraMCP-dev.zip` file from `plugin/target/`
5. Restart Ghidra
6. Enable the plugin: `File` -> `Configure` -> `Developer` -> check **GhidraMCPPlugin**

Once enabled, opening a CodeBrowser window starts the HTTP server. The first instance gets port 8192, the second 8193, etc. Check the Ghidra Console (computer icon, bottom right of the project window) for:

```
(HydraMCPPlugin) Plugin loaded on port 8192
(HydraMCPPlugin) HydraMCP HTTP server started on port 8192
```

### 3. Run the MCP bridge

```bash
uv run bridge/server.py
```

The bridge auto-discovers running Ghidra instances on ports 8192-8201 at startup and periodically scans for new ones.

## Configuration

### Claude Code

```bash
claude mcp add ghidra -- uv run /path/to/ghidra-mcp/bridge/server.py
```

### Claude Desktop / Cursor

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "uv",
      "args": ["run", "/path/to/ghidra-mcp/bridge/server.py"]
    }
  }
}
```

## Tools

| Namespace | Tools | Description |
|-----------|-------|-------------|
| `instances_*` | list, discover, register, unregister, use, current | Instance management |
| `functions_*` | list, get, decompile, disassemble, create, rename, set_signature, get_variables | Function operations |
| `data_*` | list, list_strings, create, rename, delete, set_type | Data item operations |
| `structs_*` | list, get, create, add_field, update_field, delete | Struct type management |
| `memory_*` | read, write | Memory access |
| `xrefs_*` | list | Cross-reference tracking |
| `analysis_*` | run, get_callgraph, get_dataflow | Binary analysis |
| `ui_*` | get_current_address, get_current_function | Ghidra UI interaction |
| `comments_*` | set, functions_set_comment | Comment management |

## Resources

- `/instance/{port}` -- instance and program info
- `/instance/{port}/function/decompile/address/{address}` -- decompiled C code
- `/instance/{port}/function/decompile/name/{name}` -- decompiled C code by name
- `/instance/{port}/function/info/address/{address}` -- function metadata
- `/instance/{port}/function/info/name/{name}` -- function metadata by name
- `/instance/{port}/function/disassembly/address/{address}` -- assembly listing
- `/instance/{port}/function/disassembly/name/{name}` -- assembly listing by name

## Prompts

- `analyze_function` -- guided function analysis
- `identify_vulnerabilities` -- security vulnerability analysis
- `reverse_engineer_binary` -- comprehensive RE methodology

## License

MIT
