# Shodan MCP Server Search Tool

A Python script for discovering MCP (Model Context Protocol) servers using the Shodan search engine.

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage
```bash
# Set your Shodan API key
export SHODAN_API_KEY="your_api_key_here"

# Run the search
python shodan_mcp_search.py
```

### Advanced Usage
```bash
# Use custom API key
python shodan_mcp_search.py --api-key YOUR_API_KEY

# Custom search query
python shodan_mcp_search.py --query "http.title:MCP"

# Limit results
python shodan_mcp_search.py --limit 100

# Different output formats
python shodan_mcp_search.py --format json
python shodan_mcp_search.py --format csv --output results.csv

# Save to file
python shodan_mcp_search.py --output results.json --format json
```

## Features

- **Fresh Results**: Automatically filters out results older than 10 days
- **JSON-RPC Error Detection**: Searches for servers returning specific JSON-RPC error responses
- **mcp.json Discovery**: Specifically looks for MCP service description endpoints
- **Multiple Search Patterns**: Comprehensive queries to find MCP servers

## Default Search Queries

The script uses the following default search patterns to find MCP servers:
- `http.title:"MCP Server"`
- `http.html:"Model Context Protocol"`
- `http.html:"mcp-server"`
- `http.html:"jsonrpc"`
- `http.html:"json-rpc"`
- `http.html:"/mcp"`
- `http.html:"mcp.json"`
- `http.component:"mcp.json"`
- `http.status:200 http.title:"mcp"`
- `http.body:"mcp.json"`
- `http.html:"Not Acceptable: Client must accept text/event-stream"`
- `http.html:"jsonrpc.*2.0.*server-error.*-32600"`
- `port:3000,8080,8000,9000,8888`

## Output Format

Results include:
- IP address
- Port number
- Hostnames
- Organization
- Country and city
- Last update timestamp
- HTTP title
- Detected MCP endpoint
- Search query used

## Requirements

- Python 3.6+
- Shodan API key (get one at https://shodan.io)
- Required packages: `shodan`, `tabulate`