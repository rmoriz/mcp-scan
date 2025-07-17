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

## Default Search Queries

The script uses the following default search patterns to find MCP servers:
- `http.title:"MCP Server"`
- `http.html:"Model Context Protocol"`
- `http.html:"mcp-server"`
- `http.html:"@modelcontextprotocol"`
- `port:3000 http.title:"mcp"`
- `port:8080 http.html:"mcp"`
- `http.favicon.hash:-1698079443`
- `http.html:"/mcp"`
- `http.html:"mcp.json"`
- `http.html:"MCP Inspector"`

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