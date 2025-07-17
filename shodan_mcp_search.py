#!/usr/bin/env python3
"""
Shodan MCP Server Search Tool

This script searches for MCP (Model Context Protocol) servers using the Shodan API.
It looks for services that might be running MCP servers based on common patterns.
"""

import argparse
import json
import csv
import sys
import os
from datetime import datetime, timedelta

try:
    import shodan
    from tabulate import tabulate
except ImportError:
    print("Error: Required packages not found.")
    print("Install with: pip install shodan tabulate")
    sys.exit(1)


class MCPShodanSearch:
    def __init__(self, api_key):
        """Initialize the Shodan API client."""
        if not api_key:
            raise ValueError("Shodan API key is required")
        
        self.api = shodan.Shodan(api_key)
        
    def search_mcp_servers(self, query=None, limit=100):
        """
        Search for MCP servers using various search patterns.
        
        Args:
            query (str): Custom search query (optional)
            limit (int): Maximum number of results to return
            
        Returns:
            list: List of search results
        """
        
        # Default MCP-related search queries including JSON-RPC patterns
        default_queries = [
            'http.title:"MCP Server"',
            'http.html:"Model Context Protocol"',
            'http.html:"mcp-server"',
            'http.html:"jsonrpc"',
            'http.html:"json-rpc"',
            'http.html:"/mcp"',
            'http.html:"mcp.json"',
            'http.html:"MCP Inspector"',
            'http.html:"Not Acceptable: Client must accept text/event-stream"',
            'http.html:"jsonrpc.*2.0.*server-error.*-32600"',
            'http.title:"Not Acceptable"',
            'http.component:"mcp.json"',
            'http.status:200 http.title:"mcp"',
            'http.body:"mcp.json"',
            'port:3000',
            'port:8080',
            'port:8000',
            'port:9000',
            'port:8888',
        ]
        
        results = []
        
        if query:
            # Use custom query
            queries = [query]
        else:
            # Use default MCP queries
            queries = default_queries
        
        for search_query in queries:
            try:
                print(f"Searching: {search_query}")
                
                # Perform the search
                try:
                    search_results = self.api.search(search_query)
                    print(f"Got response type: {type(search_results)}")
                except Exception as e:
                    print(f"Search failed for '{search_query}': {e}")
                    continue
                
                # Handle different response types
                if isinstance(search_results, dict):
                    matches = search_results.get('matches', [])
                elif hasattr(search_results, 'matches'):
                    matches = search_results.matches
                else:
                    matches = []
                
                if matches is None:
                    print(f"Matches is None for '{search_query}'")
                    continue
                    
                if not isinstance(matches, list):
                    print(f"Matches is not a list: {type(matches)}")
                    matches = []
                    
                if len(matches) == 0:
                    continue
                
                try:
                    for result in matches:
                        if not result:
                            continue
                            
                        # Check if result is fresher than 10 days
                        last_update = result.get('timestamp', '')
                        if last_update:
                            try:
                                # Parse Shodan timestamp format
                                update_date = datetime.strptime(last_update, '%Y-%m-%dT%H:%M:%S.%f')
                                cutoff_date = datetime.now() - timedelta(days=10)
                                if update_date < cutoff_date:
                                    continue  # Skip results older than 10 days
                            except ValueError:
                                # If timestamp format is different, include anyway
                                pass
                        
                        # Extract relevant information
                        mcp_info = {
                            'ip': str(result.get('ip_str', 'N/A')),
                            'port': str(result.get('port', 'N/A')),
                            'hostnames': result.get('hostnames', []),
                            'org': str(result.get('org', 'N/A')),
                            'country': str(result.get('location', {}).get('country_name', 'N/A')),
                            'city': str(result.get('location', {}).get('city', 'N/A')),
                            'last_update': str(last_update),
                            'product': str(result.get('product', 'N/A')),
                            'data': str(result.get('data', ''))[:200] + '...' if len(str(result.get('data', ''))) > 200 else str(result.get('data', '')),
                            'http_title': str(self._extract_http_title(result)),
                            'mcp_endpoint': str(self._find_mcp_endpoint(result)),
                            'search_query': str(search_query)
                        }
                        
                        results.append(mcp_info)
                        
                        if len(results) >= limit:
                            return results[:limit]
                except Exception as e:
                    print(f"Error processing matches for '{search_query}': {e}")
                    continue
                        
            except shodan.APIError as e:
                print(f"Error searching '{search_query}': {e}")
                continue
            except Exception as e:
                print(f"Unexpected error searching '{search_query}': {e}")
                import traceback
                traceback.print_exc()
                continue
                
        return results
    
    def _extract_http_title(self, result):
        """Extract HTTP title from Shodan result."""
        try:
            if 'http' in result:
                return result['http'].get('title', 'N/A')
            elif 'data' in result:
                # Simple regex to find title
                import re
                match = re.search(r'<title[^>]*>([^<]+)</title>', result['data'], re.IGNORECASE)
                return match.group(1).strip() if match else 'N/A'
        except:
            return 'N/A'
    
    def _find_mcp_endpoint(self, result):
        """Try to find MCP endpoint URLs and JSON-RPC endpoints in the result."""
        data = str(result.get('data', ''))
        
        # Look for common MCP and JSON-RPC patterns
        patterns = [
            r'https?://[^\s\'"]*mcp[^\s\'"]*',
            r'https?://[^\s\'"]*model[^\s\'"]*context[^\s\'"]*protocol[^\s\'"]*',
            r'"[^"]*mcp[^"]*\.json"',
            r'/mcp[^\s\'"]*',
            r'"[^"]*jsonrpc[^"]*"',
            r'/jsonrpc[^\s\'"]*',
            r'/rpc[^\s\'"]*',
            r'"[^"]*rpc[^"]*\.json"',
            r'https?://[^\s\'"]*rpc[^\s\'"]*',
            r'jsonrpc.*2\.0.*server-error',
            r'-32600.*Not Acceptable',
            r'text/event-stream',
        ]
        
        import re
        for pattern in patterns:
            matches = re.findall(pattern, data, re.IGNORECASE)
            if matches:
                return matches[0]
        
        # Construct potential endpoints
        ip = result.get('ip_str', '')
        port = result.get('port', '')
        if ip and port:
            # Try common MCP/JSON-RPC endpoints
            endpoints = [f"http://{ip}:{port}/mcp", f"http://{ip}:{port}/jsonrpc", f"http://{ip}:{port}/rpc"]
            return endpoints[0]
        
        return 'N/A'
    
    def format_results(self, results, format_type='table'):
        """Format results in specified format."""
        if not results:
            return "No results found."
        
        if format_type == 'json':
            return json.dumps(results, indent=2, default=str)
        
        elif format_type == 'csv':
            if not results:
                return ""
            
            output = []
            writer = csv.DictWriter(output, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)
            return '\n'.join(output)
        
        else:  # table format
            if not results:
                return "No results found."
            
            headers = ['IP', 'Port', 'Country', 'City', 'Organization', 'HTTP Title', 'MCP Endpoint']
            rows = []
            
            for result in results:
                rows.append([
                    result['ip'],
                    result['port'],
                    result['country'],
                    result['city'],
                    result['org'][:30] + '...' if len(result['org']) > 30 else result['org'],
                    result['http_title'][:30] + '...' if len(result['http_title']) > 30 else result['http_title'],
                    result['mcp_endpoint'][:40] + '...' if len(result['mcp_endpoint']) > 40 else result['mcp_endpoint']
                ])
            
            return tabulate(rows, headers=headers, tablefmt='grid')


def main():
    parser = argparse.ArgumentParser(description='Search for MCP servers using Shodan')
    parser.add_argument('--api-key', help='Shodan API key (can also use SHODAN_API_KEY env var)')
    parser.add_argument('--query', help='Custom search query (overrides default MCP queries)')
    parser.add_argument('--limit', type=int, default=50, help='Maximum number of results (default: 50)')
    parser.add_argument('--format', choices=['json', 'csv', 'table'], default='table', help='Output format (default: table)')
    parser.add_argument('--output', help='Output file (default: stdout)')
    
    args = parser.parse_args()
    
    # Get API key from args or environment
    api_key = args.api_key or os.getenv('SHODAN_API_KEY')
    if not api_key:
        print("Error: Shodan API key is required. Set SHODAN_API_KEY environment variable or use --api-key")
        sys.exit(1)
    
    try:
        # Initialize search
        searcher = MCPShodanSearch(api_key)
        
        # Perform search
        results = searcher.search_mcp_servers(query=args.query, limit=args.limit)
        
        # Format and output results
        formatted = searcher.format_results(results, format_type=args.format)
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write(formatted)
            print(f"Results saved to {args.output}")
        else:
            print(formatted)
            
        print(f"\nTotal results: {len(results)}")
        
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except shodan.APIError as e:
        print(f"Shodan API Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()