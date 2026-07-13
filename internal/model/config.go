package model

// MCPConfig represents a parsed MCP configuration file
type MCPConfig struct {
	// Path is the file path of the configuration
	Path string
	// Source indicates which tool owns this config (claude, cursor, vscode, etc.)
	Source string
	// Servers is the list of MCP servers defined in this config
	Servers []MCPServer
}

// MCPServer represents a single MCP server configuration
type MCPServer struct {
	// Name is the user-defined name for this server
	Name string
	// Command is the executable command (for stdio transport)
	Command string
	// Args are the command arguments
	Args []string
	// Env is the environment variables (key-value pairs)
	Env map[string]string
	// URL is for HTTP/SSE-based MCP servers
	URL string
	// Type is the raw transport type from config (sse, streamable-http, etc.)
	Type string
	// Transport is the normalized transport type (stdio, sse, streamable-http)
	Transport string
}
