package parser

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/wingaturumqi/mcp-audit/internal/model"
)

// Parse reads an MCP configuration file and returns the parsed config
func Parse(path string, source string) (*model.MCPConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}

	switch source {
	case "vscode", "vscode-insiders":
		return parseVSCode(data, path, source)
	default:
		return parseStandard(data, path, source)
	}
}

// parseStandard handles Claude Desktop, Cursor, Windsurf, and .mcp.json formats
// These all use the standard MCP config format:
//
//	{ "mcpServers": { "server-name": { "command": "...", "args": [...], "env": {...} } } }
func parseStandard(data []byte, path string, source string) (*model.MCPConfig, error) {
	var raw struct {
		MCPServers map[string]json.RawMessage `json:"mcpServers"`
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing JSON in %s: %w", path, err)
	}

	cfg := &model.MCPConfig{
		Path:    path,
		Source:  source,
		Servers: make([]model.MCPServer, 0, len(raw.MCPServers)),
	}

	for name, serverData := range raw.MCPServers {
		server, err := parseServer(name, serverData)
		if err != nil {
			return nil, fmt.Errorf("parsing server %q in %s: %w", name, path, err)
		}
		cfg.Servers = append(cfg.Servers, server)
	}

	return cfg, nil
}

// parseVSCode handles VS Code's settings.json format where MCP servers are nested under
// "mcp" -> "servers" key
func parseVSCode(data []byte, path string, source string) (*model.MCPConfig, error) {
	var raw struct {
		MCP struct {
			Servers map[string]json.RawMessage `json:"servers"`
		} `json:"mcp"`
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing VS Code settings in %s: %w", path, err)
	}

	// If no MCP section found, return empty config
	if raw.MCP.Servers == nil {
		return &model.MCPConfig{
			Path:    path,
			Source:  source,
			Servers: []model.MCPServer{},
		}, nil
	}

	cfg := &model.MCPConfig{
		Path:    path,
		Source:  source,
		Servers: make([]model.MCPServer, 0, len(raw.MCP.Servers)),
	}

	for name, serverData := range raw.MCP.Servers {
		server, err := parseServer(name, serverData)
		if err != nil {
			return nil, fmt.Errorf("parsing server %q in %s: %w", name, path, err)
		}
		cfg.Servers = append(cfg.Servers, server)
	}

	return cfg, nil
}

// parseServer parses a single MCP server definition from JSON
func parseServer(name string, data []byte) (model.MCPServer, error) {
	// Try to detect if it's an HTTP/SSE server or stdio
	var probe struct {
		Command string            `json:"command"`
		URL     string            `json:"url"`
		Type    string            `json:"type"`
		Args    json.RawMessage   `json:"args"`
		Env     map[string]string `json:"env"`
	}

	if err := json.Unmarshal(data, &probe); err != nil {
		return model.MCPServer{}, err
	}

	server := model.MCPServer{
		Name:  name,
		Env:   probe.Env,
		URL:   probe.URL,
		Type:  probe.Type,
	}

	// Determine transport type
	if probe.URL != "" {
		server.Transport = "sse"
		if probe.Type != "" {
			server.Transport = probe.Type
		}
	} else if probe.Command != "" {
		server.Transport = "stdio"
		server.Command = probe.Command
	}

	// Parse args - can be string or array
	if len(probe.Args) > 0 {
		var args []string
		if err := json.Unmarshal(probe.Args, &args); err == nil {
			server.Args = args
		} else {
			// Try as a single string
			var singleArg string
			if err := json.Unmarshal(probe.Args, &singleArg); err == nil {
				server.Args = []string{singleArg}
			}
		}
	}

	return server, nil
}
