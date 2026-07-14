package parser

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/wingaturumqi/mcp-audit/internal/model"
	"gopkg.in/yaml.v3"
)

// Parse reads an MCP configuration file and returns the parsed config
func Parse(path string, source string) (*model.MCPConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}

	ext := strings.ToLower(filepath.Ext(path))

	switch {
	case source == "vscode" || source == "vscode-insiders":
		return parseVSCode(data, path, source)
	case source == "aider" || ext == ".yml" || ext == ".yaml":
		return parseAiderYAML(data, path, source)
	default:
		return parseStandard(data, path, source)
	}
}

// parseStandard handles Claude Desktop, Cursor, Windsurf, Cline, Roo Code,
// Amazon Q, Trae, Cody, Tabnine, Augment, 通义灵码, CodeBuddy, etc.
// These all use the standard MCP config format:
//
//	{ "mcpServers": { "server-name": { "command": "...", "args": [...], "env": {...} } } }
func parseStandard(data []byte, path string, source string) (*model.MCPConfig, error) {
	var raw struct {
		MCPServers map[string]json.RawMessage `json:"mcpServers"`
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		// Try .vscode/mcp.json format: { "servers": { ... } }
		var vscodeRaw struct {
			Servers map[string]json.RawMessage `json:"servers"`
		}
		if err2 := json.Unmarshal(data, &vscodeRaw); err2 == nil && vscodeRaw.Servers != nil {
			return buildConfig(vscodeRaw.Servers, path, source), nil
		}
		return nil, fmt.Errorf("parsing JSON in %s: %w", path, err)
	}

	if raw.MCPServers == nil {
		// Try .vscode/mcp.json format as fallback
		var vscodeRaw struct {
			Servers map[string]json.RawMessage `json:"servers"`
		}
		if err2 := json.Unmarshal(data, &vscodeRaw); err2 == nil && vscodeRaw.Servers != nil {
			return buildConfig(vscodeRaw.Servers, path, source), nil
		}
		return &model.MCPConfig{Path: path, Source: source, Servers: []model.MCPServer{}}, nil
	}

	return buildConfig(raw.MCPServers, path, source), nil
}

func buildConfig(servers map[string]json.RawMessage, path string, source string) *model.MCPConfig {
	cfg := &model.MCPConfig{
		Path:    path,
		Source:  source,
		Servers: make([]model.MCPServer, 0, len(servers)),
	}

	for name, serverData := range servers {
		server, err := parseServer(name, serverData)
		if err != nil {
			continue // skip unparseable servers
		}
		cfg.Servers = append(cfg.Servers, server)
	}

	return cfg
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

	return buildConfig(raw.MCP.Servers, path, source), nil
}

// parseAiderYAML handles Aider's .aider.conf.yml format:
//
//	mcp-servers:
//	  server-name:
//	    command: "..."
//	    args: [...]
//	    env: {...}
func parseAiderYAML(data []byte, path string, source string) (*model.MCPConfig, error) {
	var raw struct {
		MCPServers map[string]struct {
			Command string            `yaml:"command"`
			Args    []string          `yaml:"args"`
			Env     map[string]string `yaml:"env"`
			URL     string            `yaml:"url"`
			Type    string            `yaml:"type"`
		} `yaml:"mcp-servers"`
	}

	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing YAML in %s: %w", path, err)
	}

	cfg := &model.MCPConfig{
		Path:    path,
		Source:  source,
		Servers: make([]model.MCPServer, 0, len(raw.MCPServers)),
	}

	for name, srv := range raw.MCPServers {
		server := model.MCPServer{
			Name:  name,
			Env:   srv.Env,
			URL:   srv.URL,
			Type:  srv.Type,
			Args:  srv.Args,
		}

		if srv.URL != "" {
			server.Transport = "sse"
			if srv.Type != "" {
				server.Transport = srv.Type
			}
		} else if srv.Command != "" {
			server.Transport = "stdio"
			server.Command = srv.Command
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
