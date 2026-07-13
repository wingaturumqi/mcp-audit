package finder

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// ConfigFile represents a discovered MCP configuration file
type ConfigFile struct {
	Path   string
	Source string // claude, cursor, vscode, windsurf, generic
}

// FindAll scans all known MCP configuration paths and returns those that exist
func FindAll() ([]ConfigFile, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	paths := getKnownPaths(home)

	var found []ConfigFile
	seen := make(map[string]bool)

	for _, cp := range paths {
		// Resolve to absolute path
		abs := cp.Path
		if !filepath.IsAbs(abs) {
			abs = filepath.Join(home, abs)
		}
		abs = filepath.Clean(abs)

		if seen[abs] {
			continue
		}

		if _, err := os.Stat(abs); err == nil {
			seen[abs] = true
			found = append(found, ConfigFile{
				Path:   abs,
				Source: cp.Source,
			})
		}
	}

	// Also scan current directory for .mcp.json
	cwd, err := os.Getwd()
	if err == nil {
		localPaths := []string{
			filepath.Join(cwd, ".mcp.json"),
			filepath.Join(cwd, ".mcp", "config.json"),
			filepath.Join(cwd, ".cursor", "mcp.json"),
		}
		for _, p := range localPaths {
			p = filepath.Clean(p)
			if !seen[p] {
				if _, err := os.Stat(p); err == nil {
					seen[p] = true
					found = append(found, ConfigFile{
						Path:   p,
						Source: guessSource(p),
					})
				}
			}
		}
	}

	return found, nil
}

type pathEntry struct {
	Path   string
	Source string
}

func getKnownPaths(home string) []pathEntry {
	var paths []pathEntry

	switch runtime.GOOS {
	case "windows":
		appData := os.Getenv("APPDATA")
		paths = []pathEntry{
			// Claude Desktop
			{filepath.Join(appData, "Claude", "claude_desktop_config.json"), "claude"},
			// Cursor
			{filepath.Join(home, ".cursor", "mcp.json"), "cursor"},
			// VS Code
			{filepath.Join(appData, "Code", "User", "settings.json"), "vscode"},
			{filepath.Join(appData, "Code - Insiders", "User", "settings.json"), "vscode-insiders"},
			// Windsurf
			{filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"), "windsurf"},
		}
	case "darwin":
		paths = []pathEntry{
			// Claude Desktop
			{filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"), "claude"},
			// Cursor
			{filepath.Join(home, ".cursor", "mcp.json"), "cursor"},
			// VS Code
			{filepath.Join(home, "Library", "Application Support", "Code", "User", "settings.json"), "vscode"},
			// Windsurf
			{filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"), "windsurf"},
		}
	default: // linux
		paths = []pathEntry{
			// Claude Desktop
			{filepath.Join(home, ".config", "claude", "claude_desktop_config.json"), "claude"},
			// Cursor
			{filepath.Join(home, ".cursor", "mcp.json"), "cursor"},
			// VS Code
			{filepath.Join(home, ".config", "Code", "User", "settings.json"), "vscode"},
			// Windsurf
			{filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"), "windsurf"},
		}
	}

	return paths
}

func guessSource(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.Contains(lower, "claude"):
		return "claude"
	case strings.Contains(lower, "cursor"):
		return "cursor"
	case strings.Contains(lower, "vscode") || strings.Contains(lower, "code"):
		return "vscode"
	case strings.Contains(lower, "windsurf"):
		return "windsurf"
	default:
		return "generic"
	}
}
