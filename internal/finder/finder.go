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
	Source string // claude, cursor, vscode, windsurf, generic, etc.
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

	// Also scan current directory for project-level configs
	cwd, err := os.Getwd()
	if err == nil {
		localPaths := []string{
			filepath.Join(cwd, ".mcp.json"),
			filepath.Join(cwd, ".mcp", "config.json"),
			filepath.Join(cwd, ".cursor", "mcp.json"),
			filepath.Join(cwd, ".vscode", "mcp.json"),
			filepath.Join(cwd, ".roo", "mcp.json"),
			filepath.Join(cwd, ".trae", "mcp.json"),
			filepath.Join(cwd, ".tongyi", "mcp.json"),
			filepath.Join(cwd, ".augment", "mcp.json"),
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
			// ── Original 5 ──────────────────────────────────────────
			// Claude Desktop
			{filepath.Join(appData, "Claude", "claude_desktop_config.json"), "claude"},
			// Cursor
			{filepath.Join(home, ".cursor", "mcp.json"), "cursor"},
			// VS Code
			{filepath.Join(appData, "Code", "User", "settings.json"), "vscode"},
			{filepath.Join(appData, "Code - Insiders", "User", "settings.json"), "vscode-insiders"},
			// Windsurf
			{filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"), "windsurf"},

			// ── New agents ──────────────────────────────────────────
			// Cline (VS Code extension)
			{filepath.Join(appData, "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"), "cline"},
			// Cline (standalone)
			{filepath.Join(home, ".cline", "mcp.json"), "cline"},
			// Roo Code (VS Code extension)
			{filepath.Join(appData, "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings", "mcp_settings.json"), "roo-code"},
			// GitHub Copilot (workspace-level)
			{filepath.Join(appData, "Code", "User", "globalStorage", "github.copilot", "mcp.json"), "copilot"},
			// Amazon Q Developer
			{filepath.Join(home, ".aws", "amazonq", "mcp.json"), "amazon-q"},
			// Trae (ByteDance)
			{filepath.Join(appData, "Trae", "User", "globalStorage", "trae-ai.mcp", "settings", "mcp_servers.json"), "trae"},
			{filepath.Join(appData, "Trae CN", "User", "globalStorage", "trae-ai.mcp", "settings", "mcp_servers.json"), "trae"},
			// Cody (Sourcegraph)
			{filepath.Join(appData, "Code", "User", "globalStorage", "sourcegraph.cody-ai", "mcp.json"), "cody"},
			// Tabnine
			{filepath.Join(home, ".tabnine", "mcp", "config.json"), "tabnine"},
			// Augment Code
			{filepath.Join(appData, "augment-code", "config", "mcp.json"), "augment"},
			// 通义灵码 (Tongyi Lingma)
			{filepath.Join(appData, "Code", "User", "globalStorage", "tongyilingma.tongyi-lingma", "mcp.json"), "tongyi"},
			// CodeBuddy (Tencent)
			{filepath.Join(appData, "Code", "User", "globalStorage", "tencent.codebuddy", "mcp.json"), "codebuddy"},
			// WorkBuddy
			{filepath.Join(home, ".workbuddy", "mcp.json"), "workbuddy"},
			// Aider (YAML format)
			{filepath.Join(home, ".aider.conf.yml"), "aider"},
			{filepath.Join(home, ".aider.conf.json"), "aider"},
		}
	case "darwin":
		paths = []pathEntry{
			// ── Original 5 ──────────────────────────────────────────
			{filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"), "claude"},
			{filepath.Join(home, ".cursor", "mcp.json"), "cursor"},
			{filepath.Join(home, "Library", "Application Support", "Code", "User", "settings.json"), "vscode"},
			{filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"), "windsurf"},

			// ── New agents ──────────────────────────────────────────
			{filepath.Join(home, "Library", "Application Support", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"), "cline"},
			{filepath.Join(home, ".cline", "mcp.json"), "cline"},
			{filepath.Join(home, "Library", "Application Support", "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings", "mcp_settings.json"), "roo-code"},
			{filepath.Join(home, "Library", "Application Support", "Code", "User", "globalStorage", "github.copilot", "mcp.json"), "copilot"},
			{filepath.Join(home, ".aws", "amazonq", "mcp.json"), "amazon-q"},
			{filepath.Join(home, "Library", "Application Support", "Trae", "User", "globalStorage", "trae-ai.mcp", "settings", "mcp_servers.json"), "trae"},
			{filepath.Join(home, "Library", "Application Support", "Code", "User", "globalStorage", "sourcegraph.cody-ai", "mcp.json"), "cody"},
			{filepath.Join(home, ".tabnine", "mcp", "config.json"), "tabnine"},
			{filepath.Join(home, "Library", "Application Support", "augment-code", "config", "mcp.json"), "augment"},
			{filepath.Join(home, "Library", "Application Support", "Code", "User", "globalStorage", "tongyilingma.tongyi-lingma", "mcp.json"), "tongyi"},
			{filepath.Join(home, "Library", "Application Support", "Code", "User", "globalStorage", "tencent.codebuddy", "mcp.json"), "codebuddy"},
			{filepath.Join(home, ".workbuddy", "mcp.json"), "workbuddy"},
			{filepath.Join(home, ".aider.conf.yml"), "aider"},
			{filepath.Join(home, ".aider.conf.json"), "aider"},
		}
	default: // linux
		paths = []pathEntry{
			// ── Original 5 ──────────────────────────────────────────
			{filepath.Join(home, ".config", "claude", "claude_desktop_config.json"), "claude"},
			{filepath.Join(home, ".cursor", "mcp.json"), "cursor"},
			{filepath.Join(home, ".config", "Code", "User", "settings.json"), "vscode"},
			{filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"), "windsurf"},

			// ── New agents ──────────────────────────────────────────
			{filepath.Join(home, ".config", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"), "cline"},
			{filepath.Join(home, ".cline", "mcp.json"), "cline"},
			{filepath.Join(home, ".config", "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings", "mcp_settings.json"), "roo-code"},
			{filepath.Join(home, ".config", "Code", "User", "globalStorage", "github.copilot", "mcp.json"), "copilot"},
			{filepath.Join(home, ".aws", "amazonq", "mcp.json"), "amazon-q"},
			{filepath.Join(home, ".config", "Trae", "User", "globalStorage", "trae-ai.mcp", "settings", "mcp_servers.json"), "trae"},
			{filepath.Join(home, ".config", "Code", "User", "globalStorage", "sourcegraph.cody-ai", "mcp.json"), "cody"},
			{filepath.Join(home, ".tabnine", "mcp", "config.json"), "tabnine"},
			{filepath.Join(home, ".config", "augment-code", "config", "mcp.json"), "augment"},
			{filepath.Join(home, ".config", "Code", "User", "globalStorage", "tongyilingma.tongyi-lingma", "mcp.json"), "tongyi"},
			{filepath.Join(home, ".config", "Code", "User", "globalStorage", "tencent.codebuddy", "mcp.json"), "codebuddy"},
			{filepath.Join(home, ".workbuddy", "mcp.json"), "workbuddy"},
			{filepath.Join(home, ".aider.conf.yml"), "aider"},
			{filepath.Join(home, ".aider.conf.json"), "aider"},
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
	case strings.Contains(lower, "cline"):
		return "cline"
	case strings.Contains(lower, "roo"):
		return "roo-code"
	case strings.Contains(lower, "copilot"):
		return "copilot"
	case strings.Contains(lower, "amazonq"):
		return "amazon-q"
	case strings.Contains(lower, "trae"):
		return "trae"
	case strings.Contains(lower, "cody"):
		return "cody"
	case strings.Contains(lower, "tabnine"):
		return "tabnine"
	case strings.Contains(lower, "augment"):
		return "augment"
	case strings.Contains(lower, "tongyi"):
		return "tongyi"
	case strings.Contains(lower, "codebuddy"):
		return "codebuddy"
	case strings.Contains(lower, "workbuddy"):
		return "workbuddy"
	case strings.Contains(lower, "aider"):
		return "aider"
	default:
		return "generic"
	}
}
