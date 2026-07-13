package model

import "fmt"

// Severity levels for security findings
type Severity int

const (
	INFO Severity = iota
	LOW
	MEDIUM
	HIGH
	CRITICAL
)

func (s Severity) String() string {
	switch s {
	case CRITICAL:
		return "CRITICAL"
	case HIGH:
		return "HIGH"
	case MEDIUM:
		return "MEDIUM"
	case LOW:
		return "LOW"
	case INFO:
		return "INFO"
	default:
		return "UNKNOWN"
	}
}

// Finding represents a single security issue discovered during scanning
type Finding struct {
	// ServerName is the MCP server where the issue was found
	ServerName string
	// Severity is the severity level
	Severity Severity
	// TtafRef is the T/TAF 352 clause reference (e.g., "5.1.a")
	TtafRef string
	// Dimension is the T/TAF dimension name (e.g., "身份鉴别与访问控制")
	Dimension string
	// Title is a short description of the issue
	Title string
	// Detail provides more context about the issue
	Detail string
	// Suggestion is the recommended fix (remediation)
	Suggestion string
	// RequiredLevel is the minimum level that requires this check (L1, L2, L3)
	RequiredLevel string
	// FilePath is the config file where the issue was found
	FilePath string
}

func (f Finding) String() string {
	return fmt.Sprintf("[%s] %s/%s: %s", f.Severity, f.TtafRef, f.Dimension, f.Title)
}
