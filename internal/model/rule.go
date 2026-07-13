package model

// RuleSet represents the loaded T/TAF 352 checks
type RuleSet struct {
	Standard    string       `json:"standard"`
	Title       string       `json:"title"`
	Version     string       `json:"version"`
	TotalChecks int          `json:"total_checks"`
	Dimensions  []Dimension  `json:"dimensions"`
}

// Dimension is a security dimension (e.g., 5.1 身份鉴别与访问控制)
type Dimension struct {
	ID     string         `json:"id"`
	Name   string         `json:"name"`
	Checks []CheckRule    `json:"checks"`
}

// CheckRule is a single check item from the standard
type CheckRule struct {
	ID           string          `json:"id"`
	Title        string          `json:"title"`
	Description  string          `json:"description"`
	Levels       LevelRequirement `json:"levels"`
	MinLevel     string          `json:"min_level"`
	CheckType    string          `json:"check_type"`
	CheckPoints  []string        `json:"check_points"`
	Remediation  string          `json:"remediation"`
	Note         string          `json:"note,omitempty"`
}

// CheckRuleWithDimension pairs a check with its dimension info
type CheckRuleWithDimension struct {
	Check   CheckRule
	DimID   string
	DimName string
}

// LevelRequirement indicates which levels require this check
type LevelRequirement struct {
	L1 bool `json:"L1"`
	L2 bool `json:"L2"`
	L3 bool `json:"L3"`
}
