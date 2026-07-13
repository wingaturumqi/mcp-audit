package rules

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/wingaturumqi/mcp-audit/internal/model"
)

// Load reads and parses the T/TAF 352 checks JSON file
func Load() (*model.RuleSet, error) {
	path := findRulesFile()
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading rules file: %w", err)
	}

	var rules model.RuleSet
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, fmt.Errorf("parsing rules JSON: %w", err)
	}

	return &rules, nil
}

// LoadFromPath reads rules from a specific path
func LoadFromPath(path string) (*model.RuleSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading rules file %s: %w", path, err)
	}

	var rules model.RuleSet
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, fmt.Errorf("parsing rules JSON: %w", err)
	}

	return &rules, nil
}

// findRulesFile locates the ttaf352-checks.json file
// Search order: executable dir, then source dir
func findRulesFile() string {
	candidates := []string{
		"rules/ttaf352-checks.json",
	}

	// Try relative to executable
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		candidates = append(candidates, filepath.Join(dir, "rules", "ttaf352-checks.json"))
	}

	// Try relative to source (for development)
	_, src, _, ok := runtime.Caller(0)
	if ok {
		dir := filepath.Dir(filepath.Dir(src)) // up from rules/ to project root
		candidates = append(candidates, filepath.Join(dir, "rules", "ttaf352-checks.json"))
	}

	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}

	return "rules/ttaf352-checks.json" // fallback
}

// GetChecksByLevel returns checks filtered by minimum level
func GetChecksByLevel(rules *model.RuleSet, level string) []model.CheckRuleWithDimension {
	var result []model.CheckRuleWithDimension
	for _, dim := range rules.Dimensions {
		for _, check := range dim.Checks {
			switch level {
			case "L1":
				if check.Levels.L1 {
					result = append(result, model.CheckRuleWithDimension{
						Check:     check,
						DimID:     dim.ID,
						DimName:   dim.Name,
					})
				}
			case "L2":
				if check.Levels.L2 {
					result = append(result, model.CheckRuleWithDimension{
						Check:     check,
						DimID:     dim.ID,
						DimName:   dim.Name,
					})
				}
			case "L3":
				// L3 includes all checks
				result = append(result, model.CheckRuleWithDimension{
					Check:     check,
					DimID:     dim.ID,
					DimName:   dim.Name,
				})
			}
		}
	}
	return result
}
