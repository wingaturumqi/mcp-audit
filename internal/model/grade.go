package model

// Level represents a T/TAF 352 security level
type Level int

const (
	LevelNone Level = iota
	Level1         // 基础级
	Level2         // 增强级
	Level3         // 高级级
)

func (l Level) String() string {
	switch l {
	case Level1:
		return "L1"
	case Level2:
		return "L2"
	case Level3:
		return "L3"
	default:
		return "未达标"
	}
}

func (l Level) Label() string {
	switch l {
	case Level1:
		return "基础级"
	case Level2:
		return "增强级"
	case Level3:
		return "高级级"
	default:
		return "未达标"
	}
}

// GradeResult is the final assessment result
type GradeResult struct {
	// AchievedLevel is the highest level fully passed
	AchievedLevel Level
	// DimensionResults breaks down pass/fail per dimension
	DimensionResults []DimensionResult
	// Findings is the list of all failed checks
	Findings []Finding
	// TotalChecks is the total number of checks evaluated
	TotalChecks int
	// PassedChecks is the number of checks passed
	PassedChecks int
}

// DimensionResult is the result for one dimension
type DimensionResult struct {
	DimensionID   string
	DimensionName string
	Total         int
	Passed        int
	Failed        int
	Findings      []Finding
}

// GradeFromResults determines the achieved level from dimension results
func GradeFromResults(dims []DimensionResult) Level {
	// A level is achieved only if ALL checks for that level pass across ALL dimensions
	// We check from highest to lowest
	for _, level := range []Level{Level3, Level2, Level1} {
		if allPassedAtLevel(dims, level) {
			return level
		}
	}
	return LevelNone
}

func allPassedAtLevel(dims []DimensionResult, level Level) bool {
	for _, d := range dims {
		// If there are any findings (failures) at this level or below, it fails
		for _, f := range d.Findings {
			if levelRequired(f.RequiredLevel) <= level {
				return false
			}
		}
	}
	return true
}

func levelRequired(s string) Level {
	switch s {
	case "L1":
		return Level1
	case "L2":
		return Level2
	case "L3":
		return Level3
	default:
		return Level1
	}
}
