package license

import "fmt"

// RequirePro checks if a valid Pro license exists, returns error if not
func RequirePro() error {
	if !IsPro() {
		return fmt.Errorf("此功能需要 Pro 许可证\n   运行 'mcp-audit activate <your-email>' 激活\n   购买: https://gitee.com/BuZhiFire/mcp-audit#pro")
	}
	return nil
}

// RequireFeature checks if a valid Pro license with a specific feature exists
func RequireFeature(feature string) error {
	lic, err := Load()
	if err != nil {
		return fmt.Errorf("此功能需要 Pro 许可证\n   运行 'mcp-audit activate <your-email>' 激活")
	}
	if err := Validate(lic); err != nil {
		return fmt.Errorf("license 无效: %w", err)
	}
	if !HasFeature(lic, feature) {
		return fmt.Errorf("当前 license 不包含 %q 功能", feature)
	}
	return nil
}
