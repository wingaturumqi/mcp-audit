package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/wingaturumqi/mcp-audit/internal/finder"
	"github.com/wingaturumqi/mcp-audit/internal/license"
	"github.com/wingaturumqi/mcp-audit/internal/model"
	"github.com/wingaturumqi/mcp-audit/internal/output"
	"github.com/wingaturumqi/mcp-audit/internal/parser"
	"github.com/wingaturumqi/mcp-audit/internal/rules"
	"github.com/wingaturumqi/mcp-audit/internal/scanner"
)

var badgeCmd = &cobra.Command{
	Use:   "badge",
	Short: "生成合规徽章 SVG（Pro）",
	Long:  "根据扫描结果生成 T/TAF 352 合规徽章（SVG 格式），可嵌入 README 或网站。",
	RunE:  runBadge,
}

var badgeOutput string
var badgeLevel string

func init() {
	badgeCmd.Flags().StringVarP(&badgeOutput, "output", "o", "badge.svg", "输出 SVG 文件路径")
	badgeCmd.Flags().StringVarP(&badgeLevel, "level", "l", "L1", "扫描级别")
	rootCmd.AddCommand(badgeCmd)
}

func runBadge(cmd *cobra.Command, args []string) error {
	if err := license.RequirePro(); err != nil {
		return err
	}

	ruleSet, err := rules.Load()
	if err != nil {
		return err
	}

	configs, err := finder.FindAll()
	if err != nil {
		return err
	}

	checks := rules.GetChecksByLevel(ruleSet, badgeLevel)

	var allFindings []model.Finding
	for _, cfg := range configs {
		parsed, err := parser.Parse(cfg.Path, cfg.Source)
		if err != nil {
			fmt.Fprintf(os.Stderr, "⚠️  解析失败 %s: %v\n", cfg.Path, err)
			continue
		}
		for _, server := range parsed.Servers {
			findings := scanner.ScanConfig(server, cfg.Path, checks)
			allFindings = append(allFindings, findings...)
		}
	}

	// Count failures
	failCount := 0
	for _, f := range allFindings {
		if f.Severity > model.INFO {
			failCount++
		}
	}

	totalChecks := len(checks)
	passed := totalChecks - failCount

	// Determine achieved level
	achievedLevel := badgeLevel
	if failCount > 0 {
		achievedLevel = "NONE"
	}

	f, err := os.Create(badgeOutput)
	if err != nil {
		return err
	}
	defer f.Close()

	output.GenerateBadgeSVG(f, achievedLevel, passed, totalChecks)

	fmt.Printf("🏷️  徽章已生成: %s\n", badgeOutput)
	fmt.Printf("   级别: %s  通过: %d/%d\n", achievedLevel, passed, totalChecks)
	return nil
}
