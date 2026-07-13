package cmd

import (
	"encoding/json"
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

var ciCmd = &cobra.Command{
	Use:   "ci",
	Short: "CI Gate 模式（Pro）",
	Long:  "以 CI 友好的方式运行扫描，通过 exit code 返回结果。适用于 GitHub Actions / Gitee Go 等 CI 流水线。",
	RunE:  runCI,
}

var (
	ciLevel  string
	ciFormat string
	ciOutput string
)

func init() {
	ciCmd.Flags().StringVarP(&ciLevel, "level", "l", "L1", "扫描级别")
	ciCmd.Flags().StringVarP(&ciFormat, "format", "f", "sarif", "输出格式: sarif, json")
	ciCmd.Flags().StringVarP(&ciOutput, "output", "o", "", "输出文件路径（默认 stdout）")
	rootCmd.AddCommand(ciCmd)
}

func runCI(cmd *cobra.Command, args []string) error {
	if err := license.RequirePro(); err != nil {
		return err
	}

	ruleSet, err := rules.Load()
	if err != nil {
		return fmt.Errorf("加载规则失败: %w", err)
	}

	configs, err := finder.FindAll()
	if err != nil {
		return err
	}

	checks := rules.GetChecksByLevel(ruleSet, ciLevel)

	var allFindings []model.Finding
	serverCount := 0

	for _, cfg := range configs {
		parsed, err := parser.Parse(cfg.Path, cfg.Source)
		if err != nil {
			continue
		}
		for _, server := range parsed.Servers {
			serverCount++
			findings := scanner.ScanConfig(server, cfg.Path, checks)
			allFindings = append(allFindings, findings...)
		}
	}

	// Count real failures (exclude INFO/manual_review)
	failCount := 0
	for _, f := range allFindings {
		if f.Severity > model.INFO {
			failCount++
		}
	}

	// Write output
	var w *os.File
	if ciOutput != "" {
		w, err = os.Create(ciOutput)
		if err != nil {
			return err
		}
		defer w.Close()
	} else {
		w = os.Stdout
	}

	switch ciFormat {
	case "sarif":
		err = output.GenerateSARIF(w, versionStr, allFindings, serverCount)
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		err = enc.Encode(map[string]interface{}{
			"level":      ciLevel,
			"servers":    serverCount,
			"findings":   len(allFindings),
			"failures":   failCount,
			"pass":       failCount == 0,
			"details":    allFindings,
		})
	default:
		return fmt.Errorf("不支持的格式: %s (可选: sarif, json)", ciFormat)
	}

	if err != nil {
		return err
	}

	// Exit code: 0 = pass, 1 = fail
	if failCount > 0 {
		fmt.Fprintf(os.Stderr, "❌ CI Gate: %d 项检查未通过 (%s)\n", failCount, ciLevel)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "✅ CI Gate: %s 全部通过\n", ciLevel)
	return nil
}
