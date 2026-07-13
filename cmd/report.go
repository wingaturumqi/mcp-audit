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

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "生成 HTML 合规报告（Pro）",
	Long:  "生成详细的 HTML 格式 T/TAF 352 合规报告，包含分级结果、问题详情和整改建议。",
	RunE:  runReport,
}

var reportOutput string
var reportLevel string

func init() {
	reportCmd.Flags().StringVarP(&reportOutput, "output", "o", "mcp-audit-report.html", "输出文件路径")
	reportCmd.Flags().StringVarP(&reportLevel, "level", "l", "L1", "扫描级别")
	rootCmd.AddCommand(reportCmd)
}

func runReport(cmd *cobra.Command, args []string) error {
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

	checks := rules.GetChecksByLevel(ruleSet, reportLevel)

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

	f, err := os.Create(reportOutput)
	if err != nil {
		return err
	}
	defer f.Close()

	if err := output.GenerateHTML(f, versionStr, reportLevel, allFindings, serverCount); err != nil {
		return err
	}

	failCount := 0
	for _, ff := range allFindings {
		if ff.Severity > model.INFO {
			failCount++
		}
	}

	fmt.Printf("📋 报告已生成: %s\n", reportOutput)
	fmt.Printf("   级别: %s  服务器: %d  问题: %d\n", reportLevel, serverCount, failCount)
	return nil
}
