package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/wingaturumqi/mcp-audit/internal/finder"
	"github.com/wingaturumqi/mcp-audit/internal/model"
	"github.com/wingaturumqi/mcp-audit/internal/parser"
	"github.com/wingaturumqi/mcp-audit/internal/rules"
	"github.com/wingaturumqi/mcp-audit/internal/scanner"
)

var scanLevel string
var scanPro bool

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "扫描 MCP 配置，输出 T/TAF 352 合规分级报告",
	Long:  "自动发现并扫描所有 MCP Server 配置，基于 T/TAF 352—2026 标准进行 L1/L2/L3 分级评估。",
	RunE:  runScan,
}

func init() {
	scanCmd.Flags().StringVarP(&scanLevel, "level", "l", "L1", "扫描级别: L1 (基础级), L2 (增强级), L3 (高级级)")
	scanCmd.Flags().BoolVar(&scanPro, "pro", false, "加载 Pro 扩展规则（等保/国密/数据出境）")
	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	scanLevel = strings.ToUpper(scanLevel)
	if scanLevel != "L1" && scanLevel != "L2" && scanLevel != "L3" {
		return fmt.Errorf("无效级别 %q，可选: L1, L2, L3", scanLevel)
	}

	var ruleSet *model.RuleSet
	var err error
	if scanPro {
		ruleSet, err = rules.LoadPro()
	} else {
		ruleSet, err = rules.Load()
	}
	if err != nil {
		return fmt.Errorf("加载规则失败: %w", err)
	}

	levelLabel := levelName(scanLevel)
	fmt.Println("🔍 mcp-audit — T/TAF 352—2026 MCP Server 安全合规自查")
	fmt.Printf("   标准: %s (%s)  级别: %s %s\n", ruleSet.Standard, ruleSet.Version, scanLevel, levelLabel)
	fmt.Println()

	configs, err := finder.FindAll()
	if err != nil {
		return fmt.Errorf("查找配置失败: %w", err)
	}

	if len(configs) == 0 {
		fmt.Println("  未找到 MCP 配置文件。")
		fmt.Println("  已搜索: Claude Desktop, Cursor, VS Code, Windsurf, .mcp.json")
		return nil
	}

	fmt.Printf("  找到 %d 个配置文件\n\n", len(configs))

	checks := rules.GetChecksByLevel(ruleSet, scanLevel)

	var allFindings []model.Finding
	serverCount := 0

	for _, cfg := range configs {
		parsed, err := parser.Parse(cfg.Path, cfg.Source)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ⚠️  解析失败 %s: %v\n", cfg.Path, err)
			continue
		}

		fmt.Printf("📁 %s (%s)\n", cfg.Path, cfg.Source)

		if len(parsed.Servers) == 0 {
			fmt.Println("  未配置 MCP 服务器。")
			fmt.Println()
			continue
		}

		for _, server := range parsed.Servers {
			serverCount++
			findings := scanner.ScanConfig(server, cfg.Path, checks)
			printServerResult(server.Name, findings)
			allFindings = append(allFindings, findings...)
		}
		fmt.Println()
	}

	printGradeSummary(ruleSet, serverCount, allFindings, scanLevel)

	return nil
}

func printServerResult(name string, findings []model.Finding) {
	if len(findings) == 0 {
		fmt.Printf("  ✅ %s — 检查全部通过\n", name)
		return
	}

	failCount := 0
	reviewCount := 0

	for _, f := range findings {
		if f.Severity == model.INFO {
			reviewCount++
			fmt.Printf("  🔍 [%s] %s %s\n", f.RequiredLevel, f.TtafRef, f.Title)
			fmt.Printf("     %s\n", f.Detail)
		} else {
			failCount++
			icon := severityIcon(f.Severity)
			fmt.Printf("  %s [%s] %s %s\n", icon, f.RequiredLevel, f.TtafRef, f.Title)
			fmt.Printf("     %s\n", f.Detail)
			fmt.Printf("     💡 %s\n", f.Suggestion)
		}
	}

	fmt.Printf("  ⚡ %s: %d 项不通过, %d 项需人工审查\n", name, failCount, reviewCount)
}

func severityIcon(s model.Severity) string {
	switch s {
	case model.CRITICAL:
		return "🔴"
	case model.HIGH:
		return "🟠"
	case model.MEDIUM:
		return "🟡"
	case model.LOW:
		return "🔵"
	default:
		return "⚪"
	}
}

func printGradeSummary(ruleSet *model.RuleSet, serverCount int, findings []model.Finding, level string) {
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	var crit, high, med, low, info int
	for _, f := range findings {
		switch f.Severity {
		case model.CRITICAL:
			crit++
		case model.HIGH:
			high++
		case model.MEDIUM:
			med++
		case model.LOW:
			low++
		case model.INFO:
			info++
		}
	}

	totalChecks := len(rules.GetChecksByLevel(ruleSet, level))
	failed := crit + high + med + low
	passed := totalChecks - failed
	if passed < 0 {
		passed = 0
	}

	fmt.Printf("  📊 扫描结果: %d 个服务器\n", serverCount)
	fmt.Printf("  📋 %s 检查项: %d/%d 通过\n", level, passed, totalChecks)
	if crit+high > 0 {
		fmt.Printf("  🔴 严重问题: %d\n", crit+high)
	}
	if med+low > 0 {
		fmt.Printf("  🟡 需改进: %d\n", med+low)
	}
	if info > 0 {
		fmt.Printf("  🔍 需人工审查: %d\n", info)
	}

	fmt.Println()

	if failed == 0 {
		fmt.Printf("  🏆 合规等级: %s %s ✅\n", level, levelName(level))
		fmt.Println("     所有检查项均通过。")
		if level == "L1" {
			fmt.Println("     运行 'mcp-audit scan -l L2' 查看增强级要求。")
		} else if level == "L2" {
			fmt.Println("     运行 'mcp-audit scan -l L3' 查看高级级要求。")
		}
	} else {
		fmt.Printf("  ⚠️  合规等级: %s 未达标\n", level)
		fmt.Printf("     有 %d 项检查未通过，请根据整改建议修复后重新扫描。\n", failed)
	}
}

func levelName(level string) string {
	switch level {
	case "L1":
		return "基础级"
	case "L2":
		return "增强级"
	case "L3":
		return "高级级"
	default:
		return ""
	}
}
