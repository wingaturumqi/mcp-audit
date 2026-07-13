package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	versionStr = "dev"
	commitStr  = "none"
)

func SetVersion(version, commit string) {
	versionStr = version
	commitStr = commit
}

var rootCmd = &cobra.Command{
	Use:   "mcp-audit",
	Short: "MCP Server 安全合规分级自查工具",
	Long: `mcp-audit — 基于 T/TAF 352—2026 标准的 MCP Server 安全合规分级自查 CLI。

扫描你的 MCP 配置，检测安全问题，输出 L1/L2/L3 分级报告和整改建议。

标准：T/TAF 352—2026《模型上下文协议服务器（MCP Server）安全技术要求》`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
