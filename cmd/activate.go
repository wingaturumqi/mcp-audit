package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/wingaturumqi/mcp-audit/internal/license"
)

var activateCmd = &cobra.Command{
	Use:   "activate [email]",
	Short: "激活 Pro 许可证",
	Long:  "使用购买时的邮箱激活 Pro 许可证，解锁高级功能。",
	Args:  cobra.ExactArgs(1),
	RunE:  runActivate,
}

func init() {
	rootCmd.AddCommand(activateCmd)
}

func runActivate(cmd *cobra.Command, args []string) error {
	email := args[0]

	// Check if license file already has a signature for this email
	existing, _ := license.Load()
	if existing != nil && existing.Email == email && license.Validate(existing) == nil {
		fmt.Printf("✅ Pro 许可证已激活 (邮箱: %s)\n", email)
		return nil
	}

	// The activate command expects the user to provide the license key
	// which is the Ed25519 signature. In the purchase flow, this is
	// delivered via email. For now, we show instructions.
	fmt.Println("📋 激活 Pro 许可证")
	fmt.Println()
	fmt.Println("请将购买时收到的许可证密钥（license key）设置为环境变量:")
	fmt.Println()
	fmt.Println("  export MCP_AUDIT_LICENSE_KEY=<your-license-key>")
	fmt.Println()
	fmt.Println("然后运行:")
	fmt.Printf("  mcp-audit activate %s\n", email)
	fmt.Println()
	fmt.Println("购买: https://gitee.com/BuZhiFire/mcp-audit#pro")

	return nil
}
