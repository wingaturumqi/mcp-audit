package scanner

import (
	"strings"

	"github.com/wingaturumqi/mcp-audit/internal/model"
)

// ScanConfig evaluates an MCP server config against T/TAF 352 checks
// Returns: findings for failed/needs-review items
func ScanConfig(server model.MCPServer, filePath string, checks []model.CheckRuleWithDimension) []model.Finding {
	var findings []model.Finding

	for _, c := range checks {
		result := evaluateCheck(server, c)
		if result != nil {
			result.FilePath = filePath
			findings = append(findings, *result)
		}
	}

	return findings
}

// evaluateCheck runs a single check against a server config.
// Returns nil if passed, a Finding if failed or needs review.
func evaluateCheck(server model.MCPServer, c model.CheckRuleWithDimension) *model.Finding {
	f := &model.Finding{
		ServerName:    server.Name,
		TtafRef:       c.Check.ID,
		Dimension:     c.DimName,
		Title:         c.Check.Title,
		RequiredLevel: c.Check.MinLevel,
		Suggestion:    c.Check.Remediation,
	}

	switch c.Check.ID {

	// === 5.1 身份鉴别与访问控制 ===

	case "5.1.a": // 身份认证机制
		if server.Transport == "sse" || server.Transport == "streamable-http" {
			hasAuth := false
			for k := range server.Env {
				kl := strings.ToLower(k)
				if strings.Contains(kl, "token") || strings.Contains(kl, "key") ||
					strings.Contains(kl, "secret") || strings.Contains(kl, "auth") {
					hasAuth = true
					break
				}
			}
			if !hasAuth {
				f.Severity = model.HIGH
				f.Detail = "远程 MCP 服务器未在环境变量中配置认证凭据（API Key/Token）"
				return f
			}
		}
		return nil // stdio 本地模式不要求强制认证

	case "5.1.d.1": // 账号权限管理-基本分离
		// 从配置层面无法完全验证，但可以检查是否有权限相关配置
		return nil // pass - 配置层面无明显违规

	case "5.1.e": // 高危操作二次确认 (L3 only)
		// 无法从配置静态检测
		f.Severity = model.INFO
		f.Detail = "高危操作二次确认需运行时验证，建议人工审查"
		return f

	// === 5.2 通信与接口安全 ===

	case "5.2.a.1": // 远程传输加密-基础 (TLS 1.2+)
		if server.Transport == "sse" || server.Transport == "streamable-http" {
			if !strings.HasPrefix(server.URL, "https://") {
				f.Severity = model.CRITICAL
				f.Detail = "远程 MCP 服务器使用非加密连接: " + server.URL
				return f
			}
		}
		return nil

	case "5.2.a.2": // 远程传输加密-增强 (TLS 1.3)
		// 无法从配置判断 TLS 版本
		f.Severity = model.INFO
		f.Detail = "TLS 版本需运行时验证，建议人工确认是否使用 TLS 1.3"
		return f

	case "5.2.b": // 本地模式通信安全
		if server.Transport == "stdio" {
			// stdio 管道由 OS 保护，一般 pass
			return nil
		}
		return nil

	case "5.2.c.1": // 接口完整性校验-基础
		// 无法从配置静态检测
		return nil

	case "5.2.e": // 重放攻击防护 (L2+)
		f.Severity = model.INFO
		f.Detail = "重放攻击防护需运行时验证"
		return f

	case "5.2.f.1": // 接口输入验证-基础
		// 无法从配置静态检测
		return nil

	case "5.2.f.3": // WAF与限流 (L3)
		f.Severity = model.INFO
		f.Detail = "WAF/限流配置需运行时或部署配置验证"
		return f

	// === 5.3 工具与资源安全 ===

	case "5.3.b": // 隐藏指令检测 (投毒检测)
		f.Severity = model.MEDIUM
		f.Detail = "工具描述投毒检测需运行时扫描工具定义（tools/list），建议部署正则+语义检测"
		return f

	case "5.3.c.1": // 工具权限声明-基本限制
		// 检查命令是否使用绝对路径（安全实践）
		if server.Transport == "stdio" && server.Command != "" {
			if server.Command == "npx" || server.Command == "uvx" || server.Command == "pip" || server.Command == "node" {
				f.Severity = model.LOW
				f.Detail = "命令使用 '" + server.Command + "' 而非绝对路径，可能存在路径注入风险"
				return f
			}
		}
		return nil

	case "5.3.d.1": // 工具输出安全-敏感信息脱敏
		// 检查 env 中是否有敏感信息可能泄露给模型
		sensitiveKeys := []string{}
		for k := range server.Env {
			kl := strings.ToLower(k)
			if strings.Contains(kl, "password") || strings.Contains(kl, "secret") ||
				strings.Contains(kl, "private_key") {
				sensitiveKeys = append(sensitiveKeys, k)
			}
		}
		if len(sensitiveKeys) > 0 {
			f.Severity = model.MEDIUM
			f.Detail = "环境变量含敏感字段可能被模型读取: " + strings.Join(sensitiveKeys, ", ")
			return f
		}
		return nil

	case "5.3.e.1": // 资源访问控制-基本权限
		return nil // 配置层面无明显违规

	// === 5.4 执行环境安全 ===

	case "5.4.a": // 执行环境隔离-低权限运行
		return nil // 配置层面无法验证

	case "5.4.b": // 容器化 (L2+)
		f.Severity = model.INFO
		f.Detail = "容器化部署需运行时验证"
		return f

	case "5.4.d": // 运行时入侵防护-基线监控
		f.Severity = model.INFO
		f.Detail = "基线完整性监控需运行时验证"
		return f

	case "5.4.g": // 配置变更管控-授权管理
		return nil

	case "5.4.j": // 组件漏洞管理-定期关注
		return nil

	// === 5.5 供应链与更新安全 ===

	case "5.5.a.1": // 组件安全审查-静态分析
		// 检查是否使用已知有风险的包管理器直接执行
		if server.Transport == "stdio" {
		 risky := false
		 switch server.Command {
		 case "npx", "uvx":
			 risky = true
		 }
		 if risky {
			 f.Severity = model.LOW
			 f.Detail = "使用 '" + server.Command + "' 直接执行可能引入未经审查的依赖"
			 return f
		 }
		}
		return nil

	case "5.5.b.1": // 软件签名和验证-校验和
		return nil // 配置层面无法验证

	case "5.5.c.1": // 更新机制安全-加密链路
		if server.Transport == "sse" || server.Transport == "streamable-http" {
			if !strings.HasPrefix(server.URL, "https://") {
				f.Severity = model.HIGH
				f.Detail = "远程通信未使用 HTTPS，更新链路不安全"
				return f
			}
		}
		return nil

	// === 5.6 数据安全与隐私保护 ===

	case "5.6.a.1": // 数据存储安全-基本保护
		return nil

	case "5.6.b.1": // 数据调用控制-最小化原则
		return nil

	case "5.6.c": // 隐私保护技术应用 (L2+)
		f.Severity = model.INFO
		f.Detail = "隐私保护（脱敏/差分隐私）需运行时验证"
		return f

	case "5.6.d": // 访问日志与追踪 (L2+)
		f.Severity = model.INFO
		f.Detail = "敏感数据访问日志需运行时验证"
		return f

	// === 5.7 日志审计与安全监控 ===

	case "5.7.a.1": // 安全事件日志-基础记录
		return nil

	case "5.7.b": // 日志保护与完整性
		return nil

	case "5.7.c": // 安全监控与告警 (L2+)
		f.Severity = model.INFO
		f.Detail = "安全监控与告警需运行时验证"
		return f

	case "5.7.d": // 定期审计和演练 (L2+)
		f.Severity = model.INFO
		f.Detail = "定期审计机制需人工审查"
		return f

	default:
		// Unknown check - mark for manual review
		if c.Check.CheckType == "manual_review" {
			f.Severity = model.INFO
			f.Detail = "此检查项需人工审查"
			return f
		}
		return nil
	}
}
