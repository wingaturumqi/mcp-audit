package scanner

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/wingaturumqi/mcp-audit/internal/model"
)

// PoisonPattern represents a detection rule for tool description poisoning
type PoisonPattern struct {
	ID       string
	Category string
	Severity model.Severity
	Pattern  *regexp.Regexp
	Desc     string
}

// poisonPatterns is the detection pattern library
var poisonPatterns []PoisonPattern

func init() {
	poisonPatterns = []PoisonPattern{
		// === 中文攻击模式 ===
		{
			ID: "CN-01", Category: "指令覆盖", Severity: model.CRITICAL,
			Pattern:  regexp.MustCompile(`(?i)(忽略|无视|跳过|抛弃|忘记)(之前|上面|以上|以前|先前)(的|所有)?(指令|提示|规则|要求|设定|限制|约束)`),
			Desc:     "检测到中文指令覆盖模式（忽略之前的指令）",
		},
		{
			ID: "CN-02", Category: "角色劫持", Severity: model.CRITICAL,
			Pattern:  regexp.MustCompile(`(?i)(你现在是|你扮演|假装你是|你的新角色|从现在起你不再是|切换到)(.{0,20})(模式|助手|管理员|开发者|AI|系统)`),
			Desc:     "检测到中文角色劫持模式",
		},
		{
			ID: "CN-03", Category: "指令注入", Severity: model.HIGH,
			Pattern:  regexp.MustCompile(`(?i)(请|帮我|立即|马上|偷偷|秘密|悄悄)(执行|运行|删除|发送|上传|下载|导出|传输|复制)(以下|下面|这个|所有)`),
			Desc:     "检测到中文指令注入（诱导执行敏感操作）",
		},
		{
			ID: "CN-04", Category: "数据外发", Severity: model.CRITICAL,
			Pattern:  regexp.MustCompile(`(?i)(把|将|把所有|将所有)?(数据|文件|信息|内容|密钥|密码|token|凭证|配置)(发送|上传|传输|转发|发到|发给|POST|GET|请求)(到|给|往)`),
			Desc:     "检测到中文数据外发指令",
		},
		{
			ID: "CN-05", Category: "系统提示", Severity: model.HIGH,
			Pattern:  regexp.MustCompile(`(?i)(系统提示|系统指令|管理员指令|开发者模式|调试模式|维护模式|紧急模式)[:：]`),
			Desc:     "检测到中文伪系统提示注入",
		},
		{
			ID: "CN-06", Category: "绕过限制", Severity: model.HIGH,
			Pattern:  regexp.MustCompile(`(?i)(不要|无需|禁止|跳过|绕过|破解|解除)(安全|验证|认证|授权|权限|检查|审核|过滤|限制|沙箱|隔离)`),
			Desc:     "检测到中文安全限制绕过指令",
		},
		{
			ID: "CN-07", Category: "隐蔽操作", Severity: model.HIGH,
			Pattern:  regexp.MustCompile(`(?i)(不要|别|禁止)(告诉|告知|通知|显示|输出|记录|日志)(用户|主人|管理员|任何人)`),
			Desc:     "检测到隐蔽操作指令（要求不通知用户）",
		},

		// === 英文攻击模式 ===
		{
			ID: "EN-01", Category: "指令覆盖", Severity: model.CRITICAL,
			Pattern:  regexp.MustCompile(`(?i)(ignore|disregard|forget|override|discard)\s+(all\s+)?(previous|above|prior|earlier)\s+(instructions|rules|prompts|constraints|directives)`),
			Desc:     "检测到英文指令覆盖模式 (ignore previous instructions)",
		},
		{
			ID: "EN-02", Category: "系统注入", Severity: model.CRITICAL,
			Pattern:  regexp.MustCompile(`(?i)(system\s*(prompt|override|message|instruction)|you\s+are\s+now|act\s+as|pretend\s+(to\s+be|you('re|\s+are))|new\s+role)`),
			Desc:     "检测到英文系统提示注入",
		},
		{
			ID: "EN-03", Category: "代码执行", Severity: model.CRITICAL,
			Pattern:  regexp.MustCompile(`(?i)(execute|run|eval|exec)\s+(the\s+following|this|these)\s+(command|code|script|shell|payload)`),
			Desc:     "检测到英文代码执行注入",
		},
		{
			ID: "EN-04", Category: "数据外发", Severity: model.CRITICAL,
			Pattern:  regexp.MustCompile(`(?i)(send|exfiltrate|upload|transmit|post|leak)\s+(all\s+)?(data|files|secrets|tokens|keys|credentials|config)\s+(to|via|through)`),
			Desc:     "检测到英文数据外发指令",
		},
		{
			ID: "EN-05", Category: "安全绕过", Severity: model.HIGH,
			Pattern:  regexp.MustCompile(`(?i)(bypass|disable|remove|circumvent|break)\s+(security|auth|sandbox|isolation|restriction|validation|filter|check)`),
			Desc:     "检测到英文安全绕过指令",
		},
		{
			ID: "EN-06", Category: "角色劫持", Severity: model.HIGH,
			Pattern:  regexp.MustCompile(`(?i)(developer\s+mode|debug\s+mode|maintenance\s+mode|god\s+mode|sudo\s+mode|admin\s+mode|DAN|jailbreak)`),
			Desc:     "检测到英文模式切换注入",
		},
		{
			ID: "EN-07", Category: "隐蔽操作", Severity: model.HIGH,
			Pattern:  regexp.MustCompile(`(?i)(do\s+not|never|don't)\\s+(tell|inform|notify|show|display|log|report)\s+(the\s+)?(user|human|admin|anyone)`),
			Desc:     "检测到隐蔽操作指令 (do not tell user)",
		},

		// === 特殊标签检测 ===
		{
			ID: "TAG-01", Category: "隐藏标签", Severity: model.CRITICAL,
			Pattern:  regexp.MustCompile(`(?i)<\s*(hidden[_-]?instruction|system[_-]?prompt|override|secret[_-]?command|internal[_-]?note|admin[_-]?note)`),
			Desc:     "检测到隐藏指令标签",
		},
		{
			ID: "TAG-02", Category: "隐藏标签", Severity: model.HIGH,
			Pattern:  regexp.MustCompile(`(?i)\[(hidden|secret|internal|admin|system)\s*(instruction|command|note|prompt)\]`),
			Desc:     "检测到方括号隐藏指令标签",
		},
		{
			ID: "TAG-03", Category: "编码绕过", Severity: model.HIGH,
			Pattern:  regexp.MustCompile(`(?i)(base64|hex|rot13|unicode|url[_-]?encode)(\s*[:=]\s*|\s+)([A-Za-z0-9+/=]{20,}|%[0-9A-Fa-f]{2})`),
			Desc:     "检测到编码绕过（base64/hex/rot13 编码的隐藏内容）",
		},

		// === 网络外发检测 ===
		{
			ID: "NET-01", Category: "网络外发", Severity: model.HIGH,
			Pattern:  regexp.MustCompile(`https?://[^\s"']+\.(xyz|top|tk|ml|ga|cf|gq|pw|cc|ru|cn)[^\s"']*`),
			Desc:     "检测到可疑高风险域名 URL",
		},
		{
			ID: "NET-02", Category: "网络外发", Severity: model.MEDIUM,
			Pattern:  regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}\b`),
			Desc:     "检测到嵌入的 IP:Port 地址",
		},
		{
			ID: "NET-03", Category: "网络外发", Severity: model.MEDIUM,
			Pattern:  regexp.MustCompile(`(?i)(curl|wget|fetch|http\.get|http\.post|axios|requests\.get|urllib)\s*\(`),
			Desc:     "检测到网络请求函数调用",
		},

		// === 命令注入检测 ===
		{
			ID: "CMD-01", Category: "命令注入", Severity: model.CRITICAL,
			Pattern:  regexp.MustCompile(`(?i)(;\s*|\|\s*|&&\s*|` + "`" + `)\s*(rm\s+-rf|del\s+/[sf]|format\s+c:|shutdown|reboot|mkfs|dd\s+if=|chmod\s+777|cat\s+/etc/passwd|curl\s+.*\|\s*sh)`),
			Desc:     "检测到危险系统命令注入",
		},
		{
			ID: "CMD-02", Category: "命令注入", Severity: model.HIGH,
			Pattern:  regexp.MustCompile(`(?i)(os\.system|subprocess|exec|eval|__import__|child_process|spawn|execSync)\s*\(`),
			Desc:     "检测到代码执行函数调用",
		},
	}
}

// DetectPoison scans a tool description for poisoning patterns
// Returns findings for each matched pattern
func DetectPoison(serverName, toolName, description string, filePath string) []model.Finding {
	var findings []model.Finding

	for _, p := range poisonPatterns {
		if p.Pattern.MatchString(description) {
			match := p.Pattern.FindString(description)
			findings = append(findings, model.Finding{
				ServerName:    serverName,
				Severity:      p.Severity,
				TtafRef:       "5.3.b",
				Dimension:     "工具与资源安全",
				Title:         fmt.Sprintf("[%s] 投毒检测: %s", p.ID, p.Category),
				Detail:        fmt.Sprintf("工具 '%s' 描述中检测到可疑内容: %s\n匹配: %s", toolName, p.Desc, truncate(match, 80)),
				Suggestion:    "审查该工具描述，移除可疑指令后重新注册",
				RequiredLevel: "L2",
				FilePath:      filePath,
			})
		}
	}

	return findings
}

// DetectPoisonBatch scans multiple tool descriptions
func DetectPoisonBatch(serverName string, tools []ToolDesc, filePath string) []model.Finding {
	var findings []model.Finding
	for _, t := range tools {
		findings = append(findings, DetectPoison(serverName, t.Name, t.Description, filePath)...)
	}
	return findings
}

// ToolDesc represents a tool with its name and description
type ToolDesc struct {
	Name        string
	Description string
}

func truncate(s string, max int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
