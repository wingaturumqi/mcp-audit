package output

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/wingaturumqi/mcp-audit/internal/model"
)

// SARIF 2.1.0 format structures
type sarifLog struct {
	Version string       `json:"version"`
	Schema  string       `json:"$schema"`
	Runs    []sarifRun   `json:"runs"`
}

type sarifRun struct {
	Tool     sarifTool      `json:"tool"`
	Results  []sarifResult  `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string       `json:"name"`
	Version        string       `json:"version"`
	InformationURI string       `json:"informationUri"`
	Rules          []sarifRule  `json:"rules"`
}

type sarifRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	ShortDescription sarifMessage      `json:"shortDescription"`
	FullDescription  sarifMessage      `json:"fullDescription"`
	HelpURI          string            `json:"helpUri,omitempty"`
	DefaultConfiguration sarifConfig   `json:"defaultConfiguration"`
	Properties       sarifProperties   `json:"properties"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifProperties struct {
	Tags []string `json:"tags"`
}

type sarifResult struct {
	RuleID  string       `json:"ruleId"`
	Level   string       `json:"level"`
	Message sarifMessage `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLoc `json:"physicalLocation"`
}

type sarifPhysicalLoc struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

// GenerateSARIF writes a SARIF 2.1.0 report
func GenerateSARIF(w io.Writer, version string, findings []model.Finding, serverCount int) error {
	// Build rules from findings
	ruleMap := make(map[string]bool)
	var rules []sarifRule
	for _, f := range findings {
		if ruleMap[f.TtafRef] {
			continue
		}
		ruleMap[f.TtafRef] = true
		rules = append(rules, sarifRule{
			ID:   f.TtafRef,
			Name: f.Title,
			ShortDescription: sarifMessage{Text: f.Title},
			FullDescription:  sarifMessage{Text: f.Detail},
			DefaultConfiguration: sarifConfig{
				Level: severityToSARIFLevel(f.Severity),
			},
			Properties: sarifProperties{
				Tags: []string{"security", "ttaf352", f.RequiredLevel, f.Dimension},
			},
		})
	}

	// Build results
	var results []sarifResult
	for _, f := range findings {
		results = append(results, sarifResult{
			RuleID:  f.TtafRef,
			Level:   severityToSARIFLevel(f.Severity),
			Message: sarifMessage{Text: f.Detail},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLoc{
						ArtifactLocation: sarifArtifact{URI: f.FilePath},
					},
				},
			},
		})
	}

	log := sarifLog{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "mcp-audit",
						Version:        version,
						InformationURI: "https://gitee.com/BuZhiFire/mcp-audit",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func severityToSARIFLevel(s model.Severity) string {
	switch s {
	case model.CRITICAL, model.HIGH:
		return "error"
	case model.MEDIUM:
		return "warning"
	case model.LOW:
		return "note"
	default:
		return "none"
	}
}

// GenerateHTML writes an HTML compliance report
func GenerateHTML(w io.Writer, version, level string, findings []model.Finding, serverCount int) error {
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
	failCount := crit + high + med + low

	// Build findings rows
	var rows string
	for _, f := range findings {
		icon := "⚪"
		switch f.Severity {
		case model.CRITICAL:
			icon = "🔴"
		case model.HIGH:
			icon = "🟠"
		case model.MEDIUM:
			icon = "🟡"
		case model.LOW:
			icon = "🔵"
		case model.INFO:
			icon = "🔍"
		}
		rows += fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",
			icon, f.RequiredLevel, f.TtafRef, f.Dimension, f.Title, f.Suggestion)
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>mcp-audit 合规报告 — %s %s</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;
background:#f6f8fb;color:#1f2933;line-height:1.7;padding:32px}
.wrap{max-width:960px;margin:0 auto}
h1{font-size:24px;margin-bottom:8px}
.meta{color:#52606d;font-size:14px;margin-bottom:24px}
.kpi{display:flex;gap:16px;margin-bottom:24px}
.kpi div{background:#fff;border:1px solid #e4e9f0;border-radius:12px;padding:16px 20px;flex:1}
.kpi .v{font-size:28px;font-weight:800}
.kpi .l{font-size:13px;color:#52606d}
.pass .v{color:#16a34a} .fail .v{color:#dc2626} .info .v{color:#2563eb}
table{width:100%%;border-collapse:collapse;background:#fff;border-radius:12px;overflow:hidden;margin-bottom:24px}
th,td{border:1px solid #e4e9f0;padding:10px 12px;text-align:left;font-size:13px}
th{background:#f1f5f9;font-weight:700}
tr:nth-child(even) td{background:#fafcff}
footer{text-align:center;color:#94a3b8;font-size:12px;margin-top:32px}
</style>
</head>
<body>
<div class="wrap">
<h1>🔍 mcp-audit T/TAF 352 合规报告</h1>
<p class="meta">标准: T/TAF 352—2026 | 级别: %s | 版本: %s | 服务器: %d</p>
<div class="kpi">
<div class="pass"><div class="v">%d</div><div class="l">通过</div></div>
<div class="fail"><div class="v">%d</div><div class="l">不通过</div></div>
<div><div class="v">%d</div><div class="l">需人工审查</div></div>
</div>
<table>
<thead><tr><th>状态</th><th>级别</th><th>条款</th><th>维度</th><th>检查项</th><th>整改建议</th></tr></thead>
<tbody>%s</tbody>
</table>
<footer>Generated by mcp-audit v%s | %s</footer>
</div>
</body>
</html>`, level, level, level, version, serverCount,
		failCount, failCount, info, rows, version, "T/TAF 352—2026")
	return nil
}

// GenerateBadgeSVG writes an SVG compliance badge
func GenerateBadgeSVG(w io.Writer, level string, passed, total int) error {
	var color, label string
	switch level {
	case "L3":
		color = "#16a34a"
		label = "L3 高级级"
	case "L2":
		color = "#2563eb"
		label = "L2 增强级"
	case "L1":
		color = "#0ea5a4"
		label = "L1 基础级"
	default:
		color = "#dc2626"
		label = "未达标"
	}

	pct := fmt.Sprintf("%d/%d", passed, total)
	leftW := len(label)*8 + 16
	rightW := len(pct)*8 + 16
	totalW := leftW + rightW

	svg := fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="20">
  <linearGradient id="b" x2="0" y2="100%%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <mask id="a"><rect width="%d" height="20" rx="3" fill="#fff"/></mask>
  <g mask="url(#a)">
    <rect width="%d" height="20" fill="#555"/>
    <rect x="%d" width="%d" height="20" fill="%s"/>
    <rect width="%d" height="20" fill="url(#b)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="%d" y="15" fill="#010101" fill-opacity=".3">%s</text>
    <text x="%d" y="14">%s</text>
    <text x="%d" y="15" fill="#010101" fill-opacity=".3">%s</text>
    <text x="%d" y="14">%s</text>
  </g>
</svg>`, totalW, totalW, leftW, leftW, rightW, color, totalW,
		leftW/2, label, leftW/2, label,
		leftW+rightW/2, pct, leftW+rightW/2, pct)

	fmt.Fprint(w, svg)
	return nil
}
