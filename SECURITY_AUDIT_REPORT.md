# 🔍 安全审计报告

## 📊 执行摘要
- **审计对象**: mcp-audit — 基于 T/TAF 352—2026 标准的 MCP Server 安全合规分级自查 CLI
- **审计路径**: `D:\project\mcp-audit`
- **审计范围**: 全部 Go 源码（21 个 .go 文件）、规则 JSON（2 个）、依赖清单（go.mod / go.sum）、文档
- **发现问题总数**: 0 个
  - 🔴 Malicious（恶意）: 0 个
  - ⚠️ Suspicious（可疑）: 0 个
  - 📝 信息性提醒: 2 个（非风险项，不计入风险总数）
- **安全评分**: 85 分

---

## 🔴 Malicious（恶意）风险发现

✅ 未发现 Malicious 风险

未发现任何自动执行的下载+执行、敏感信息外送、破坏性命令、隐蔽操作或权限提升等恶意操作组合。

---

## ⚠️ Suspicious（可疑）风险发现

✅ 未发现 Suspicious 风险

未发现自动执行的全局未固定版本依赖安装、非官方源安装或未固定 commit SHA 的仓库依赖。

---

## 📝 信息性提醒（非风险项）

1. **`--live` 模式会执行用户配置中的命令**（信息性提醒）
   - **位置**: `internal/probe/probe.go:75`
   - **代码片段**: `cmd := exec.Command(command, args...)`
   - **说明**: 该 `exec.Command` 属于 `ProbeStdio` 函数，仅在用户显式运行 `mcp-audit scan --live` 时触发。执行的 `command` 与 `args` 均来自用户自己的 MCP 配置文件（Claude Desktop / Cursor / VS Code / Windsurf / .mcp.json），是工具连接 stdio MCP Server 获取 `tools/list` 定义的核心功能，属于"提供能力"而非自动投毒。功能描述与实际行为完全一致，无隐藏意图。
   - **建议**: 建议在 `--live` 模式的帮助文档中明确提示"将执行配置文件中的命令"，引导用户仅对可信配置启用该模式。

2. **README 安装命令使用 `@latest` 未固定版本**（信息性提醒）
   - **位置**: `README.md:15`、`README_zh.md:15`
   - **代码片段**: `go install github.com/wingaturumqi/mcp-audit@latest`
   - **说明**: 这是 Go 模块的标准安装方式，由用户手动执行，非工具自动执行，不构成投毒风险。
   - **建议**: 生产环境建议改用固定版本号安装（如 `go install github.com/wingaturumqi/mcp-audit@v1.0.0`），并可附加 checksum 校验。

---

## 📋 详细检查结果

### 命令执行与权限检查
- 发现次数: 1 处真实命令执行 + 2 处 `os.Executable()` 路径查询
- 详细列表:
  - `internal/probe/probe.go:75` — `cmd := exec.Command(command, args...)`：`--live` 模式下连接 stdio MCP Server，命令来源为用户配置文件，需用户显式启用
  - `internal/rules/loader.go:52,107` — `os.Executable()`：仅获取当前可执行文件路径以定位 rules JSON，非执行外部命令
- **结论**: 无恶意命令执行。唯一的 `exec.Command` 是工具核心功能且受用户显式控制。

### 文件操作与敏感路径检查
- 发现次数: 文件写入 4 处，敏感路径关键词命中均为检测正则
- 详细列表:
  - `cmd/report.go:66` — `os.Create(reportOutput)`：写入 HTML 报告，路径来自用户命令行参数
  - `cmd/badge.go:80` — `os.Create(badgeOutput)`：写入 SVG 徽章，路径来自用户命令行参数
  - `cmd/ci.go:86` — `os.Create(ciOutput)`：写入 CI 输出文件，路径来自用户命令行参数
  - `internal/license/license.go:59` — `os.WriteFile(LicensePath(), data, 0600)`：写入 license 文件到配置目录（`~/.mcp-audit/` 或 `%APPDATA%/mcp-audit/`），权限 0600
  - `internal/scanner/poison.go:80,136` — `.ssh`/`private_key`/`credentials` 等关键词仅出现在**投毒检测正则模式**中，用于识别恶意内容，非实际访问敏感路径
  - `internal/scanner/scanner.go:137` — 检查 env 中是否含 `private_key` 字段名以告警敏感信息可能泄露，非读取私钥
- **结论**: 所有文件写入均指向用户指定路径或标准配置目录；敏感路径关键词均为检测逻辑，无实际越权访问。

### 网络请求检查
- 发现的 URL:
  - `https://gitee.com/BuZhiFire/mcp-audit` — 项目主页（购买/信息链接，仅展示不访问）
  - `https://github.com/wingaturumqi/mcp-audit` — GitHub 镜像（文档中展示）
  - `https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json` — SARIF 标准 schema URI（仅作为 JSON 输出的 `$schema` 字段值，不会被程序访问）
  - `http://www.w3.org/2000/svg` — SVG 命名空间声明（标准）
  - `http://evil.xyz/collect` — 测试用例中的恶意 URL 样本（仅用于测试检测功能）
- 实际网络请求: 仅 `internal/probe/probe.go` 中 `httpPostJSONRPC`（HTTP POST），目标 URL 来自用户 MCP 配置文件，用于连接远程 MCP Server 获取 `tools/list`，属 `--live` 模式核心功能
- Base64 编码检测: 仅出现在 `poison.go` 的检测正则与测试用例中，无实际 base64 解码或外送行为
- **结论**: 无自动下载并执行远程脚本的模式（无 `curl|bash`、`wget|sh` 等）；网络请求均为工具核心功能且受用户控制。

### 远程脚本深度分析
- 不适用。未发现任何自动下载并执行远程脚本的行为，无需进行远程内容深度分析。

### 依赖安装风险检查
- **全局安装检测**: 未发现工具自动执行的全局依赖安装命令
- **虚拟环境检查**: Go 项目，依赖通过 `go.mod` 管理，编译为单一二进制，天然隔离
- **依赖来源检查**:
  - `go.mod` 唯一直接依赖 `github.com/spf13/cobra v1.10.2` — **版本已固定**
  - 传递依赖（mousetrap v1.1.0、pflag v1.0.9 等）均为知名合法库且版本固定
  - `go.sum` 含完整哈希校验，防篡改
  - 无非官方源（`--index-url` / `--registry`）安装
  - 无未固定 commit SHA 的仓库依赖
- **结论**: 依赖供应链安全，无投毒风险。

---

## 💡 总体建议

1. **`--live` 模式安全提示**: 该模式会执行用户配置文件中的命令并连接远程 MCP Server，建议在命令帮助中加入明确的安全提示，引导用户仅对可信配置启用。
2. **license 公钥管理**: `internal/license/license.go` 中硬编码的 Ed25519 公钥（用于验证许可证签名）为作者自身公钥，不构成泄露风险；如需轮换可考虑支持从配置目录加载外部公钥。
3. **HTTP probe 认证处理**: `httpPostJSONRPC` 会从 env 中提取含 `token`/`key`/`auth` 字段的值作为 Bearer token 发送，这是连接需认证 MCP Server 的合理行为；建议在文档中说明此机制，避免用户混淆。
4. **安装版本固定**: 建议在 README 中同时提供固定版本号的安装示例，便于生产环境使用。

---

## ✅ 审计结论

**风险等级**: ✅ Benign（可信）

**审计依据**:
- 项目功能描述（MCP Server 安全合规自查 CLI）与实际代码行为完全一致，无隐藏意图
- 唯一的命令执行（`exec.Command`）是 `--live` 模式核心功能，受用户显式控制，命令来源为用户自有配置
- 所有文件操作均限于用户指定路径或标准配置目录
- 无自动下载执行远程脚本、无敏感信息外送、无破坏性命令、无隐蔽执行
- 依赖版本固定且有哈希校验，供应链安全

**使用建议**:
- ✅ **Benign（可信）- 可以安全使用**（85 分）：无投毒风险。代码行为与声明功能一致，所有敏感操作（命令执行、网络请求）均为工具核心功能且需用户显式触发。
