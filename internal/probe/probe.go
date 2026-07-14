package probe

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/wingaturumqi/mcp-audit/internal/scanner"
)

// ToolInfo represents a tool returned by tools/list
type ToolInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type jsonrpcRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int         `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

type jsonrpcNotification struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

type jsonrpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *jsonrpcError   `json:"error,omitempty"`
}

type jsonrpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type initResult struct {
	ProtocolVersion string `json:"protocolVersion"`
	ServerInfo      struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"serverInfo"`
}

type toolsListResult struct {
	Tools []ToolInfo `json:"tools"`
}

// ProbeResult contains the result of probing an MCP server
type ProbeResult struct {
	ServerName  string
	Tools       []ToolInfo
	ServerInfo  string
	Error       string
	Transport   string
}

// ProbeStdio connects to a stdio MCP server and retrieves tools/list
func ProbeStdio(command string, args []string, env map[string]string, timeout time.Duration) (*ProbeResult, error) {
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	cmd := exec.Command(command, args...)

	// Set environment variables
	if env != nil {
		for k, v := range env {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("创建 stdin 管道失败: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("创建 stdout 管道失败: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("启动进程失败: %w", err)
	}

	// Ensure cleanup
	defer func() {
		stdin.Close()
		cmd.Process.Kill()
		cmd.Wait()
	}()

	reader := bufio.NewReader(stdout)

	// Step 1: Send initialize
	initReq := jsonrpcRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
		Params: map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]interface{}{},
			"clientInfo": map[string]string{
				"name":    "mcp-audit",
				"version": "1.0.0",
			},
		},
	}

	if err := sendJSONRPC(stdin, initReq); err != nil {
		return nil, fmt.Errorf("发送 initialize 失败: %w", err)
	}

	// Read initialize response
	initResp, err := readJSONRPC(reader, timeout)
	if err != nil {
		return nil, fmt.Errorf("读取 initialize 响应失败: %w", err)
	}

	if initResp.Error != nil {
		return nil, fmt.Errorf("initialize 错误: %s", initResp.Error.Message)
	}

	var initRes initResult
	if err := json.Unmarshal(initResp.Result, &initRes); err != nil {
		return nil, fmt.Errorf("解析 initialize 结果失败: %w", err)
	}

	// Step 2: Send initialized notification
	notif := jsonrpcNotification{
		JSONRPC: "2.0",
		Method:  "notifications/initialized",
	}
	if err := sendJSONRPC(stdin, notif); err != nil {
		return nil, fmt.Errorf("发送 initialized 通知失败: %w", err)
	}

	// Step 3: Send tools/list
	toolsReq := jsonrpcRequest{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "tools/list",
	}

	if err := sendJSONRPC(stdin, toolsReq); err != nil {
		return nil, fmt.Errorf("发送 tools/list 失败: %w", err)
	}

	toolsResp, err := readJSONRPC(reader, timeout)
	if err != nil {
		return nil, fmt.Errorf("读取 tools/list 响应失败: %w", err)
	}

	if toolsResp.Error != nil {
		return nil, fmt.Errorf("tools/list 错误: %s", toolsResp.Error.Message)
	}

	var toolsRes toolsListResult
	if err := json.Unmarshal(toolsResp.Result, &toolsRes); err != nil {
		return nil, fmt.Errorf("解析 tools/list 结果失败: %w", err)
	}

	return &ProbeResult{
		Tools:     toolsRes.Tools,
		ServerInfo: fmt.Sprintf("%s %s", initRes.ServerInfo.Name, initRes.ServerInfo.Version),
		Transport: "stdio",
	}, nil
}

// ProbeHTTP connects to an HTTP/SSE MCP server and retrieves tools/list
func ProbeHTTP(url string, env map[string]string, timeout time.Duration) (*ProbeResult, error) {
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	client := &http.Client{Timeout: timeout}

	// Step 1: Initialize
	initReq := jsonrpcRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
		Params: map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]interface{}{},
			"clientInfo": map[string]string{
				"name":    "mcp-audit",
				"version": "1.0.0",
			},
		},
	}

	initResp, err := httpPostJSONRPC(client, url, initReq, env)
	if err != nil {
		return nil, fmt.Errorf("initialize 请求失败: %w", err)
	}

	if initResp.Error != nil {
		return nil, fmt.Errorf("initialize 错误: %s", initResp.Error.Message)
	}

	var initRes initResult
	if err := json.Unmarshal(initResp.Result, &initRes); err != nil {
		return nil, fmt.Errorf("解析 initialize 结果失败: %w", err)
	}

	// Step 2: tools/list
	toolsReq := jsonrpcRequest{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "tools/list",
	}

	toolsResp, err := httpPostJSONRPC(client, url, toolsReq, env)
	if err != nil {
		return nil, fmt.Errorf("tools/list 请求失败: %w", err)
	}

	if toolsResp.Error != nil {
		return nil, fmt.Errorf("tools/list 错误: %s", toolsResp.Error.Message)
	}

	var toolsRes toolsListResult
	if err := json.Unmarshal(toolsResp.Result, &toolsRes); err != nil {
		return nil, fmt.Errorf("解析 tools/list 结果失败: %w", err)
	}

	return &ProbeResult{
		Tools:     toolsRes.Tools,
		ServerInfo: fmt.Sprintf("%s %s", initRes.ServerInfo.Name, initRes.ServerInfo.Version),
		Transport: "http",
	}, nil
}

// ProbeAndScan connects to a server, gets tools, and runs poison detection
func ProbeAndScan(serverName, command string, args []string, env map[string]string, url, transport string, filePath string) (*ProbeResult, []scanner.ToolDesc) {
	var result *ProbeResult
	var err error

	switch transport {
	case "stdio":
		result, err = ProbeStdio(command, args, env, 10*time.Second)
	case "sse", "streamable-http":
		result, err = ProbeHTTP(url, env, 10*time.Second)
	default:
		// Try to auto-detect
		if url != "" {
			result, err = ProbeHTTP(url, env, 10*time.Second)
		} else if command != "" {
			result, err = ProbeStdio(command, args, env, 10*time.Second)
		} else {
			return &ProbeResult{ServerName: serverName, Error: "无法确定传输类型"}, nil
		}
	}

	if err != nil {
		return &ProbeResult{
			ServerName: serverName,
			Error:      err.Error(),
			Transport:  transport,
		}, nil
	}

	result.ServerName = serverName

	// Convert to ToolDesc for poison scanning
	var tools []scanner.ToolDesc
	for _, t := range result.Tools {
		tools = append(tools, scanner.ToolDesc{
			Name:        t.Name,
			Description: t.Description,
		})
	}

	return result, tools
}

// --- helpers ---

func sendJSONRPC(w io.Writer, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = w.Write(data)
	return err
}

func readJSONRPC(reader *bufio.Reader, timeout time.Duration) (*jsonrpcResponse, error) {
	done := make(chan *jsonrpcResponse, 1)
	errCh := make(chan error, 1)

	go func() {
		for {
			line, err := reader.ReadBytes('\n')
			if err != nil {
				errCh <- err
				return
			}
			line = bytes.TrimSpace(line)
			if len(line) == 0 {
				continue
			}

			var resp jsonrpcResponse
			if err := json.Unmarshal(line, &resp); err != nil {
				continue // skip malformed lines
			}

			// Only return responses with an ID (not notifications)
			if resp.ID > 0 {
				done <- &resp
				return
			}
		}
	}()

	select {
	case resp := <-done:
		return resp, nil
	case err := <-errCh:
		return nil, err
	case <-time.After(timeout):
		return nil, fmt.Errorf("超时 (%v)", timeout)
	}
}

func httpPostJSONRPC(client *http.Client, url string, req jsonrpcRequest, env map[string]string) (*jsonrpcResponse, error) {
	data, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	// Add auth from env
	for k, v := range env {
		kl := strings.ToLower(k)
		if strings.Contains(kl, "token") || strings.Contains(kl, "key") || strings.Contains(kl, "auth") {
			httpReq.Header.Set("Authorization", "Bearer "+v)
			break
		}
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body[:min(len(body), 200)]))
	}

	var rpcResp jsonrpcResponse
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return nil, fmt.Errorf("解析 JSON-RPC 响应失败: %w", err)
	}

	return &rpcResp, nil
}
