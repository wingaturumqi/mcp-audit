package license

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// License represents a Pro license
type License struct {
	Email     string   `json:"email"`
	Signature string   `json:"signature"` // Ed25519 hex signature of email
	Features  []string `json:"features"`
	IssuedAt  string   `json:"issued_at"`
	ExpiresAt string   `json:"expires_at,omitempty"` // empty = perpetual
}

// Embedded Ed25519 public key (32 bytes hex-encoded = 64 chars)
var publicKeyHex = "0fc90d6314e1a89a178cad85bb65fe9d4f7ba83a8fd8096ac87fe7bc0d064ade"

func publicKey() ed25519.PublicKey {
	b, err := hex.DecodeString(publicKeyHex)
	if err != nil || len(b) != ed25519.PublicKeySize {
		panic("invalid embedded public key")
	}
	return ed25519.PublicKey(b)
}

func configDir() string {
	if runtime.GOOS == "windows" {
		if appData := os.Getenv("APPDATA"); appData != "" {
			return filepath.Join(appData, "mcp-audit")
		}
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".mcp-audit")
}

// LicensePath returns the path to the license file
func LicensePath() string {
	return filepath.Join(configDir(), "license.json")
}

// Save writes the license to disk
func Save(lic *License) error {
	dir := configDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating config dir: %w", err)
	}
	data, err := json.MarshalIndent(lic, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(LicensePath(), data, 0600)
}

// Load reads the license from disk
func Load() (*License, error) {
	data, err := os.ReadFile(LicensePath())
	if err != nil {
		return nil, fmt.Errorf("未找到 license 文件 (运行 'mcp-audit activate <key> 激活')")
	}
	var lic License
	if err := json.Unmarshal(data, &lic); err != nil {
		return nil, fmt.Errorf("license 文件格式错误: %w", err)
	}
	return &lic, nil
}

// Validate checks if the license is valid
func Validate(lic *License) error {
	if lic == nil {
		return fmt.Errorf("未提供 license")
	}
	if lic.ExpiresAt != "" {
		expires, err := time.Parse(time.RFC3339, lic.ExpiresAt)
		if err == nil && time.Now().After(expires) {
			return fmt.Errorf("license 已于 %s 过期", expires.Format("2006-01-02"))
		}
	}
	if !VerifySignature(lic.Email, lic.Signature) {
		return fmt.Errorf("license 签名无效")
	}
	return nil
}

// HasFeature checks if the license includes a specific feature
func HasFeature(lic *License, feature string) bool {
	if lic == nil {
		return false
	}
	for _, f := range lic.Features {
		if f == feature || f == "pro" || f == "*" {
			return true
		}
	}
	return false
}

// Sign creates an Ed25519 signature (server-side only)
func Sign(privKey ed25519.PrivateKey, email string) string {
	sig := ed25519.Sign(privKey, []byte(email))
	return hex.EncodeToString(sig)
}

// VerifySignature verifies an Ed25519 signature
func VerifySignature(email, sigHex string) bool {
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(publicKey(), []byte(email), sig)
}

// IsPro returns true if a valid Pro license is loaded
func IsPro() bool {
	lic, err := Load()
	if err != nil {
		return false
	}
	return Validate(lic) == nil
}
