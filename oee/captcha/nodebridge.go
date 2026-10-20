package captcha

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
)

// NodeBridge — Node.js subprocess এ captcha encrypt করে (১০০% accurate)
type NodeBridge struct {
	NodeBin  string // default "node"
	BridgeJS string // captcha-bridge.js-এর path
	DeobfJS  string // latest-phone.deobf.js-এর path
}

type bridgeConfig struct {
	Secret  string `json:"secret"`
	StartAt int    `json:"startAt"`
	Length  int    `json:"length"`
	Version int    `json:"version"`
}

func (b *NodeBridge) node() string {
	if b.NodeBin == "" {
		return "node"
	}
	return b.NodeBin
}

// Config — Node bridge থেকে আসল config পড়ি
func (b *NodeBridge) Config() (*Config, error) {
	cmd := exec.Command(b.node(), b.BridgeJS, b.DeobfJS, "config")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("bridge config: %w: %s", err, stderr.String())
	}
	var c bridgeConfig
	if err := json.Unmarshal(stdout.Bytes(), &c); err != nil {
		return nil, fmt.Errorf("parse bridge config: %w (raw=%q)", err, stdout.String())
	}
	return &Config{Secret: c.Secret, StartAt: c.StartAt, Length: c.Length, Version: c.Version}, nil
}

// Encrypt — raw → encrypted (Node bridge ব্যবহার করে)
func (b *NodeBridge) Encrypt(rawToken string, cfg *Config) (string, error) {
	secretHex := hex.EncodeToString([]byte(cfg.Secret))
	cmd := exec.Command(b.node(),
		b.BridgeJS, b.DeobfJS, "encrypt",
		fmt.Sprint(cfg.StartAt),
		fmt.Sprint(cfg.Length),
		fmt.Sprint(cfg.Version),
		secretHex,
		rawToken,
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("bridge encrypt: %w: %s", err, stderr.String())
	}
	return stdout.String(), nil
}

// Decrypt
func (b *NodeBridge) Decrypt(encToken string, cfg *Config) (string, error) {
	secretHex := hex.EncodeToString([]byte(cfg.Secret))
	cmd := exec.Command(b.node(),
		b.BridgeJS, b.DeobfJS, "decrypt",
		fmt.Sprint(cfg.StartAt),
		fmt.Sprint(cfg.Length),
		fmt.Sprint(cfg.Version),
		secretHex,
		encToken,
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("bridge decrypt: %w: %s", err, stderr.String())
	}
	return stdout.String(), nil
}

// NewNodeBridge — default paths
func NewNodeBridge(cwd string) *NodeBridge {
	return &NodeBridge{
		NodeBin:  "node",
		BridgeJS: filepath.Join(cwd, "tools", "captcha-bridge.js"),
		DeobfJS:  filepath.Join(cwd, "latest-phone.deobf.js"),
	}
}
