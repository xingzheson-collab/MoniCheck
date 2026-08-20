package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestServerNegotiatesAndListsReadOnlyTools(t *testing.T) {
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`,
	}, "\n") + "\n"
	var output bytes.Buffer
	if err := (Server{Input: strings.NewReader(input), Output: &output}).Run(context.Background()); err != nil {
		t.Fatalf("run MCP server: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected two responses, got %d: %s", len(lines), output.String())
	}
	if !strings.Contains(lines[0], `"protocolVersion":"2025-06-18"`) || !strings.Contains(lines[1], `monicheck.audit.run`) {
		t.Fatalf("unexpected MCP responses: %s", output.String())
	}
	for _, forbidden := range []string{"api_key", "bearer_token", "password", "prometheus_url", "grafana_url", "alertmanager_url"} {
		if strings.Contains(strings.ToLower(lines[1]), forbidden) {
			t.Fatalf("tool schema accepts a credential field %q: %s", forbidden, lines[1])
		}
	}
}

func TestConfigValidationToolRejectsSecretFieldsAndReturnsStructure(t *testing.T) {
	request := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"monicheck.config.validate","arguments":{"config_path":"x","api_key":"secret"}}}` + "\n"
	var output bytes.Buffer
	if err := (Server{Input: strings.NewReader(request), Output: &output}).Run(context.Background()); err != nil {
		t.Fatalf("run MCP server: %v", err)
	}
	var envelope struct {
		Result toolResult `json:"result"`
	}
	if err := json.Unmarshal(output.Bytes(), &envelope); err != nil {
		t.Fatalf("decode MCP response: %v", err)
	}
	if !envelope.Result.IsError || !strings.Contains(envelope.Result.Content[0].Text, "unknown field") {
		t.Fatalf("secret-shaped argument was not rejected: %s", output.String())
	}
}

func TestUnknownToolIsARecoverableToolError(t *testing.T) {
	request := `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"monicheck.mutate","arguments":{}}}` + "\n"
	var output bytes.Buffer
	if err := (Server{Input: strings.NewReader(request), Output: &output}).Run(context.Background()); err != nil {
		t.Fatalf("run MCP server: %v", err)
	}
	if !strings.Contains(output.String(), `"isError":true`) || !strings.Contains(output.String(), "unknown tool") {
		t.Fatalf("unexpected unknown-tool response: %s", output.String())
	}
}
