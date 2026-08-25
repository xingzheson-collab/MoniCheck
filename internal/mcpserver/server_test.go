package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/report"
	"monicheck/internal/storage"
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
	if !strings.Contains(lines[0], `"protocolVersion":"2025-06-18"`) {
		t.Fatalf("unexpected MCP responses: %s", output.String())
	}
	for _, tool := range []string{"monicheck.audit.run", "monicheck.report.export", "monicheck.findings.query", "monicheck.coverage.by_service", "monicheck.entity.get", "monicheck.baseline.diff"} {
		if !strings.Contains(lines[1], tool) {
			t.Fatalf("MCP tool list missing %q: %s", tool, lines[1])
		}
	}
	if !strings.Contains(lines[1], `"purpose"`) || !strings.Contains(lines[1], `"maximum":50`) {
		t.Fatalf("need-to-know query bounds missing: %s", lines[1])
	}
	var listed struct {
		Result struct {
			Tools []toolDefinition `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[1]), &listed); err != nil {
		t.Fatalf("decode tools/list response: %v", err)
	}
	for _, tool := range listed.Result.Tools {
		if tool.Name != "monicheck.findings.query" {
			continue
		}
		properties, ok := tool.InputSchema["properties"].(map[string]any)
		if !ok || properties["purpose"] == nil || properties["service"] == nil || properties["properties"] != nil {
			t.Fatalf("findings query schema is malformed: %#v", tool.InputSchema)
		}
	}
	for _, forbidden := range []string{"api_key", "bearer_token", "password", "prometheus_url", "grafana_url", "alertmanager_url"} {
		if strings.Contains(strings.ToLower(lines[1]), forbidden) {
			t.Fatalf("tool schema accepts a credential field %q: %s", forbidden, lines[1])
		}
	}
}

func TestFindingsQueryToolReturnsScopedIdentifiersAndAuditRef(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := storage.NewFileStore(path)
	if err != nil {
		t.Fatalf("new file store: %v", err)
	}
	resource := model.Resource{
		ID: "target-redis", UID: "redis", Type: model.ResourceTypeTarget, Name: "redis-exporter",
		Source: model.SourceInfo{System: "prometheus"}, Status: model.ResourceStatusActive,
	}
	if err := store.Resources.Upsert(ctx, resource); err != nil {
		t.Fatalf("save resource: %v", err)
	}
	if err := store.Findings.ReplaceOpenByAnalyzer(ctx, "test", []model.Finding{{
		ID: "finding-redis", Type: "BrokenTarget", Severity: model.SeverityCritical,
		Resource:       model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
		Recommendation: "Check the exporter.", Metadata: map[string]string{"analyzer_id": "test"},
	}}); err != nil {
		t.Fatalf("save finding: %v", err)
	}
	request := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"monicheck.findings.query","arguments":{"storage_path":` + mustJSON(path) + `,"entity":"redis-exporter","purpose":"Answer the user's Redis health question"}}}` + "\n"
	var output bytes.Buffer
	if err := (Server{Input: strings.NewReader(request), Output: &output}).Run(ctx); err != nil {
		t.Fatalf("run MCP server: %v", err)
	}
	if !strings.Contains(output.String(), `"isError":false`) || !strings.Contains(output.String(), `"resource":{"id":"target-redis"`) || !strings.Contains(output.String(), `"audit_event_ref"`) {
		t.Fatalf("unexpected query response: %s", output.String())
	}
	for _, forbidden := range []string{"raw evidence should", "https://", "prometheus.internal"} {
		if strings.Contains(output.String(), forbidden) {
			t.Fatalf("query response leaked %q: %s", forbidden, output.String())
		}
	}
}

func TestReportExportToolWritesPrivateFileWithoutReturningContent(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	outputPath := filepath.Join(dir, "exports", "report.json")
	store, err := storage.NewFileStore(statePath)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	content := `{"contract_version":"governance-report.v1","private_marker":"must-not-return"}`
	if err := store.ReportExports.Save(ctx, model.ReportExport{
		ID: "report", Type: "governance", Format: "json", Origin: report.LocalPostureSnapshotOrigin,
		ContentType: "application/json", Content: content, CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Executions.Save(ctx, model.ExecutionResult{ID: "run", Status: model.ExecutionStatusSucceeded, FinishedAt: now}); err != nil {
		t.Fatal(err)
	}
	request := `{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"monicheck.report.export","arguments":{"storage_path":` + mustJSON(statePath) + `,"output_path":` + mustJSON(outputPath) + `}}}` + "\n"
	var output bytes.Buffer
	if err := (Server{Input: strings.NewReader(request), Output: &output}).Run(ctx); err != nil {
		t.Fatalf("run MCP server: %v", err)
	}
	if !strings.Contains(output.String(), `"isError":false`) || !strings.Contains(output.String(), `"content_returned":false`) {
		t.Fatalf("unexpected export receipt: %s", output.String())
	}
	if strings.Contains(output.String(), "must-not-return") {
		t.Fatalf("export response returned private report content: %s", output.String())
	}
	body, err := os.ReadFile(outputPath)
	if err != nil || string(body) != content {
		t.Fatalf("unexpected exported report: body=%q err=%v", body, err)
	}
	info, err := os.Stat(outputPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("report permissions are not private: info=%v err=%v", info, err)
	}
}

func mustJSON(value string) string {
	body, _ := json.Marshal(value)
	return string(body)
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
