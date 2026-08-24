package localui

import (
	"context"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"monicheck/internal/localruntime"
	"monicheck/internal/model"
	"monicheck/internal/report"
	"monicheck/internal/storage"
)

func TestActivationReceiptEndpointIsDownloadOnlyAndNoStore(t *testing.T) {
	store := storage.NewMemoryStore()
	createdAt := time.Date(2026, 8, 14, 10, 0, 0, 0, time.UTC)
	if err := store.ReportExports.Save(context.Background(), model.ReportExport{
		ID: "report", Type: "governance", Format: "json", Origin: report.LocalPostureSnapshotOrigin,
		ContentType: "application/json", Content: `{"resource_count":10,"finding_count":4}`, CreatedAt: createdAt,
	}); err != nil {
		t.Fatal(err)
	}
	runtime := &localruntime.Runtime{Store: store}
	server := New("127.0.0.1:0", runtime)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/local/activation-receipt", nil)
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" || recorder.Header().Get("Content-Disposition") != `attachment; filename="monicheck-activation-receipt.json"` {
		t.Fatalf("unexpected response: status=%d headers=%v body=%s", recorder.Code, recorder.Header(), recorder.Body.String())
	}
	var receipt map[string]any
	if err := json.NewDecoder(recorder.Body).Decode(&receipt); err != nil {
		t.Fatal(err)
	}
	if receipt["contract_version"] != "activation-receipt.v1" || receipt["sharing_mode"] != "MANUAL_ONLY" {
		t.Fatalf("unexpected receipt contract: %#v", receipt)
	}
}

func TestLocalUIExposesExplicitActivationActionsWithoutReportData(t *testing.T) {
	body, err := fs.ReadFile(staticFiles, "static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(body)
	for _, required := range []string{
		`href="/api/v1/local/activation-receipt"`,
		`issues/new?template=activation-feedback.yml`,
		`https://moni-check-web.vercel.app/?intent=managed-pilot#contact`,
		`Nothing is uploaded automatically.`,
	} {
		if !strings.Contains(html, required) {
			t.Fatalf("Local UI is missing activation contract %q", required)
		}
	}
	for _, forbidden := range []string{"receipt=", "endpoint=", "resource=", "finding="} {
		if strings.Contains(html, forbidden) {
			t.Fatalf("Local UI leaked report data through activation URL %q", forbidden)
		}
	}
}

func TestLocalUILeadsWithEvidenceCompletenessWhenCoverageIsPartial(t *testing.T) {
	body, err := fs.ReadFile(staticFiles, "static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	script := string(body)
	for _, required := range []string{
		"Evidence completeness",
		"Evaluable coverage:",
		"UNKNOWN signals are excluded from the denominator",
		"coverage_evidence_state",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("Local UI is missing partial-evidence boundary %q", required)
		}
	}
}

func TestLocalUIExposesPersistedAgentAuditEntry(t *testing.T) {
	body, err := fs.ReadFile(staticFiles, "static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	script, err := fs.ReadFile(staticFiles, "static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"data-view=\"agent\"", "Agent audit"} {
		if !strings.Contains(string(body), required) {
			t.Fatalf("Local UI is missing Agent audit navigation %q", required)
		}
	}
	for _, required := range []string{"PERSISTED_AGENT_AUDIT", "does not contact providers or rerun analyzers", "Monitoring failures appear before hygiene advice", "MONITORING FAILURE", "searchParams.set('view'", "action_groups", "inventory_visibility", "coverage?.assessments", "Copy exception YAML", "UNKNOWN signals are excluded from the denominator", "missing.slice(0, 10)", "unknown.slice(0, 10)", "Live connector status is unavailable in serve-only mode"} {
		if !strings.Contains(string(script), required) {
			t.Fatalf("Local UI is missing persisted Agent behavior %q", required)
		}
	}
}

func TestAgentAuditEndpointIsReadOnlyAndNoStore(t *testing.T) {
	store := storage.NewMemoryStore()
	createdAt := time.Date(2026, 8, 23, 10, 0, 0, 0, time.UTC)
	if err := store.ReportExports.Save(context.Background(), model.ReportExport{
		ID: "report", Type: "governance", Format: "json", Origin: report.LocalPostureSnapshotOrigin,
		ContentType: "application/json", Content: `{"resource_count":0,"finding_count":0}`, CreatedAt: createdAt,
	}); err != nil {
		t.Fatal(err)
	}
	runtime := &localruntime.Runtime{Store: store, Execution: model.ExecutionResult{
		ID: "execution", Status: model.ExecutionStatusSucceeded, StartedAt: createdAt.Add(-time.Second), FinishedAt: createdAt,
	}}
	server := New("127.0.0.1:0", runtime)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/local/agent-audit", nil))
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unexpected response: status=%d headers=%v body=%s", recorder.Code, recorder.Header(), recorder.Body.String())
	}
	var payload map[string]any
	if err := json.NewDecoder(recorder.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload["contract_version"] != "agent-audit.v1" {
		t.Fatalf("unexpected contract: %#v", payload)
	}
}
