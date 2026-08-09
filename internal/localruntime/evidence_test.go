package localruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"monicheck/internal/analyzer"
	"monicheck/internal/execution"
	"monicheck/internal/logger"
	"monicheck/internal/model"
	"monicheck/internal/report"
	"monicheck/internal/storage"
	"monicheck/pkg/evidence"
)

func TestEvidenceBundleOmitsResourceNamesAndRawEvidence(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	now := time.Now().UTC()
	resource := model.Resource{ID: "https://prometheus.internal/secret-metric", UID: "secret-metric", Type: model.ResourceTypeMetric, Name: "customer_secret_metric", Source: model.SourceInfo{System: "prometheus", Instance: "https://prometheus.internal"}, Status: model.ResourceStatusActive, CreatedAt: now, UpdatedAt: now}
	if err := store.Resources.Upsert(ctx, resource); err != nil {
		t.Fatal(err)
	}
	finding := model.Finding{ID: "finding-secret", Type: "UnusedMetric", Category: model.FindingCategoryCost, Severity: model.SeverityWarning, Status: model.FindingStatusOpen, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{"query at https://prometheus.internal contains customer_secret_metric"}, Recommendation: "private recommendation", CreatedAt: now, UpdatedAt: now}
	if err := store.Findings.ReplaceOpenByAnalyzer(ctx, "builtin.unused_metric", []model.Finding{finding}); err != nil {
		t.Fatal(err)
	}
	executionResult := model.ExecutionResult{ID: "execution-secret", Status: model.ExecutionStatusSucceeded, AnalyzerIDs: []string{"builtin.unused_metric"}, FindingCount: 1, StartedAt: now.Add(-time.Second), FinishedAt: now}
	if _, err := report.SaveLocalPostureSnapshot(ctx, store, executionResult); err != nil {
		t.Fatal(err)
	}
	engine := execution.NewEngine(store, nil, analyzer.NewRegistry(), logger.New(&bytes.Buffer{}, "quiet"))
	runtime := &Runtime{Store: store, Engine: engine, Execution: executionResult}
	bundle, err := runtime.EvidenceBundle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.ContractVersion != evidence.ContractVersion || len(bundle.Findings) != 1 {
		t.Fatalf("unexpected bundle: %#v", bundle)
	}
	body, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"prometheus.internal", "customer_secret_metric", "private recommendation", "query at"} {
		if bytes.Contains(body, []byte(secret)) {
			t.Fatalf("evidence bundle leaked %q: %s", secret, body)
		}
	}
}
