package analyzer

import (
	"context"
	"testing"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/report"
	"monicheck/internal/storage"
)

func TestOverdueCostCommitmentAnalyzerReportsActivePastDueCommitment(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	now := time.Now().UTC()
	if err := store.Resources.Upsert(ctx, model.Resource{
		ID: "metric", Type: model.ResourceTypeMetric, Name: "requests", Status: model.ResourceStatusActive,
		Metadata: map[string]string{model.MetadataSeriesCount: "100", model.MetadataSeriesCountSource: "tsdb_head"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.FindingWorkflow.Save(ctx, model.FindingWorkflowEvent{
		ID: "commitment", FindingID: "finding", Action: report.CostOptimizationApprovedAction, CreatedAt: now.Add(-2 * time.Hour),
		Metadata: map[string]string{
			"finding_type": "UnusedMetric", "resource_id": "metric", "resource_type": string(model.ResourceTypeMetric), "resource_name": "requests",
			"opportunity_type": "REMOVE_UNUSED_METRIC", "owner": "platform", "due_at": now.Add(-time.Hour).Format(time.RFC3339Nano),
			"baseline_series": "100", "potential_series_reduction": "100", "approved_series_reduction": "80",
		},
	}); err != nil {
		t.Fatal(err)
	}
	findings, err := NewOverdueCostCommitmentAnalyzer().Execute(ctx, Context{
		Resources: store.Resources, Findings: store.Findings, FindingWorkflow: store.FindingWorkflow,
	})
	if err != nil || len(findings) != 1 {
		t.Fatalf("expected one overdue commitment finding, findings=%#v err=%v", findings, err)
	}
	if findings[0].Type != "OverdueCostCommitment" || findings[0].Metadata["owner"] != "platform" {
		t.Fatalf("unexpected finding %#v", findings[0])
	}
}
