package analyzer

import (
	"context"
	"testing"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/report"
	"monicheck/internal/storage"
)

func TestOverdueCostVerificationAnalyzerReportsOldPendingBaseline(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	now := time.Now().UTC()
	if err := store.Resources.Upsert(ctx, model.Resource{
		ID: "metric", Type: model.ResourceTypeMetric, Name: "requests", Status: model.ResourceStatusActive,
		UpdatedAt: now.Add(-3 * time.Hour),
		Metadata: map[string]string{
			model.MetadataConnectorID:       "prometheus.main",
			model.MetadataSeriesCount:       "1000",
			model.MetadataSeriesCountSource: "tsdb_head",
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.FindingWorkflow.Save(ctx, model.FindingWorkflowEvent{
		ID: "baseline", FindingID: "source-finding", Action: report.CostBaselineCapturedAction, CreatedAt: now.Add(-2 * time.Hour),
		Metadata: map[string]string{
			"baseline_series": "1000", "measurement_source": "tsdb_head", "connector_id": "prometheus.previous",
			"opportunity_type": "REMOVE_UNUSED_METRIC", "finding_type": "UnusedMetric",
			"resource_id": "metric", "resource_type": string(model.ResourceTypeMetric), "resource_name": "requests",
		},
	}); err != nil {
		t.Fatal(err)
	}
	findings, err := NewOverdueCostVerificationAnalyzer().Execute(ctx, Context{
		Resources: store.Resources, Findings: store.Findings, FindingWorkflow: store.FindingWorkflow,
		Config: map[string]any{"cost_verification_sla": time.Hour},
	})
	if err != nil || len(findings) != 1 {
		t.Fatalf("expected overdue verification finding, findings=%#v err=%v", findings, err)
	}
	finding := findings[0]
	if finding.Type != "OverdueCostVerification" ||
		finding.Metadata["source_finding_id"] != "source-finding" ||
		finding.Metadata["verification_state"] != report.CostVerificationUnverifiable ||
		finding.Metadata["connector_id"] != "prometheus.main" {
		t.Fatalf("unexpected finding %#v", finding)
	}
}

func TestOverdueCostVerificationAnalyzerSkipsYoungAndVerifiedBaselines(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	now := time.Now().UTC()
	for _, resource := range []model.Resource{
		{
			ID: "young", Type: model.ResourceTypeMetric, Name: "young", Status: model.ResourceStatusActive,
			UpdatedAt: now.Add(-time.Hour),
			Metadata:  map[string]string{model.MetadataSeriesCount: "100", model.MetadataSeriesCountSource: "tsdb_head"},
		},
		{
			ID: "verified", Type: model.ResourceTypeMetric, Name: "verified", Status: model.ResourceStatusActive,
			UpdatedAt: now,
			Metadata:  map[string]string{model.MetadataSeriesCount: "50", model.MetadataSeriesCountSource: "tsdb_head"},
		},
	} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatal(err)
		}
		baselineAt := now.Add(-2 * time.Hour)
		if resource.ID == "young" {
			baselineAt = now.Add(-30 * time.Minute)
		}
		if err := store.FindingWorkflow.Save(ctx, model.FindingWorkflowEvent{
			ID: "baseline-" + resource.ID, FindingID: "finding-" + resource.ID,
			Action: report.CostBaselineCapturedAction, CreatedAt: baselineAt,
			Metadata: map[string]string{
				"baseline_series": "100", "measurement_source": "tsdb_head", "opportunity_type": "REMOVE_UNUSED_METRIC",
				"finding_type": "UnusedMetric", "resource_id": resource.ID,
				"resource_type": string(model.ResourceTypeMetric), "resource_name": resource.Name,
			},
		}); err != nil {
			t.Fatal(err)
		}
	}
	findings, err := NewOverdueCostVerificationAnalyzer().Execute(ctx, Context{
		Resources: store.Resources, Findings: store.Findings, FindingWorkflow: store.FindingWorkflow,
		Config: map[string]any{"cost_verification_sla": time.Hour},
	})
	if err != nil || len(findings) != 0 {
		t.Fatalf("expected no overdue findings, findings=%#v err=%v", findings, err)
	}
}
