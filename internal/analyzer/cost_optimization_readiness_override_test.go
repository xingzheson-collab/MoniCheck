package analyzer

import (
	"context"
	"strings"
	"testing"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/report"
	"monicheck/internal/storage"
)

func TestCostOptimizationReadinessOverrideAnalyzerReportsActiveOverride(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	now := time.Now().UTC()
	if err := store.Resources.Upsert(ctx, model.Resource{
		ID: "metric", Type: model.ResourceTypeMetric, Name: "requests", Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataConnectorID:       "prometheus.current",
			model.MetadataSeriesCount:       "1000",
			model.MetadataSeriesCountSource: "tsdb_head",
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.FindingWorkflow.Save(ctx, model.FindingWorkflowEvent{
		ID: "baseline", FindingID: "source-finding", Action: report.CostBaselineCapturedAction, CreatedAt: now.Add(-time.Hour),
		Metadata: map[string]string{
			"baseline_series": "1000", "measurement_source": "tsdb_head", "connector_id": "prometheus.previous",
			"opportunity_type": "REMOVE_UNUSED_METRIC", "finding_type": "UnusedMetric",
			"resource_id": "metric", "resource_type": string(model.ResourceTypeMetric), "resource_name": "requests",
			"readiness_override": "true", "readiness_state": report.CostReadinessIncompleteCoverage,
			"readiness_blocking_reasons": "rule_evidence_unavailable,arbitrary-private-value",
		},
	}); err != nil {
		t.Fatal(err)
	}
	findings, err := NewCostOptimizationReadinessOverrideAnalyzer().Execute(ctx, Context{
		Resources: store.Resources, Findings: store.Findings, FindingWorkflow: store.FindingWorkflow,
	})
	if err != nil || len(findings) != 1 {
		t.Fatalf("expected readiness override finding, findings=%#v err=%v", findings, err)
	}
	finding := findings[0]
	if finding.Type != "CostOptimizationReadinessOverride" ||
		finding.Metadata["source_finding_id"] != "source-finding" ||
		finding.Metadata["readiness_state_at_capture"] != report.CostReadinessIncompleteCoverage ||
		finding.Metadata["readiness_blocking_reasons"] != "rule_evidence_unavailable" ||
		strings.Contains(finding.Evidence[0], "arbitrary-private-value") {
		t.Fatalf("unexpected override finding %#v", finding)
	}
}

func TestCostOptimizationReadinessOverrideAnalyzerSkipsTerminalVerification(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	now := time.Now().UTC()
	if err := store.Resources.Upsert(ctx, model.Resource{
		ID: "metric", Type: model.ResourceTypeMetric, Name: "requests", Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataSeriesCount:       "50",
			model.MetadataSeriesCountSource: "tsdb_head",
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.FindingWorkflow.Save(ctx, model.FindingWorkflowEvent{
		ID: "baseline", FindingID: "source-finding", Action: report.CostBaselineCapturedAction, CreatedAt: now.Add(-time.Hour),
		Metadata: map[string]string{
			"baseline_series": "100", "measurement_source": "tsdb_head",
			"opportunity_type": "REMOVE_UNUSED_METRIC", "finding_type": "UnusedMetric",
			"resource_id": "metric", "resource_type": string(model.ResourceTypeMetric), "resource_name": "requests",
			"readiness_override": "true", "readiness_state": report.CostReadinessNeedsObservation,
			"readiness_blocking_reasons": "observation_window_incomplete",
		},
	}); err != nil {
		t.Fatal(err)
	}
	findings, err := NewCostOptimizationReadinessOverrideAnalyzer().Execute(ctx, Context{
		Resources: store.Resources, Findings: store.Findings, FindingWorkflow: store.FindingWorkflow,
	})
	if err != nil || len(findings) != 0 {
		t.Fatalf("expected terminal verified override to clear, findings=%#v err=%v", findings, err)
	}
}
