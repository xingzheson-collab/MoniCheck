package report

import (
	"context"
	"testing"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestBuildCostOutcomeSummaryPreservesRealizedReceiptWhenLiveMeasurementRegresses(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	now := time.Now().UTC()
	resource := model.Resource{
		ID: "metric", Type: model.ResourceTypeMetric, Name: "requests_total", Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "prometheus"}, UpdatedAt: now,
		Metadata: map[string]string{
			model.MetadataConnectorID: "prometheus.main", model.MetadataSeriesCount: "400",
			model.MetadataSeriesCountSource: "tsdb_head",
		},
	}
	if err := store.Resources.Upsert(ctx, resource); err != nil {
		t.Fatal(err)
	}
	if err := store.Findings.ReplaceOpenByAnalyzer(ctx, "test.cost", []model.Finding{{
		ID: "finding", Type: "UnusedMetric", Category: model.FindingCategoryCost, Severity: model.SeverityWarning,
		Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Status: model.FindingStatusOpen,
		Metadata: map[string]string{"analyzer_id": "test.cost"},
	}}); err != nil {
		t.Fatal(err)
	}
	approvalAt := now.Add(-2 * time.Hour)
	approval := model.FindingWorkflowEvent{
		ID: "commitment", FindingID: "finding", Action: CostOptimizationApprovedAction, Actor: "finops",
		Note: "remove unused series", CreatedAt: approvalAt,
		Metadata: map[string]string{
			"finding_type": "UnusedMetric", "resource_id": resource.ID, "resource_type": string(resource.Type), "resource_name": resource.Name,
			"opportunity_type": "REMOVE_UNUSED_METRIC", "owner": "platform", "due_at": now.Add(time.Hour).Format(time.RFC3339Nano),
			"baseline_series": "1000", "potential_series_reduction": "1000", "approved_series_reduction": "800",
			"measurement_source": "tsdb_head", "connector_id": "prometheus.main", "currency": "USD", "approved_monthly_savings": "0.08",
		},
	}
	if err := store.FindingWorkflow.Save(ctx, approval); err != nil {
		t.Fatal(err)
	}
	receipt := model.FindingWorkflowEvent{
		ID: "receipt", FindingID: "finding", Action: CostOutcomeRealizedAction, Actor: "finops", Note: "accepted",
		CreatedAt: now,
		Metadata: map[string]string{
			"commitment_id": approval.ID, "finding_type": "UnusedMetric", "resource_id": resource.ID,
			"resource_type": string(resource.Type), "resource_name": resource.Name, "opportunity_type": "REMOVE_UNUSED_METRIC",
			"owner": "platform", "approved_series_reduction": "800", "baseline_series": "1000", "current_series": "400",
			"realized_series_reduction": "600", "verification_method": CostVerificationMethodMeasurement,
			"measurement_source": "tsdb_head", "connector_id": "prometheus.main", "measurement_at": now.Format(time.RFC3339Nano),
			"currency": "USD", "realized_monthly_savings": "0.06",
		},
	}
	if err := store.FindingWorkflow.Save(ctx, receipt); err != nil {
		t.Fatal(err)
	}

	summary, err := BuildCostOutcomeSummaryAt(ctx, store, storage.ResourceFilter{}, CostPricing{
		Currency: "USD", MonthlyPerMillionActiveSeries: 100,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if summary.ApprovedCount != 1 || summary.RealizedCount != 1 ||
		summary.ApprovedSeriesReduction != 800 || summary.RealizedSeriesReduction != 600 ||
		summary.RealizedPercentOfApproved != 75 || len(summary.Items) != 1 ||
		summary.Items[0].State != CostOutcomeStateRealized {
		t.Fatalf("unexpected realized summary %#v", summary)
	}

	resource.Metadata[model.MetadataSeriesCount] = "1200"
	if err := store.Resources.Upsert(ctx, resource); err != nil {
		t.Fatal(err)
	}
	regressed, err := BuildCostOutcomeSummaryAt(ctx, store, storage.ResourceFilter{}, CostPricing{}, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if regressed.RealizedSeriesReduction != 600 || len(regressed.Receipts) != 1 ||
		regressed.Receipts[0].RealizedSeriesReduction != 600 || regressed.Items[0].State != CostOutcomeStateRealized {
		t.Fatalf("realized receipt regressed with live measurement: %#v", regressed)
	}
}

func TestBuildCostOutcomeSummaryExcludesCancelledCommitmentAndHonorsTenantFilter(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	now := time.Now().UTC()
	for _, team := range []string{"alpha", "beta"} {
		resource := model.Resource{
			ID: team, Type: model.ResourceTypeMetric, Name: team, Status: model.ResourceStatusActive,
			Labels:   map[string]string{"team": team},
			Metadata: map[string]string{model.MetadataSeriesCount: "100", model.MetadataSeriesCountSource: "tsdb_head"},
		}
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatal(err)
		}
		approval := model.FindingWorkflowEvent{
			ID: "commitment-" + team, FindingID: "finding-" + team, Action: CostOptimizationApprovedAction, CreatedAt: now,
			Metadata: map[string]string{
				"resource_id": team, "resource_type": string(model.ResourceTypeMetric), "resource_name": team,
				"finding_type": "UnusedMetric", "opportunity_type": "REMOVE_UNUSED_METRIC", "owner": team,
				"due_at": now.Add(time.Hour).Format(time.RFC3339Nano), "baseline_series": "100",
				"potential_series_reduction": "100", "approved_series_reduction": "100",
			},
		}
		if err := store.FindingWorkflow.Save(ctx, approval); err != nil {
			t.Fatal(err)
		}
		if team == "alpha" {
			if err := store.FindingWorkflow.Save(ctx, model.FindingWorkflowEvent{
				ID: "cancel-alpha", FindingID: approval.FindingID, Action: CostOptimizationCancelledAction, CreatedAt: now.Add(time.Minute),
				Metadata: map[string]string{"commitment_id": approval.ID, "resource_id": team},
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	summary, err := BuildCostOutcomeSummaryAt(ctx, store, storage.ResourceFilter{Team: "alpha"}, CostPricing{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if summary.ApprovedCount != 0 || len(summary.Items) != 0 {
		t.Fatalf("cancelled alpha commitment should not leak beta or remain active: %#v", summary)
	}
	beta, err := BuildCostOutcomeSummaryAt(ctx, store, storage.ResourceFilter{Team: "beta"}, CostPricing{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if beta.ApprovedCount != 1 || len(beta.Items) != 1 || beta.Items[0].Owner != "beta" {
		t.Fatalf("expected beta commitment only: %#v", beta)
	}
}
