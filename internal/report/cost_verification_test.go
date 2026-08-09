package report

import (
	"context"
	"strings"
	"testing"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestBuildCostVerificationSummarySeparatesVerifiedPendingAndNoReduction(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	now := time.Now().UTC()
	resources := []model.Resource{
		{ID: "verified", Type: model.ResourceTypeMetric, Name: "verified", Status: model.ResourceStatusActive, Metadata: map[string]string{model.MetadataSeriesCount: "400000", model.MetadataSeriesCountSource: "tsdb_head"}},
		{ID: "pending", Type: model.ResourceTypeMetric, Name: "pending", Status: model.ResourceStatusActive, Metadata: map[string]string{model.MetadataSeriesCount: "500000", model.MetadataSeriesCountSource: "tsdb_head"}},
		{ID: "unchanged", Type: model.ResourceTypeMetric, Name: "unchanged", Status: model.ResourceStatusActive, Metadata: map[string]string{model.MetadataSeriesCount: "600000", model.MetadataSeriesCountSource: "tsdb_head"}},
	}
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatal(err)
		}
	}
	findings := []model.Finding{
		{ID: "f-verified", Type: "UnusedMetric", Resource: model.ResourceRef{ID: "verified", Type: model.ResourceTypeMetric, Name: "verified"}, Status: model.FindingStatusResolved, Metadata: map[string]string{"analyzer_id": "a"}},
		{ID: "f-pending", Type: "UnusedMetric", Resource: model.ResourceRef{ID: "pending", Type: model.ResourceTypeMetric, Name: "pending"}, Status: model.FindingStatusOpen, Metadata: map[string]string{"analyzer_id": "b"}},
		{ID: "f-unchanged", Type: "HighCardinalityMetric", Resource: model.ResourceRef{ID: "unchanged", Type: model.ResourceTypeMetric, Name: "unchanged"}, Status: model.FindingStatusOpen, Metadata: map[string]string{"analyzer_id": "c"}},
	}
	for _, finding := range findings {
		if err := store.Findings.ReplaceOpenByAnalyzer(ctx, finding.Metadata["analyzer_id"], []model.Finding{finding}); err != nil {
			t.Fatal(err)
		}
	}
	baselines := []model.FindingWorkflowEvent{
		{ID: "b1", FindingID: "f-verified", Action: CostBaselineCapturedAction, CreatedAt: now.Add(-time.Hour), Metadata: map[string]string{"baseline_series": "1000000", "measurement_source": "tsdb_head", "opportunity_type": "REMOVE_UNUSED_METRIC"}},
		{ID: "b2", FindingID: "f-pending", Action: CostBaselineCapturedAction, CreatedAt: now.Add(time.Hour), Metadata: map[string]string{"baseline_series": "500000", "measurement_source": "tsdb_head", "opportunity_type": "REMOVE_UNUSED_METRIC"}},
		{ID: "b3", FindingID: "f-unchanged", Action: CostBaselineCapturedAction, CreatedAt: now.Add(-time.Hour), Metadata: map[string]string{"baseline_series": "500000", "measurement_source": "tsdb_head", "opportunity_type": "REDUCE_HIGH_CARDINALITY"}},
	}
	for _, event := range baselines {
		if err := store.FindingWorkflow.Save(ctx, event); err != nil {
			t.Fatal(err)
		}
	}

	summary, err := BuildCostVerificationSummary(ctx, store, storage.ResourceFilter{}, CostPricing{Currency: "USD", MonthlyPerMillionActiveSeries: 100})
	if err != nil {
		t.Fatal(err)
	}
	if summary.BaselineCount != 3 || summary.VerifiedCount != 1 || summary.PendingCount != 1 || summary.NoReductionCount != 1 {
		t.Fatalf("unexpected verification states: %#v", summary)
	}
	if summary.VerifiedSeriesReduction != 600000 || summary.VerifiedMonthlySavings == nil || *summary.VerifiedMonthlySavings != 60 {
		t.Fatalf("unexpected verified savings: %#v", summary)
	}
	if summary.Items[0].State != CostVerificationVerified || summary.Items[0].FindingID != "f-verified" {
		t.Fatalf("expected verified saving first: %#v", summary.Items)
	}
}

func TestBuildCostVerificationSummaryVerifiesCompleteSnapshotTombstoneAfterFindingRemoval(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	now := time.Now().UTC()
	resource := model.Resource{
		ID:     "removed",
		Type:   model.ResourceTypeMetric,
		Name:   "removed_metric",
		Status: model.ResourceStatusOrphan,
		Metadata: map[string]string{
			model.MetadataSeriesCount:                       "250000",
			model.MetadataSeriesCountSource:                 "tsdb_head",
			model.MetadataConnectorID:                       "prometheus",
			model.MetadataConnectorOrphanedAt:               now.Format(time.RFC3339Nano),
			model.MetadataConnectorOrphanedSnapshotID:       "snapshot-complete",
			model.MetadataConnectorOrphanedSnapshotComplete: "true",
		},
	}
	if err := store.Resources.Upsert(ctx, resource); err != nil {
		t.Fatal(err)
	}
	baseline := model.FindingWorkflowEvent{
		ID:        "baseline",
		FindingID: "finding-removed",
		Action:    CostBaselineCapturedAction,
		CreatedAt: now.Add(-time.Hour),
		Metadata: map[string]string{
			"baseline_series":    "250000",
			"measurement_source": "tsdb_head",
			"connector_id":       "prometheus",
			"opportunity_type":   "REMOVE_UNUSED_METRIC",
			"finding_type":       "UnusedMetric",
			"resource_id":        "removed",
			"resource_type":      string(model.ResourceTypeMetric),
			"resource_name":      "removed_metric",
		},
	}
	if err := store.FindingWorkflow.Save(ctx, baseline); err != nil {
		t.Fatal(err)
	}

	summary, err := BuildCostVerificationSummary(ctx, store, storage.ResourceFilter{}, CostPricing{
		Currency:                      "USD",
		MonthlyPerMillionActiveSeries: 200,
	})
	if err != nil {
		t.Fatal(err)
	}
	if summary.BaselineCount != 1 || summary.VerifiedCount != 1 || len(summary.Items) != 1 {
		t.Fatalf("expected self-contained baseline to survive finding removal, got %#v", summary)
	}
	item := summary.Items[0]
	if item.State != CostVerificationVerified ||
		item.VerificationMethod != CostVerificationMethodTombstone ||
		item.EvidenceSnapshotID != "snapshot-complete" ||
		item.CurrentSeries != 0 ||
		item.VerifiedSeriesReduction != 250000 ||
		item.VerifiedMonthlySavings == nil ||
		*item.VerifiedMonthlySavings != 50 {
		t.Fatalf("unexpected tombstone verification %#v", item)
	}
	export, err := BuildExportWithFilterAndCostPricing(ctx, store, "cost", "csv", storage.ResourceFilter{}, CostPricing{
		Currency:                      "USD",
		MonthlyPerMillionActiveSeries: 200,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"cost_verification,finding-removed.verification_method,COMPLETE_SNAPSHOT_TOMBSTONE",
		"cost_verification,finding-removed.connector_id,prometheus",
		"cost_verification,finding-removed.evidence_snapshot_id,snapshot-complete",
		"cost_verification,finding-removed.verified_series_reduction,250000",
	} {
		if !strings.Contains(export.Content, expected) {
			t.Fatalf("expected CSV evidence %q in:\n%s", expected, export.Content)
		}
	}
}

func TestBuildCostVerificationSummaryRejectsUntrustedOrMismatchedTombstone(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	now := time.Now().UTC()
	for _, resource := range []model.Resource{
		{
			ID:     "partial",
			Type:   model.ResourceTypeMetric,
			Name:   "partial",
			Status: model.ResourceStatusOrphan,
			Metadata: map[string]string{
				model.MetadataConnectorID:                 "prometheus",
				model.MetadataConnectorOrphanedAt:         now.Format(time.RFC3339Nano),
				model.MetadataConnectorOrphanedSnapshotID: "partial-snapshot",
			},
		},
		{
			ID:     "mismatch",
			Type:   model.ResourceTypeMetric,
			Name:   "mismatch",
			Status: model.ResourceStatusOrphan,
			Metadata: map[string]string{
				model.MetadataConnectorID:                       "grafana",
				model.MetadataConnectorOrphanedAt:               now.Format(time.RFC3339Nano),
				model.MetadataConnectorOrphanedSnapshotID:       "complete-snapshot",
				model.MetadataConnectorOrphanedSnapshotComplete: "true",
			},
		},
	} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatal(err)
		}
		baseline := model.FindingWorkflowEvent{
			ID:        "baseline-" + resource.ID,
			FindingID: "finding-" + resource.ID,
			Action:    CostBaselineCapturedAction,
			CreatedAt: now.Add(-time.Hour),
			Metadata: map[string]string{
				"baseline_series":    "100",
				"measurement_source": "tsdb_head",
				"connector_id":       "prometheus",
				"opportunity_type":   "REMOVE_UNUSED_METRIC",
				"finding_type":       "UnusedMetric",
				"resource_id":        resource.ID,
				"resource_type":      string(model.ResourceTypeMetric),
				"resource_name":      resource.Name,
			},
		}
		if err := store.FindingWorkflow.Save(ctx, baseline); err != nil {
			t.Fatal(err)
		}
	}

	summary, err := BuildCostVerificationSummary(ctx, store, storage.ResourceFilter{}, CostPricing{})
	if err != nil {
		t.Fatal(err)
	}
	if summary.BaselineCount != 2 || summary.UnverifiableCount != 2 || summary.VerifiedCount != 0 {
		t.Fatalf("untrusted tombstones must remain unverifiable, got %#v", summary)
	}
}
