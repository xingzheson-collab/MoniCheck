package report

import (
	"context"
	"testing"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestBuildCostReadinessSummarySeparatesReadyObservationAndInventory(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	now := time.Now().UTC()
	for _, resource := range []model.Resource{
		readinessMetric("ready", now.Add(-8*24*time.Hour), true, "1000"),
		readinessMetric("young", now.Add(-time.Hour), true, "2000"),
		readinessMetric("inventory", now.Add(-8*24*time.Hour), false, "3000"),
		readinessConsumer("dashboard", model.ResourceTypeDashboard),
		readinessConsumer("rule", model.ResourceTypeAlertRule),
	} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatal(err)
		}
	}
	for _, finding := range []model.Finding{
		readinessFinding("finding-ready", "ready"),
		readinessFinding("finding-young", "young"),
		readinessFinding("finding-inventory", "inventory"),
	} {
		if err := store.Findings.ReplaceOpenByAnalyzer(ctx, finding.ID, []model.Finding{finding}); err != nil {
			t.Fatal(err)
		}
	}
	summary, err := BuildCostReadinessSummaryAt(ctx, store, storage.ResourceFilter{}, CostPricing{
		Currency: "USD", MonthlyPerMillionActiveSeries: 100,
	}, CostReadinessConfig{
		ObservationWindow:       7 * 24 * time.Hour,
		RequiredEvidenceDomains: []string{CostEvidenceDashboard, CostEvidenceRule},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if summary.OpportunityCount != 3 || summary.ReadyCount != 1 || summary.BlockedCount != 2 ||
		summary.IncompleteInventoryCount != 1 || summary.NeedsObservationCount != 1 ||
		summary.ReadyPotentialSeriesReduction != 1000 || summary.BlockedPotentialSeriesReduction != 5000 {
		t.Fatalf("unexpected readiness summary %#v", summary)
	}
	if summary.ReadyPotentialMonthlySavings == nil || *summary.ReadyPotentialMonthlySavings != 0.1 {
		t.Fatalf("unexpected ready monthly savings %#v", summary)
	}
	states := map[string]string{}
	for _, item := range summary.Items {
		states[item.Resource.ID] = item.ReadinessState
	}
	if states["ready"] != CostReadinessReady ||
		states["young"] != CostReadinessNeedsObservation ||
		states["inventory"] != CostReadinessIncompleteInventory {
		t.Fatalf("unexpected readiness states %#v", states)
	}
}

func TestBuildCostReadinessSummaryRequiresConfiguredEvidenceAndCountsConsumers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	now := time.Now().UTC()
	metric := readinessMetric("metric", now.Add(-8*24*time.Hour), true, "5000")
	panel := readinessConsumer("panel", model.ResourceTypePanel)
	for _, resource := range []model.Resource{metric, panel} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Relationships.Upsert(ctx, model.Relationship{
		ID: "uses", FromID: panel.ID, ToID: metric.ID, Type: model.RelationshipUses, CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	finding := model.Finding{
		ID: "finding", Type: "HighCardinalityMetric", Severity: model.SeverityWarning,
		Resource: model.ResourceRef{ID: metric.ID, Type: metric.Type, Name: metric.Name},
		Status:   model.FindingStatusOpen, Metadata: map[string]string{"analyzer_id": "high", "threshold": "1000"},
	}
	if err := store.Findings.ReplaceOpenByAnalyzer(ctx, "high", []model.Finding{finding}); err != nil {
		t.Fatal(err)
	}
	summary, err := BuildCostReadinessSummaryAt(ctx, store, storage.ResourceFilter{}, CostPricing{}, CostReadinessConfig{
		ObservationWindow:       0,
		RequiredEvidenceDomains: []string{CostEvidenceDashboard, CostEvidenceRule},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if summary.IncompleteCoverageCount != 1 || summary.ReadyCount != 0 ||
		len(summary.Items) != 1 || summary.Items[0].ConsumerCount != 1 ||
		summary.Items[0].ConsumersByType[string(model.ResourceTypePanel)] != 1 ||
		summary.EvidenceAvailability[CostEvidenceDashboard] != true ||
		summary.EvidenceAvailability[CostEvidenceRule] != false {
		t.Fatalf("unexpected evidence readiness %#v", summary)
	}

	summary, err = BuildCostReadinessSummaryAt(ctx, store, storage.ResourceFilter{}, CostPricing{}, CostReadinessConfig{
		ObservationWindow:       0,
		RequiredEvidenceDomains: []string{CostEvidenceDashboard},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if summary.ReadyCount != 1 || !summary.Items[0].Ready {
		t.Fatalf("expected configured dashboard evidence to be sufficient, got %#v", summary)
	}
}

func readinessMetric(id string, createdAt time.Time, complete bool, series string) model.Resource {
	metadata := map[string]string{
		model.MetadataSeriesCount:       series,
		model.MetadataSeriesCountSource: "tsdb_head",
	}
	if complete {
		metadata[model.MetadataConnectorSnapshotCompleteness] = "complete"
	}
	return model.Resource{
		ID: id, Type: model.ResourceTypeMetric, Name: id, Status: model.ResourceStatusActive,
		CreatedAt: createdAt, Metadata: metadata,
	}
}

func readinessConsumer(id string, resourceType model.ResourceType) model.Resource {
	return model.Resource{
		ID: id, Type: resourceType, Name: id, Status: model.ResourceStatusActive,
		Metadata: map[string]string{model.MetadataConnectorSnapshotCompleteness: "complete"},
	}
}

func readinessFinding(id string, resourceID string) model.Finding {
	return model.Finding{
		ID: id, Type: "UnusedMetric", Severity: model.SeverityWarning,
		Resource: model.ResourceRef{ID: resourceID, Type: model.ResourceTypeMetric, Name: resourceID},
		Status:   model.FindingStatusOpen, Metadata: map[string]string{"analyzer_id": id},
	}
}
