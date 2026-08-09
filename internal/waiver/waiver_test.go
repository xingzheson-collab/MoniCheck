package waiver

import (
	"testing"
	"time"

	"monicheck/internal/model"
)

func TestApplySelectsMostSpecificActiveWaiver(t *testing.T) {
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	finding := model.Finding{
		ID:       "finding-1",
		Type:     "UnusedMetric",
		Resource: model.ResourceRef{ID: "metric-1"},
		Metadata: map[string]string{"analyzer_id": "builtin.unused_metric"},
		Status:   model.FindingStatusOpen,
	}
	waivers := []model.Waiver{
		{ID: "type", Scope: model.WaiverScopeFindingType, ScopeValue: "UnusedMetric", ExpiresAt: now.Add(time.Hour), CreatedAt: now},
		{ID: "resource", Scope: model.WaiverScopeResource, ScopeValue: "metric-1", ExpiresAt: now.Add(time.Hour), CreatedAt: now.Add(-time.Minute)},
		{ID: "finding", Scope: model.WaiverScopeFinding, ScopeValue: "finding-1", ExpiresAt: now.Add(time.Hour), CreatedAt: now.Add(-2 * time.Minute)},
	}
	result := ApplyToFinding(finding, waivers, now)
	if result.Status != model.FindingStatusWaived || result.Metadata[MetadataID] != "finding" {
		t.Fatalf("expected most-specific finding waiver, got %#v", result)
	}
}

func TestApplyReopensExpiredOrRevokedWaiver(t *testing.T) {
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	finding := model.Finding{
		ID:       "finding-1",
		Type:     "UnusedMetric",
		Metadata: map[string]string{MetadataID: "expired", MetadataScope: string(model.WaiverScopeFinding)},
		Status:   model.FindingStatusWaived,
	}
	result := ApplyToFinding(finding, []model.Waiver{{
		ID: "expired", Scope: model.WaiverScopeFinding, ScopeValue: finding.ID, ExpiresAt: now,
	}}, now)
	if result.Status != model.FindingStatusOpen || result.Metadata[MetadataID] != "" {
		t.Fatalf("expected expired waiver to reopen finding, got %#v", result)
	}
}

func TestApplyDoesNotOverrideWorkflowStatus(t *testing.T) {
	now := time.Now().UTC()
	finding := model.Finding{ID: "finding-1", Status: model.FindingStatusAcked, Metadata: map[string]string{}}
	result := ApplyToFinding(finding, []model.Waiver{{
		ID: "waiver", Scope: model.WaiverScopeFinding, ScopeValue: finding.ID, ExpiresAt: now.Add(time.Hour),
	}}, now)
	if result.Status != model.FindingStatusAcked {
		t.Fatalf("waiver should not override workflow state, got %s", result.Status)
	}
}

func TestApplyDoesNotMutateInputMetadata(t *testing.T) {
	now := time.Now().UTC()
	finding := model.Finding{
		ID: "finding-1", Status: model.FindingStatusWaived,
		Metadata: map[string]string{MetadataID: "expired", MetadataScope: string(model.WaiverScopeFinding)},
	}
	_ = ApplyToFinding(finding, nil, now)
	if finding.Metadata[MetadataID] != "expired" {
		t.Fatalf("ApplyToFinding mutated its input metadata: %#v", finding.Metadata)
	}
}
