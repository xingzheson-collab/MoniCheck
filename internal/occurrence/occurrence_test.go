package occurrence

import (
	"testing"
	"time"

	"monicheck/internal/model"
)

func TestReconcileObserveResolveAndReopen(t *testing.T) {
	firstAt := time.Unix(10, 0).UTC()
	secondAt := time.Unix(20, 0).UTC()
	thirdAt := time.Unix(30, 0).UTC()
	finding := model.Finding{
		ID: "finding-1", Type: "BrokenTarget", Severity: model.SeverityCritical,
		Category: model.FindingCategoryReliability,
		Resource: model.ResourceRef{Type: model.ResourceTypeTarget},
		Metadata: map[string]string{"analyzer_id": "builtin.broken_target"},
	}
	records := Reconcile("builtin.broken_target", nil, []model.Finding{finding}, firstAt)
	records = Reconcile("builtin.broken_target", records, nil, secondAt)
	if len(records) != 1 || records[0].Active || records[0].ResolvedAt == nil || !records[0].ResolvedAt.Equal(secondAt) {
		t.Fatalf("expected resolved occurrence, got %#v", records)
	}
	records = Reconcile("builtin.broken_target", records, []model.Finding{finding}, thirdAt)
	got := records[0]
	if !got.Active || got.ObservationCount != 2 || got.ReopenCount != 1 || !got.FirstSeenAt.Equal(firstAt) || !got.LastSeenAt.Equal(thirdAt) {
		t.Fatalf("unexpected reopened occurrence %#v", got)
	}
}

func TestGroupKeyExcludesResourceIdentity(t *testing.T) {
	left := model.Finding{Type: "UnusedMetric", Severity: model.SeverityWarning, Category: model.FindingCategoryCost, Resource: model.ResourceRef{ID: "private-a", Name: "a", Type: model.ResourceTypeMetric}, Metadata: map[string]string{"analyzer_id": "unused"}}
	right := left
	right.Resource.ID = "private-b"
	right.Resource.Name = "b"
	if GroupKey(left) != GroupKey(right) {
		t.Fatal("resource identity changed group key")
	}
}
