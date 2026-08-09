package risk

import (
	"reflect"
	"testing"

	"monicheck/internal/model"
)

func TestScoreIsTransparentAndDeterministic(t *testing.T) {
	finding := model.Finding{
		Severity: model.SeverityCritical,
		Category: model.FindingCategoryReliability,
		Resource: model.ResourceRef{ID: "target-1", Type: model.ResourceTypeTarget},
		Evidence: []string{"target is down"},
		Metadata: map[string]string{"analyzer_id": "builtin.broken_target"},
	}
	first := Score(finding)
	second := Score(finding)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("expected deterministic score: %#v %#v", first, second)
	}
	if first.Score != 97 || first.Level != "CRITICAL" || first.Confidence != 100 || first.ConfidenceLevel != "HIGH" {
		t.Fatalf("unexpected score %#v", first)
	}
	if len(first.Components) != 3 || len(first.ConfidenceComponents) != 3 {
		t.Fatalf("expected complete breakdown %#v", first)
	}
}

func TestWorkflowStateAndIdentityDoNotChangeRisk(t *testing.T) {
	base := model.Finding{
		Severity: model.SeverityWarning,
		Category: model.FindingCategoryCost,
		Resource: model.ResourceRef{ID: "metric-private-a", Type: model.ResourceTypeMetric, Name: "private-a"},
		Evidence: []string{"evidence-a"},
		Metadata: map[string]string{"analyzer_id": "analyzer-a"},
		Status:   model.FindingStatusOpen,
	}
	changed := base
	changed.ID = "finding-private-b"
	changed.Resource.ID = "metric-private-b"
	changed.Resource.Name = "private-b"
	changed.Evidence = []string{"evidence-b"}
	changed.Metadata = map[string]string{"analyzer_id": "analyzer-b", "waiver.id": "waiver-private"}
	changed.Status = model.FindingStatusWaived
	if !reflect.DeepEqual(Score(base), Score(changed)) {
		t.Fatalf("identity or workflow state changed risk score")
	}
}
