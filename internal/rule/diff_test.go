package rule

import (
	"testing"

	"monicheck/internal/model"
)

func TestDiff(t *testing.T) {
	before := []Rule{
		{ID: "same", Scope: []model.ResourceType{model.ResourceTypeMetric}, Condition: Condition{Expression: `type == "Metric"`}},
		{ID: "changed", Version: "0.1.0", Condition: Condition{Expression: `used_by == 0`}},
		{ID: "removed", Condition: Condition{Expression: `type == "Dashboard"`}},
	}
	after := []Rule{
		{ID: "same", Scope: []model.ResourceType{model.ResourceTypeMetric}, Condition: Condition{Expression: `type == "Metric"`}},
		{ID: "changed", Version: "0.2.0", Condition: Condition{Expression: `used_by == 0`}},
		{ID: "added", Condition: Condition{Expression: `cardinality > 1000`}},
	}

	diff := Diff(before, after)
	if !diff.Changed {
		t.Fatalf("expected diff to report changes")
	}
	if diff.Summary[DiffUnchanged] != 1 || diff.Summary[DiffChanged] != 1 || diff.Summary[DiffRemoved] != 1 || diff.Summary[DiffAdded] != 1 {
		t.Fatalf("unexpected summary %#v", diff.Summary)
	}
	if len(diff.Items) != 4 {
		t.Fatalf("expected 4 diff items, got %d", len(diff.Items))
	}
}
