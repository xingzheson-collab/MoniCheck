package graph

import (
	"testing"

	"monicheck/internal/model"
)

func TestGraphConstructorsPreserveOrBoundDanglingRelationships(t *testing.T) {
	resources := []model.Resource{{ID: "rule", Type: model.ResourceTypeAlertRule}}
	relationships := []model.Relationship{{
		ID: "dangling", FromID: "rule", ToID: "missing-metric", Type: model.RelationshipUses,
	}}

	governance := New(resources, relationships)
	if len(governance.Outgoing("rule")) != 1 {
		t.Fatal("governance graph removed a dangling relationship")
	}
	bounded := NewBounded(resources, relationships)
	if len(bounded.Outgoing("rule")) != 0 || len(bounded.Relationships()) != 0 {
		t.Fatal("bounded graph retained a relationship outside its inventory")
	}
}
