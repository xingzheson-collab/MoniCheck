package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestInhibitionRuleAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resources := []model.Resource{
		inhibitionRuleResource("healthy", "alertmanager", "1", "1", "2", "0", "0", model.ResourceStatusActive),
		inhibitionRuleResource("empty-target", "alertmanager", "1", "0", "1", "0", "0", model.ResourceStatusActive),
		inhibitionRuleResource("wildcard", "grafana", "1", "1", "1", "0", "1", model.ResourceStatusActive),
		inhibitionRuleResource("no-equal", "grafana", "1", "1", "0", "0", "0", model.ResourceStatusActive),
		inhibitionRuleResource("deprecated", "alertmanager", "0", "0", "0", "1", "1", model.ResourceStatusDeprecated),
		inhibitionRuleResource("other", "custom", "0", "0", "0", "1", "1", model.ResourceStatusActive),
	}
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert inhibition rule: %v", err)
		}
	}
	broad, err := NewBroadInhibitionRuleAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(broad) != 2 || broad[0].Severity != model.SeverityCritical {
		t.Fatalf("unexpected broad inhibition findings: %#v, %v", broad, err)
	}
	withoutEqual, err := NewInhibitionRuleWithoutEqualLabelsAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(withoutEqual) != 1 || withoutEqual[0].Resource.ID != "no-equal" || withoutEqual[0].Severity != model.SeverityWarning {
		t.Fatalf("unexpected equal-label findings: %#v, %v", withoutEqual, err)
	}
}

func inhibitionRuleResource(id, system, sourceCount, targetCount, equalCount, sourceBroad, targetBroad string, status model.ResourceStatus) model.Resource {
	return model.Resource{
		ID: id, Type: model.ResourceTypeInhibitionRule, Name: id, Status: status,
		Source: model.SourceInfo{System: system, Instance: "local", ExternalID: "inhibition-rule:" + id},
		Metadata: map[string]string{
			model.MetadataInhibitionSourceMatcherCount: sourceCount, model.MetadataInhibitionTargetMatcherCount: targetCount,
			model.MetadataInhibitionEqualLabelCount: equalCount, model.MetadataInhibitionSourceBroadCount: sourceBroad,
			model.MetadataInhibitionTargetBroadCount: targetBroad,
		},
	}
}
