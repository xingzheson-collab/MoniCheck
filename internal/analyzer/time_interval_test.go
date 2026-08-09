package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestTimeIntervalAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	for _, resource := range []model.Resource{
		timeIntervalResource("used", "alertmanager", "true", "1", "0"),
		timeIntervalResource("unused", "alertmanager", "true", "0", "0"),
		timeIntervalResource("missing", "alertmanager", "false", "0", "2"),
		timeIntervalResource("grafana-unused", "grafana", "true", "0", "0"),
		timeIntervalResource("grafana-missing", "grafana", "false", "1", "0"),
		timeIntervalResource("other-missing", "custom", "false", "1", "0"),
	} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert interval: %v", err)
		}
	}
	undefined, err := NewUndefinedTimeIntervalAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(undefined) != 2 {
		t.Fatalf("unexpected undefined findings: %#v, %v", undefined, err)
	}
	unused, err := NewUnusedTimeIntervalAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(unused) != 2 {
		t.Fatalf("unexpected unused findings: %#v, %v", unused, err)
	}
}

func timeIntervalResource(name, system, declared, muteRefs, activeRefs string) model.Resource {
	return model.Resource{ID: name, Type: model.ResourceTypeTimeInterval, Name: name, Status: model.ResourceStatusActive,
		Source:   model.SourceInfo{System: system, Instance: "local", ExternalID: "time-interval:" + name},
		Metadata: map[string]string{model.MetadataTimeIntervalDeclared: declared, model.MetadataTimeIntervalMuteRefCount: muteRefs, model.MetadataTimeIntervalActiveRefCount: activeRefs}}
}
