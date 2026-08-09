package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestNotificationTemplateAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	for _, resource := range []model.Resource{
		notificationTemplateResource("used", "1", "2", ""),
		notificationTemplateResource("unused", "1", "0", ""),
		notificationTemplateResource("empty", "0", "0", ""),
		notificationTemplateResource("builtin", "2", "0", "grafana"),
		undefinedNotificationTemplateResource("missing", "2"),
		conflictingNotificationTemplateResource("conflict", "shared.message"),
	} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert template: %v", err)
		}
	}
	empty, err := NewEmptyNotificationTemplateAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(empty) != 1 || empty[0].Resource.Name != "empty" {
		t.Fatalf("unexpected empty findings: %#v, %v", empty, err)
	}
	unused, err := NewUnusedNotificationTemplateAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(unused) != 1 || unused[0].Resource.Name != "unused" {
		t.Fatalf("unexpected unused findings: %#v, %v", unused, err)
	}
	undefined, err := NewUndefinedNotificationTemplateAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(undefined) != 1 || undefined[0].Resource.Name != "missing" {
		t.Fatalf("unexpected undefined findings: %#v, %v", undefined, err)
	}
	conflicts, err := NewDuplicateNotificationTemplateDefinitionAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(conflicts) != 1 || conflicts[0].Resource.Name != "conflict" || conflicts[0].Severity != model.SeverityCritical {
		t.Fatalf("unexpected conflict findings: %#v, %v", conflicts, err)
	}
}

func undefinedNotificationTemplateResource(name, references string) model.Resource {
	resource := notificationTemplateResource(name, "0", references, "")
	resource.Metadata[model.MetadataTemplateDeclared] = "false"
	return resource
}

func conflictingNotificationTemplateResource(name, conflicts string) model.Resource {
	resource := notificationTemplateResource(name, "1", "1", "")
	resource.Metadata[model.MetadataTemplateConflictCount] = "1"
	resource.Metadata[model.MetadataTemplateConflictNames] = conflicts
	return resource
}

func notificationTemplateResource(name, definitions, references, kind string) model.Resource {
	return model.Resource{ID: name, Type: model.ResourceTypeNotificationTemplate, Name: name, Status: model.ResourceStatusActive,
		Source:   model.SourceInfo{System: "grafana", Instance: "local", ExternalID: "notification-template:" + name},
		Metadata: map[string]string{model.MetadataTemplateDeclared: "true", model.MetadataTemplateDefinitionCount: definitions, model.MetadataTemplateReferenceCount: references, model.MetadataTemplateKind: kind}}
}
