package analyzer

import (
	"context"
	"strings"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestN9ERuntimeCoverageAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resources := []model.Resource{
		n9eRuntimeCoverageTestResource("healthy", map[string]string{
			model.MetadataN9ECurrentAlertDiscoveryAvailable: "true",
			model.MetadataN9EHistoryDiscoveryAvailable:      "true",
			model.MetadataN9ECurrentAlertEventsTruncated:    "false",
			model.MetadataN9EHistoryEventsTruncated:         "false",
		}),
		n9eRuntimeCoverageTestResource("current-unavailable", map[string]string{
			model.MetadataN9ECurrentAlertDiscoveryAvailable: "false",
			model.MetadataN9EHistoryDiscoveryAvailable:      "true",
		}),
		n9eRuntimeCoverageTestResource("history-unavailable", map[string]string{
			model.MetadataN9ECurrentAlertDiscoveryAvailable: "true",
			model.MetadataN9EHistoryDiscoveryAvailable:      "false",
		}),
		n9eRuntimeCoverageTestResource("truncated", map[string]string{
			model.MetadataN9ECurrentAlertDiscoveryAvailable: "true",
			model.MetadataN9EHistoryDiscoveryAvailable:      "true",
			model.MetadataN9ECurrentAlertEventsTruncated:    "true",
			model.MetadataN9ECurrentAlertEventCount:         "50000",
			model.MetadataN9ECurrentAlertEventTotal:         "51000",
			model.MetadataN9EHistoryEventsTruncated:         "true",
			model.MetadataN9EHistoryEventCount:              "10000",
			model.MetadataN9EHistoryEventTotal:              "12000",
		}),
	}
	wrongSource := n9eRuntimeCoverageTestResource("wrong-source", map[string]string{
		model.MetadataN9ECurrentAlertDiscoveryAvailable: "false",
		model.MetadataN9EHistoryDiscoveryAvailable:      "false",
		model.MetadataN9ECurrentAlertEventsTruncated:    "true",
	})
	wrongSource.Source.System = "grafana"
	inactive := n9eRuntimeCoverageTestResource("inactive", map[string]string{
		model.MetadataN9ECurrentAlertDiscoveryAvailable: "false",
		model.MetadataN9EHistoryDiscoveryAvailable:      "false",
		model.MetadataN9ECurrentAlertEventsTruncated:    "true",
	})
	inactive.Status = model.ResourceStatusDeprecated
	unmarked := n9eRuntimeCoverageTestResource("unmarked", map[string]string{
		model.MetadataN9ECurrentAlertDiscoveryAvailable: "false",
	})
	delete(unmarked.Metadata, model.MetadataN9ERuntime)
	resources = append(resources, wrongSource, inactive, unmarked)
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert runtime resource: %v", err)
		}
	}

	tests := []struct {
		analyzer     Analyzer
		resourceID   string
		findingType  string
		evidencePart string
	}{
		{NewN9ECurrentAlertDiscoveryUnavailableAnalyzer(), "current-unavailable", "N9ECurrentAlertDiscoveryUnavailable", "current alert discovery endpoint"},
		{NewN9EHistoryDiscoveryUnavailableAnalyzer(), "history-unavailable", "N9EHistoryDiscoveryUnavailable", "history discovery endpoint"},
		{NewN9EEventDiscoveryTruncatedAnalyzer(), "truncated", "N9EEventDiscoveryTruncated", "50000 of 51000"},
	}
	for _, test := range tests {
		t.Run(test.analyzer.ID(), func(t *testing.T) {
			findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
			if err != nil {
				t.Fatalf("execute analyzer: %v", err)
			}
			if len(findings) != 1 ||
				findings[0].Resource.ID != test.resourceID ||
				findings[0].Type != test.findingType ||
				findings[0].Severity != model.SeverityWarning ||
				findings[0].Category != model.FindingCategoryReliability ||
				!strings.Contains(findings[0].Evidence[0], test.evidencePart) ||
				model.DefaultFindingCategory(findings[0].Type, findings[0].Resource.Type) != model.FindingCategoryReliability {
				t.Fatalf("unexpected N9E runtime findings: %#v", findings)
			}
		})
	}
}

func n9eRuntimeCoverageTestResource(id string, metadata map[string]string) model.Resource {
	metadata[model.MetadataN9ERuntime] = "true"
	return model.Resource{
		ID:       id,
		UID:      id,
		Type:     model.ResourceTypeInstance,
		Name:     "N9E Runtime",
		Source:   model.SourceInfo{System: "n9e", Instance: "http://" + id},
		Metadata: metadata,
		Status:   model.ResourceStatusActive,
	}
}
