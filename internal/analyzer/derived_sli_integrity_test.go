package analyzer

import (
	"context"
	"testing"
	"time"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestDerivedSLIIntegrityAnalyzerEvidenceStates(t *testing.T) {
	now := time.Now().UTC()
	tests := []struct {
		name          string
		resources     []model.Resource
		relationships []model.Relationship
		findingType   string
		severity      model.Severity
	}{
		{
			name: "observed bucket input is healthy",
			resources: []model.Resource{
				derivedSLIRule("rule-observed", "p99 observed"),
				derivedSLIMetric("metric-bucket", "http_request_duration_seconds_bucket", nil),
				{ID: "target", Type: model.ResourceTypeTarget, Name: "api", Status: model.ResourceStatusActive},
			},
			relationships: []model.Relationship{
				derivedSLIRelationship("rule-observed", "metric-bucket", model.RelationshipUses, nil, now),
				derivedSLIRelationship("target", "metric-bucket", model.RelationshipProduces, nil, now),
			},
		},
		{
			name:      "exact missing input is critical",
			resources: []model.Resource{derivedSLIRule("rule-missing", "p99 missing")},
			relationships: []model.Relationship{derivedSLIRelationship("rule-missing", "missing-bucket", model.RelationshipUses, map[string]string{
				model.MetadataMetricInventoryBinding: "EXACT",
			}, now)},
			findingType: "DerivedSLIInputNotCollected", severity: model.SeverityCritical,
		},
		{
			name: "placeholder input stays unknown",
			resources: []model.Resource{
				derivedSLIRule("rule-unknown", "p99 unknown"),
				derivedSLIMetric("metric-bucket", "http_request_duration_seconds_bucket", nil),
			},
			relationships: []model.Relationship{derivedSLIRelationship("rule-unknown", "metric-bucket", model.RelationshipUses, nil, now)},
			findingType:   "DerivedSLIInputUnverified", severity: model.SeverityWarning,
		},
		{
			name: "base metric type drift reaches derived SLI",
			resources: []model.Resource{
				derivedSLIRule("rule-drift", "p99 drift"),
				derivedSLIMetric("metric-bucket", "http_request_duration_seconds_bucket", nil),
				derivedSLIMetric("metric-base", "http_request_duration_seconds", map[string]string{
					model.MetadataMetricTypeVariants: `["histogram","summary"]`,
				}),
				{ID: "target", Type: model.ResourceTypeTarget, Name: "api", Status: model.ResourceStatusActive},
			},
			relationships: []model.Relationship{
				derivedSLIRelationship("rule-drift", "metric-bucket", model.RelationshipUses, nil, now),
				derivedSLIRelationship("target", "metric-bucket", model.RelationshipProduces, nil, now),
			},
			findingType: "DerivedSLIMetricContractDrift", severity: model.SeverityCritical,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			store := storage.NewMemoryStore()
			for _, resource := range tt.resources {
				if err := store.Resources.Upsert(ctx, resource); err != nil {
					t.Fatalf("upsert resource: %v", err)
				}
			}
			for _, relationship := range tt.relationships {
				if err := store.Relationships.Upsert(ctx, relationship); err != nil {
					t.Fatalf("upsert relationship: %v", err)
				}
			}
			resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
			if err != nil {
				t.Fatalf("build graph: %v", err)
			}
			findings, err := NewDerivedSLIIntegrityAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
			if err != nil {
				t.Fatalf("execute analyzer: %v", err)
			}
			if tt.findingType == "" {
				if len(findings) != 0 {
					t.Fatalf("expected healthy chain, got %#v", findings)
				}
				return
			}
			if len(findings) != 1 || findings[0].Type != tt.findingType || findings[0].Severity != tt.severity {
				t.Fatalf("unexpected finding: %#v", findings)
			}
		})
	}
}

func derivedSLIRule(id, name string) model.Resource {
	return model.Resource{
		ID: id, Type: model.ResourceTypeRecordingRule, Name: name,
		Source:   model.SourceInfo{System: "prometheus", Instance: "prometheus-a"},
		Metadata: map[string]string{model.MetadataPromQL: `histogram_quantile(0.99, sum by (le) (rate(http_request_duration_seconds_bucket[5m])))`},
		Status:   model.ResourceStatusActive,
	}
}

func derivedSLIMetric(id, name string, metadata map[string]string) model.Resource {
	return model.Resource{
		ID: id, Type: model.ResourceTypeMetric, Name: name,
		Source:   model.SourceInfo{System: "prometheus", Instance: "prometheus-a"},
		Metadata: metadata, Status: model.ResourceStatusActive,
	}
}

func derivedSLIRelationship(from, to string, relationshipType model.RelationshipType, metadata map[string]string, now time.Time) model.Relationship {
	return model.Relationship{ID: model.StableID(from, string(relationshipType), to), FromID: from, ToID: to, Type: relationshipType, Metadata: metadata, CreatedAt: now}
}
