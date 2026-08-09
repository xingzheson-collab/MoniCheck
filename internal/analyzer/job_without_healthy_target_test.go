package analyzer

import (
	"context"
	"testing"
	"time"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestJobWithoutHealthyTargetAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	healthyJob := scrapeJobResource("job-healthy", "api", "prometheus", model.ResourceStatusActive)
	unhealthyJob := scrapeJobResource("job-unhealthy", "payments", "prometheus", model.ResourceStatusActive)
	deprecatedJob := scrapeJobResource("job-deprecated", "legacy", "prometheus", model.ResourceStatusDeprecated)
	thanosJob := scrapeJobResource("job-thanos", "global-api", "thanos", model.ResourceStatusActive)

	healthyTarget := scrapeTargetResource("target-healthy", "api-1", "prometheus", model.ResourceStatusActive, "up", "")
	degradedTarget := scrapeTargetResource("target-degraded", "api-2", "prometheus", model.ResourceStatusBroken, "down", "timeout")
	downTarget := scrapeTargetResource("target-down", "payments-1", "prometheus", model.ResourceStatusBroken, "down", "connection refused")
	orphanTarget := scrapeTargetResource("target-orphan", "payments-2", "prometheus", model.ResourceStatusOrphan, "unknown", "")
	deprecatedTarget := scrapeTargetResource("target-deprecated", "payments-old", "prometheus", model.ResourceStatusDeprecated, "up", "")
	legacyTarget := scrapeTargetResource("target-legacy", "legacy-1", "prometheus", model.ResourceStatusBroken, "down", "timeout")
	thanosTarget := scrapeTargetResource("target-thanos", "global-api-1", "thanos", model.ResourceStatusBroken, "down", "timeout")

	for _, resource := range []model.Resource{
		healthyJob, unhealthyJob, deprecatedJob, thanosJob,
		healthyTarget, degradedTarget, downTarget, orphanTarget, deprecatedTarget, legacyTarget, thanosTarget,
	} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	for _, relationship := range []model.Relationship{
		scrapeJobRelationship("rel-healthy", healthyTarget.ID, healthyJob.ID),
		scrapeJobRelationship("rel-degraded", degradedTarget.ID, healthyJob.ID),
		scrapeJobRelationship("rel-down", downTarget.ID, unhealthyJob.ID),
		scrapeJobRelationship("rel-orphan", orphanTarget.ID, unhealthyJob.ID),
		scrapeJobRelationship("rel-deprecated-target", deprecatedTarget.ID, unhealthyJob.ID),
		scrapeJobRelationship("rel-legacy", legacyTarget.ID, deprecatedJob.ID),
		scrapeJobRelationship("rel-thanos", thanosTarget.ID, thanosJob.ID),
	} {
		if err := store.Relationships.Upsert(ctx, relationship); err != nil {
			t.Fatalf("upsert relationship: %v", err)
		}
	}

	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}
	findings, err := NewJobWithoutHealthyTargetAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected findings for prometheus and thanos jobs, got %#v", findings)
	}
	if findings[0].Resource.ID != unhealthyJob.ID || findings[0].Metadata["target_count"] != "2" {
		t.Fatalf("expected two eligible unhealthy prometheus targets, got %#v", findings[0])
	}
	if findings[1].Resource.ID != thanosJob.ID || findings[1].Metadata["source_system"] != "thanos" {
		t.Fatalf("expected compatible thanos job finding, got %#v", findings[1])
	}
}

func TestJobWithoutHealthyTargetAnalyzerRequiresMatchingSourceInstance(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	job := scrapeJobResource("job", "api", "prometheus", model.ResourceStatusActive)
	job.Source.Instance = "prometheus-a"
	target := scrapeTargetResource("target", "api-1", "prometheus", model.ResourceStatusBroken, "down", "timeout")
	target.Source.Instance = "prometheus-b"
	if err := store.Resources.Upsert(ctx, job); err != nil {
		t.Fatalf("upsert job: %v", err)
	}
	if err := store.Resources.Upsert(ctx, target); err != nil {
		t.Fatalf("upsert target: %v", err)
	}
	if err := store.Relationships.Upsert(ctx, scrapeJobRelationship("rel", target.ID, job.ID)); err != nil {
		t.Fatalf("upsert relationship: %v", err)
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}
	findings, err := NewJobWithoutHealthyTargetAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected mismatched connector instance target to be ignored, got %#v", findings)
	}
}

func TestTargetScrapeAnalyzersSupportPrometheusCompatibleSources(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	target := scrapeTargetResource("target-mimir", "mimir-api", "mimir", model.ResourceStatusActive, "up", "")
	target.Metadata[model.MetadataScrapeDuration] = "9s"
	target.Metadata[model.MetadataScrapeTimeout] = "10s"
	target.Metadata[model.MetadataLastScrape] = time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	if err := store.Resources.Upsert(ctx, target); err != nil {
		t.Fatalf("upsert target: %v", err)
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}
	analysis := Context{Resources: store.Resources, Graph: resourceGraph}
	for name, execute := range map[string]func(context.Context, Context) ([]model.Finding, error){
		"slow":    NewSlowTargetScrapeAnalyzer().Execute,
		"stale":   NewStaleTargetScrapeAnalyzer().Execute,
		"timeout": NewTargetScrapeTimeoutRiskAnalyzer().Execute,
	} {
		findings, err := execute(ctx, analysis)
		if err != nil {
			t.Fatalf("execute %s analyzer: %v", name, err)
		}
		if len(findings) != 1 || findings[0].Resource.ID != target.ID {
			t.Fatalf("expected %s analyzer finding for Mimir target, got %#v", name, findings)
		}
	}
}

func scrapeJobResource(id string, name string, system string, status model.ResourceStatus) model.Resource {
	return model.Resource{
		ID:     id,
		Type:   model.ResourceTypeJob,
		Name:   name,
		Status: status,
		Source: model.SourceInfo{System: system, Instance: system + "-local"},
	}
}

func scrapeTargetResource(id string, name string, system string, status model.ResourceStatus, health string, lastError string) model.Resource {
	return model.Resource{
		ID:     id,
		Type:   model.ResourceTypeTarget,
		Name:   name,
		Status: status,
		Source: model.SourceInfo{System: system, Instance: system + "-local"},
		Metadata: map[string]string{
			model.MetadataHealth:    health,
			model.MetadataLastError: lastError,
		},
	}
}

func scrapeJobRelationship(id string, targetID string, jobID string) model.Relationship {
	return model.Relationship{
		ID:     id,
		FromID: targetID,
		ToID:   jobID,
		Type:   model.RelationshipBelongsTo,
	}
}
