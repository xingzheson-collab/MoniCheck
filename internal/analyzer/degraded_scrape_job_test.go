package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestDegradedScrapeJobAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	degradedJob := scrapeJobResource("job-degraded", "api", "victoriametrics", model.ResourceStatusActive)
	downJob := scrapeJobResource("job-down", "payments", "victoriametrics", model.ResourceStatusActive)
	healthyJob := scrapeJobResource("job-healthy", "workers", "victoriametrics", model.ResourceStatusActive)

	resources := []model.Resource{degradedJob, downJob, healthyJob}
	relationships := make([]model.Relationship, 0)
	for index := 0; index < 3; index++ {
		status := model.ResourceStatusBroken
		health := "down"
		lastError := "timeout"
		if index == 0 {
			status = model.ResourceStatusActive
			health = "up"
			lastError = ""
		}
		target := scrapeTargetResource("target-api-"+string(rune('a'+index)), "api-target", "victoriametrics", status, health, lastError)
		resources = append(resources, target)
		relationships = append(relationships, scrapeJobRelationship("rel-api-"+target.ID, target.ID, degradedJob.ID))
	}
	for index := 0; index < 2; index++ {
		target := scrapeTargetResource("target-payments-"+string(rune('a'+index)), "payments-target", "victoriametrics", model.ResourceStatusBroken, "down", "timeout")
		resources = append(resources, target)
		relationships = append(relationships, scrapeJobRelationship("rel-payments-"+target.ID, target.ID, downJob.ID))
	}
	for index := 0; index < 2; index++ {
		target := scrapeTargetResource("target-workers-"+string(rune('a'+index)), "workers-target", "victoriametrics", model.ResourceStatusActive, "up", "")
		resources = append(resources, target)
		relationships = append(relationships, scrapeJobRelationship("rel-workers-"+target.ID, target.ID, healthyJob.ID))
	}
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	for _, relationship := range relationships {
		if err := store.Relationships.Upsert(ctx, relationship); err != nil {
			t.Fatalf("upsert relationship: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}
	analysis := Context{Resources: store.Resources, Graph: resourceGraph}
	findings, err := NewDegradedScrapeJobAnalyzer().Execute(ctx, analysis)
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 || findings[0].Resource.ID != degradedJob.ID {
		t.Fatalf("expected only partially degraded job finding, got %#v", findings)
	}
	if findings[0].Metadata["target_count"] != "3" || findings[0].Metadata["healthy_targets"] != "1" || findings[0].Metadata["healthy_ratio"] != "0.3333" {
		t.Fatalf("unexpected degraded job metadata: %#v", findings[0].Metadata)
	}

	findings, err = NewDegradedScrapeJobAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
		Config: map[string]any{
			"scrape_job_healthy_ratio_threshold": 0.3,
		},
	})
	if err != nil {
		t.Fatalf("execute analyzer with threshold: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected configured threshold to suppress finding, got %#v", findings)
	}

	findings, err = NewDegradedScrapeJobAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
		Config: map[string]any{
			"allowed_degraded_scrape_jobs": "api",
		},
	})
	if err != nil {
		t.Fatalf("execute analyzer with allowlist: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected allowlisted job to be suppressed, got %#v", findings)
	}
}
