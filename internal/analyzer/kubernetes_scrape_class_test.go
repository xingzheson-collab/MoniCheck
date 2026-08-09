package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesInvalidScrapeClassSetAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	invalid := kubernetesScrapeClassWorkload("invalid", "2", "1", "1")
	valid := kubernetesScrapeClassWorkload("valid", "1", "0", "0")
	for _, resource := range []model.Resource{invalid, valid} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	findings, err := NewKubernetesInvalidScrapeClassSetAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(findings) != 1 || findings[0].Resource.ID != invalid.ID || findings[0].Severity != model.SeverityCritical {
		t.Fatalf("unexpected findings: %#v err=%v", findings, err)
	}
}

func TestKubernetesUndefinedScrapeClassAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	missing := kubernetesScrapeClassTarget("missing", "mesh", "true", "1")
	resolved := kubernetesScrapeClassTarget("resolved", "mesh", "true", "0")
	unknown := kubernetesScrapeClassTarget("unknown", "mesh", "false", "1")
	for _, resource := range []model.Resource{missing, resolved, unknown} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	findings, err := NewKubernetesUndefinedScrapeClassAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(findings) != 1 || findings[0].Resource.ID != missing.ID || findings[0].Category != model.FindingCategoryReliability {
		t.Fatalf("unexpected findings: %#v err=%v", findings, err)
	}
}

func TestKubernetesScrapeClassResourceAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	unused := kubernetesScrapeClassResource("unused", "0", "false")
	insecure := kubernetesScrapeClassResource("insecure", "2", "true")
	used := kubernetesScrapeClassResource("used", "1", "false")
	for _, resource := range []model.Resource{unused, insecure, used} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	findings, err := NewKubernetesUnusedScrapeClassAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(findings) != 1 || findings[0].Resource.ID != unused.ID || findings[0].Severity != model.SeverityInfo {
		t.Fatalf("unexpected unused findings: %#v err=%v", findings, err)
	}
	findings, err = NewKubernetesInsecureScrapeClassTLSAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(findings) != 1 || findings[0].Resource.ID != insecure.ID || findings[0].Category != model.FindingCategorySecurity {
		t.Fatalf("unexpected insecure findings: %#v err=%v", findings, err)
	}
}

func kubernetesScrapeClassWorkload(name, defaults, unnamed, duplicates string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeTSDB, Name: name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": "Prometheus", "namespace": "monitoring", "scrape_class_default_count": defaults, "scrape_class_unnamed_count": unnamed, "scrape_class_duplicate_name_count": duplicates}}
}

func kubernetesScrapeClassTarget(name, requested, evaluable, missing string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeTarget, Name: name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": "ServiceMonitor", "namespace": "prod", "scrape_class": requested, "scrape_class_resolution_evaluable": evaluable, "scrape_class_missing_workload_count": missing}}
}

func kubernetesScrapeClassResource(name, usage, insecure string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeScrapeClass, Name: name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": "ScrapeClass", "namespace": "monitoring", "scrape_class_parent_name": "main", "scrape_class_usage_count": usage, "scrape_class_tls_insecure": insecure}}
}
