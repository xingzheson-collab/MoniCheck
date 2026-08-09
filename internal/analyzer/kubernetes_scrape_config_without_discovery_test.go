package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesScrapeConfigWithoutDiscoveryAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	static := kubernetesScrapeConfigResource("static", "static", "2", "0", "0", "1")
	discovered := kubernetesScrapeConfigResource("discovered", "discovered", "0", "2", "0", "0")
	empty := kubernetesScrapeConfigResource("empty", "empty", "0", "0", "1", "1")
	monitor := kubernetesMonitorResource("monitor", "monitor", "prod", "ServiceMonitor")
	for _, resource := range []model.Resource{static, discovered, empty, monitor} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	findings, err := NewKubernetesScrapeConfigWithoutDiscoveryAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 || findings[0].Resource.ID != empty.ID {
		t.Fatalf("expected empty ScrapeConfig finding, got %#v", findings)
	}
	if findings[0].Severity != model.SeverityCritical || findings[0].Category != model.FindingCategoryConfiguration {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
}

func kubernetesScrapeConfigResource(id string, name string, staticTargets string, discoveryConfigs string, emptyStatic string, staticCount string) model.Resource {
	return model.Resource{
		ID:     id,
		UID:    id,
		Type:   model.ResourceTypeTarget,
		Name:   name,
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "kubernetes", Instance: "/etc/kubernetes", ExternalID: "scrapeconfig:prod/" + name},
		Metadata: map[string]string{
			"kubernetes_kind":                   "ScrapeConfig",
			"namespace":                         "prod",
			"scrape_config_static_target_count": staticTargets,
			"scrape_config_discovery_count":     discoveryConfigs,
			"scrape_config_empty_static_count":  emptyStatic,
			"scrape_config_static_count":        staticCount,
		},
	}
}
