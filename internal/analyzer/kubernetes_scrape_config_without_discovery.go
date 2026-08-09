package analyzer

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const KubernetesScrapeConfigWithoutDiscoveryAnalyzerID = "builtin.kubernetes_scrape_config_without_discovery"

type KubernetesScrapeConfigWithoutDiscoveryAnalyzer struct{}

func NewKubernetesScrapeConfigWithoutDiscoveryAnalyzer() *KubernetesScrapeConfigWithoutDiscoveryAnalyzer {
	return &KubernetesScrapeConfigWithoutDiscoveryAnalyzer{}
}

func (a *KubernetesScrapeConfigWithoutDiscoveryAnalyzer) ID() string {
	return KubernetesScrapeConfigWithoutDiscoveryAnalyzerID
}

func (a *KubernetesScrapeConfigWithoutDiscoveryAnalyzer) Name() string {
	return "Kubernetes ScrapeConfig Without Discovery"
}

func (a *KubernetesScrapeConfigWithoutDiscoveryAnalyzer) Version() string {
	return "0.1.0"
}

func (a *KubernetesScrapeConfigWithoutDiscoveryAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTarget}
}

func (a *KubernetesScrapeConfigWithoutDiscoveryAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	targets, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTarget})
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, target := range targets {
		if !isKubernetesScrapeConfigTarget(target) || kubernetesScrapeConfigHasDiscovery(target) {
			continue
		}
		namespace := kubernetesResourceNamespace(target)
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), target.ID),
			Type:     "KubernetesScrapeConfigWithoutDiscovery",
			Severity: model.SeverityCritical,
			Category: model.FindingCategoryConfiguration,
			Resource: model.ResourceRef{ID: target.ID, Type: target.Type, Name: target.Name},
			Evidence: []string{
				fmt.Sprintf("Kubernetes ScrapeConfig %q in namespace %q has no static targets or service-discovery configurations", target.Name, namespace),
			},
			Recommendation: "为该 ScrapeConfig 增加至少一个非空 staticConfigs.targets，或配置 Kubernetes/File/HTTP/DNS 等 service discovery；没有发现来源时不会生成有效 scrape 目标。",
			Metadata: map[string]string{
				"analyzer_id":                       a.ID(),
				"kubernetes_kind":                   "ScrapeConfig",
				"namespace":                         namespace,
				"scrape_config_static_target_count": strings.TrimSpace(target.Metadata["scrape_config_static_target_count"]),
				"scrape_config_discovery_count":     strings.TrimSpace(target.Metadata["scrape_config_discovery_count"]),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Metadata["namespace"] != findings[j].Metadata["namespace"] {
			return findings[i].Metadata["namespace"] < findings[j].Metadata["namespace"]
		}
		return findings[i].Resource.Name < findings[j].Resource.Name
	})
	return findings, nil
}

func isKubernetesScrapeConfigTarget(resource model.Resource) bool {
	return resource.Source.System == "kubernetes" &&
		resource.Type == model.ResourceTypeTarget &&
		resource.Status == model.ResourceStatusActive &&
		strings.TrimSpace(resource.Metadata["kubernetes_kind"]) == "ScrapeConfig"
}

func kubernetesScrapeConfigHasDiscovery(resource model.Resource) bool {
	staticTargets, staticErr := strconv.Atoi(strings.TrimSpace(resource.Metadata["scrape_config_static_target_count"]))
	discoveryConfigs, discoveryErr := strconv.Atoi(strings.TrimSpace(resource.Metadata["scrape_config_discovery_count"]))
	return (staticErr == nil && staticTargets > 0) || (discoveryErr == nil && discoveryConfigs > 0)
}
