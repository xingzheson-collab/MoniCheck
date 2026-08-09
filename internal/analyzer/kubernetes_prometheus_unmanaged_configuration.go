package analyzer

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const KubernetesPrometheusUnmanagedConfigurationAnalyzerID = "builtin.kubernetes_prometheus_unmanaged_configuration"

type KubernetesPrometheusUnmanagedConfigurationAnalyzer struct{}

func NewKubernetesPrometheusUnmanagedConfigurationAnalyzer() *KubernetesPrometheusUnmanagedConfigurationAnalyzer {
	return &KubernetesPrometheusUnmanagedConfigurationAnalyzer{}
}

func (a *KubernetesPrometheusUnmanagedConfigurationAnalyzer) ID() string {
	return KubernetesPrometheusUnmanagedConfigurationAnalyzerID
}
func (a *KubernetesPrometheusUnmanagedConfigurationAnalyzer) Name() string {
	return "Kubernetes Prometheus Unmanaged Configuration"
}
func (a *KubernetesPrometheusUnmanagedConfigurationAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesPrometheusUnmanagedConfigurationAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}

func (a *KubernetesPrometheusUnmanagedConfigurationAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTSDB})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		kind := strings.TrimSpace(resource.Metadata["kubernetes_kind"])
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || (kind != "Prometheus" && kind != "PrometheusAgent") || resource.Metadata["prometheus_configuration_managed"] != "false" {
			continue
		}
		namespace := kubernetesResourceNamespace(resource)
		additionalDeclared := resource.Metadata["prometheus_additional_scrape_configs_declared"] == "true"
		findings = append(findings, model.Finding{
			ID:             model.StableID(a.ID(), resource.ID),
			Type:           "KubernetesPrometheusUnmanagedConfiguration",
			Severity:       model.SeverityWarning,
			Category:       model.FindingCategoryConfiguration,
			Resource:       model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
			Evidence:       []string{fmt.Sprintf("Kubernetes %s %q in namespace %q leaves serviceMonitorSelector, podMonitorSelector, probeSelector, and scrapeConfigSelector all null; Operator-generated scrape configuration is unmanaged", kind, resource.Name, namespace)},
			Recommendation: "至少声明一个 Monitor selector（空对象表示选择全部），让 Prometheus Operator 管理生成配置；需要附加原生 scrape jobs 时使用 additionalScrapeConfigs 或 ScrapeConfig CRD，并迁移已废弃的 raw configuration Secret 接管模式。",
			Metadata: map[string]string{
				"analyzer_id":                        a.ID(),
				"kubernetes_kind":                    kind,
				"namespace":                          namespace,
				"additional_scrape_configs_declared": fmt.Sprintf("%t", additionalDeclared),
				"declared_monitor_selector_count":    "0",
			},
			Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now,
		})
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}
