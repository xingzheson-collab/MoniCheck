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

const (
	KubernetesInvalidScrapeClassSetAnalyzerID  = "builtin.kubernetes_invalid_scrape_class_set"
	KubernetesUndefinedScrapeClassAnalyzerID   = "builtin.kubernetes_undefined_scrape_class"
	KubernetesUnusedScrapeClassAnalyzerID      = "builtin.kubernetes_unused_scrape_class"
	KubernetesInsecureScrapeClassTLSAnalyzerID = "builtin.kubernetes_insecure_scrape_class_tls"
)

type KubernetesInvalidScrapeClassSetAnalyzer struct{}
type KubernetesUndefinedScrapeClassAnalyzer struct{}
type KubernetesUnusedScrapeClassAnalyzer struct{}
type KubernetesInsecureScrapeClassTLSAnalyzer struct{}

func NewKubernetesInvalidScrapeClassSetAnalyzer() *KubernetesInvalidScrapeClassSetAnalyzer {
	return &KubernetesInvalidScrapeClassSetAnalyzer{}
}
func NewKubernetesUndefinedScrapeClassAnalyzer() *KubernetesUndefinedScrapeClassAnalyzer {
	return &KubernetesUndefinedScrapeClassAnalyzer{}
}
func NewKubernetesUnusedScrapeClassAnalyzer() *KubernetesUnusedScrapeClassAnalyzer {
	return &KubernetesUnusedScrapeClassAnalyzer{}
}
func NewKubernetesInsecureScrapeClassTLSAnalyzer() *KubernetesInsecureScrapeClassTLSAnalyzer {
	return &KubernetesInsecureScrapeClassTLSAnalyzer{}
}

func (a *KubernetesInvalidScrapeClassSetAnalyzer) ID() string {
	return KubernetesInvalidScrapeClassSetAnalyzerID
}
func (a *KubernetesInvalidScrapeClassSetAnalyzer) Name() string {
	return "Kubernetes Invalid ScrapeClass Set"
}
func (a *KubernetesInvalidScrapeClassSetAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesInvalidScrapeClassSetAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}
func (a *KubernetesInvalidScrapeClassSetAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTSDB})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		kind := resource.Metadata["kubernetes_kind"]
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || (kind != "Prometheus" && kind != "PrometheusAgent") {
			continue
		}
		defaults := strings.TrimSpace(resource.Metadata["scrape_class_default_count"])
		unnamed := strings.TrimSpace(resource.Metadata["scrape_class_unnamed_count"])
		duplicates := strings.TrimSpace(resource.Metadata["scrape_class_duplicate_name_count"])
		if numericMetadata(defaults) <= 1 && numericMetadata(unnamed) == 0 && numericMetadata(duplicates) == 0 {
			continue
		}
		namespace := kubernetesResourceNamespace(resource)
		findings = append(findings, model.Finding{ID: model.StableID(a.ID(), resource.ID), Type: "KubernetesInvalidScrapeClassSet", Severity: model.SeverityCritical, Category: model.FindingCategoryConfiguration, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{fmt.Sprintf("Kubernetes %s %q has %s default, %s unnamed, and %s duplicate-name scrape class definitions", kind, resource.Name, defaults, unnamed, duplicates)}, Recommendation: "确保每个 scrape class 名称非空且唯一，并且最多只有一个 class 设置 default=true；修复后检查 Operator Reconciled 状态。", Metadata: map[string]string{"analyzer_id": a.ID(), "kubernetes_kind": kind, "namespace": namespace, "scrape_class_default_count": defaults, "scrape_class_unnamed_count": unnamed, "scrape_class_duplicate_name_count": duplicates}, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now})
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func (a *KubernetesUndefinedScrapeClassAnalyzer) ID() string {
	return KubernetesUndefinedScrapeClassAnalyzerID
}
func (a *KubernetesUndefinedScrapeClassAnalyzer) Name() string {
	return "Kubernetes Monitor References Undefined ScrapeClass"
}
func (a *KubernetesUndefinedScrapeClassAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesUndefinedScrapeClassAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTarget}
}
func (a *KubernetesUndefinedScrapeClassAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTarget})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		requested := strings.TrimSpace(resource.Metadata["scrape_class"])
		missing := strings.TrimSpace(resource.Metadata["scrape_class_missing_workload_count"])
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || requested == "" || resource.Metadata["scrape_class_resolution_evaluable"] != "true" || numericMetadata(missing) == 0 {
			continue
		}
		namespace := kubernetesResourceNamespace(resource)
		findings = append(findings, model.Finding{ID: model.StableID(a.ID(), resource.ID), Type: "KubernetesUndefinedScrapeClass", Severity: model.SeverityCritical, Category: model.FindingCategoryReliability, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{fmt.Sprintf("Kubernetes %s %q requests scrape class %q which is missing from %s selecting Prometheus workloads", resource.Metadata["kubernetes_kind"], resource.Name, requested, missing)}, Recommendation: "在每个选择该 monitor 的 Prometheus/PrometheusAgent 中定义同名 scrapeClasses 条目，或将 spec.scrapeClass 修正为已存在的 class。", Metadata: map[string]string{"analyzer_id": a.ID(), "kubernetes_kind": resource.Metadata["kubernetes_kind"], "namespace": namespace, "scrape_class": requested, "scrape_class_missing_workload_count": missing}, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now})
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func (a *KubernetesUnusedScrapeClassAnalyzer) ID() string {
	return KubernetesUnusedScrapeClassAnalyzerID
}
func (a *KubernetesUnusedScrapeClassAnalyzer) Name() string    { return "Kubernetes Unused ScrapeClass" }
func (a *KubernetesUnusedScrapeClassAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesUnusedScrapeClassAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeScrapeClass}
}
func (a *KubernetesUnusedScrapeClassAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return kubernetesScrapeClassResourceFindings(ctx, analysis, a.ID(), false)
}

func (a *KubernetesInsecureScrapeClassTLSAnalyzer) ID() string {
	return KubernetesInsecureScrapeClassTLSAnalyzerID
}
func (a *KubernetesInsecureScrapeClassTLSAnalyzer) Name() string {
	return "Kubernetes ScrapeClass Disables TLS Verification"
}
func (a *KubernetesInsecureScrapeClassTLSAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesInsecureScrapeClassTLSAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeScrapeClass}
}
func (a *KubernetesInsecureScrapeClassTLSAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return kubernetesScrapeClassResourceFindings(ctx, analysis, a.ID(), true)
}

func kubernetesScrapeClassResourceFindings(ctx context.Context, analysis Context, analyzerID string, insecure bool) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeScrapeClass})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive {
			continue
		}
		if insecure {
			if resource.Metadata["scrape_class_tls_insecure"] != "true" {
				continue
			}
		} else if resource.Metadata["scrape_class_usage_count"] != "0" {
			continue
		}
		findingType := "KubernetesUnusedScrapeClass"
		severity := model.SeverityInfo
		category := model.FindingCategoryLifecycle
		evidence := fmt.Sprintf("Kubernetes scrape class %q on %q is not used by any selected monitor", resource.Name, resource.Metadata["scrape_class_parent_name"])
		recommendation := "删除未使用的 class，或让预期 monitor 显式引用它；若它应作为默认配置，请检查 default 标记和 monitor 选择范围。"
		if insecure {
			findingType = "KubernetesInsecureScrapeClassTLS"
			severity = model.SeverityWarning
			category = model.FindingCategorySecurity
			evidence = fmt.Sprintf("Kubernetes scrape class %q on %q sets tlsConfig.insecureSkipVerify=true", resource.Name, resource.Metadata["scrape_class_parent_name"])
			recommendation = "启用服务端证书校验并配置可信 CA；共享 scrape class 会把不安全 TLS 设置传播给所有使用它的 monitor。"
		}
		findings = append(findings, model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": "ScrapeClass", "namespace": resource.Metadata["namespace"], "scrape_class_parent_name": resource.Metadata["scrape_class_parent_name"]}, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now})
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func numericMetadata(value string) int {
	result := 0
	for _, character := range strings.TrimSpace(value) {
		if character < '0' || character > '9' {
			return 0
		}
		result = result*10 + int(character-'0')
	}
	return result
}
