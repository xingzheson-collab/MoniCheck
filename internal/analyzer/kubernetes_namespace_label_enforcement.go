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

const (
	KubernetesMonitorNamespaceLabelNotEnforcedAnalyzerID = "builtin.kubernetes_monitor_namespace_label_not_enforced"
	KubernetesRuleNamespaceLabelNotEnforcedAnalyzerID    = "builtin.kubernetes_rule_namespace_label_not_enforced"
)

type KubernetesMonitorNamespaceLabelNotEnforcedAnalyzer struct{}
type KubernetesRuleNamespaceLabelNotEnforcedAnalyzer struct{}

func NewKubernetesMonitorNamespaceLabelNotEnforcedAnalyzer() *KubernetesMonitorNamespaceLabelNotEnforcedAnalyzer {
	return &KubernetesMonitorNamespaceLabelNotEnforcedAnalyzer{}
}

func NewKubernetesRuleNamespaceLabelNotEnforcedAnalyzer() *KubernetesRuleNamespaceLabelNotEnforcedAnalyzer {
	return &KubernetesRuleNamespaceLabelNotEnforcedAnalyzer{}
}

func (a *KubernetesMonitorNamespaceLabelNotEnforcedAnalyzer) ID() string {
	return KubernetesMonitorNamespaceLabelNotEnforcedAnalyzerID
}
func (a *KubernetesMonitorNamespaceLabelNotEnforcedAnalyzer) Name() string {
	return "Kubernetes Monitor Namespace Label Not Enforced"
}
func (a *KubernetesMonitorNamespaceLabelNotEnforcedAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesMonitorNamespaceLabelNotEnforcedAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTarget}
}
func (a *KubernetesMonitorNamespaceLabelNotEnforcedAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTarget})
	if err != nil {
		return nil, err
	}
	return kubernetesNamespaceLabelFindings(resources, a.ID(), time.Now().UTC()), nil
}

func (a *KubernetesRuleNamespaceLabelNotEnforcedAnalyzer) ID() string {
	return KubernetesRuleNamespaceLabelNotEnforcedAnalyzerID
}
func (a *KubernetesRuleNamespaceLabelNotEnforcedAnalyzer) Name() string {
	return "Kubernetes Rule Namespace Label Not Enforced"
}
func (a *KubernetesRuleNamespaceLabelNotEnforcedAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesRuleNamespaceLabelNotEnforcedAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeAlertRule, model.ResourceTypeRecordingRule}
}
func (a *KubernetesRuleNamespaceLabelNotEnforcedAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources := make([]model.Resource, 0)
	for _, resourceType := range a.InputTypes() {
		items, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: resourceType})
		if err != nil {
			return nil, err
		}
		resources = append(resources, items...)
	}
	return kubernetesNamespaceLabelFindings(resources, a.ID(), time.Now().UTC()), nil
}

func kubernetesNamespaceLabelFindings(resources []model.Resource, analyzerID string, now time.Time) []model.Finding {
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		finding, matched := kubernetesNamespaceLabelFinding(resource, analyzerID, now)
		if matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings
}

func kubernetesNamespaceLabelFinding(resource model.Resource, analyzerID string, now time.Time) (model.Finding, bool) {
	if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive {
		return model.Finding{}, false
	}
	kind := strings.TrimSpace(resource.Metadata["kubernetes_kind"])
	crossKey := ""
	enforcedKey := ""
	excludedKey := ""
	unprotectedKey := ""
	findingType := ""
	subject := ""
	switch analyzerID {
	case KubernetesMonitorNamespaceLabelNotEnforcedAnalyzerID:
		if resource.Type != model.ResourceTypeTarget || (kind != "ServiceMonitor" && kind != "PodMonitor" && kind != "Probe" && kind != "ScrapeConfig") {
			return model.Finding{}, false
		}
		crossKey = "prometheus_cross_namespace_selected_count"
		enforcedKey = "prometheus_namespace_label_enforced_count"
		excludedKey = "prometheus_namespace_label_excluded_count"
		unprotectedKey = "prometheus_namespace_label_unprotected_count"
		findingType = "KubernetesMonitorNamespaceLabelNotEnforced"
		subject = kind
	case KubernetesRuleNamespaceLabelNotEnforcedAnalyzerID:
		if (resource.Type != model.ResourceTypeAlertRule && resource.Type != model.ResourceTypeRecordingRule) || kind != "PrometheusRule" {
			return model.Finding{}, false
		}
		crossKey = "rule_evaluator_cross_namespace_selected_count"
		enforcedKey = "rule_evaluator_namespace_label_enforced_count"
		excludedKey = "rule_evaluator_namespace_label_excluded_count"
		unprotectedKey = "rule_evaluator_namespace_label_unprotected_count"
		findingType = "KubernetesRuleNamespaceLabelNotEnforced"
		subject = "PrometheusRule entry"
	default:
		return model.Finding{}, false
	}
	crossCount := kubernetesNamespaceLabelMetadataInt(resource, crossKey)
	enforcedCount := kubernetesNamespaceLabelMetadataInt(resource, enforcedKey)
	excludedCount := kubernetesNamespaceLabelMetadataInt(resource, excludedKey)
	unprotectedCount := kubernetesNamespaceLabelMetadataInt(resource, unprotectedKey)
	if crossCount == 0 || excludedCount+unprotectedCount == 0 {
		return model.Finding{}, false
	}
	metadata := map[string]string{
		"analyzer_id":                analyzerID,
		"kubernetes_kind":            kind,
		"namespace":                  resource.Metadata["namespace"],
		"cross_namespace_count":      strconv.Itoa(crossCount),
		"enforced_workload_count":    strconv.Itoa(enforcedCount),
		"excluded_workload_count":    strconv.Itoa(excludedCount),
		"unprotected_workload_count": strconv.Itoa(unprotectedCount),
	}
	return model.Finding{
		ID:             model.StableID(analyzerID, resource.ID),
		Type:           findingType,
		Severity:       model.SeverityWarning,
		Category:       model.FindingCategorySecurity,
		Resource:       model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
		Evidence:       []string{fmt.Sprintf("Kubernetes %s %q is selected across namespaces by %d evaluator workload(s): %d enforce an origin namespace label, %d explicitly exclude it, and %d do not configure enforcement", subject, resource.Name, crossCount, enforcedCount, excludedCount, unprotectedCount)},
		Recommendation: "在所有跨 Namespace 选择该对象的 Prometheus/Agent/ThanosRuler 设置非空 enforcedNamespaceLabel，并删除非必要的 excludedFromEnforcement 或旧式 PrometheusRule exclusion；保留例外时应明确评审其租户隔离影响。",
		Metadata:       metadata,
		Status:         model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now,
	}, true
}

func kubernetesNamespaceLabelMetadataInt(resource model.Resource, key string) int {
	value, err := strconv.Atoi(strings.TrimSpace(resource.Metadata[key]))
	if err != nil || value < 0 {
		return 0
	}
	return value
}
