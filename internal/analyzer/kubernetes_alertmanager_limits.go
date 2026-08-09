package analyzer

import (
	"context"
	"fmt"
	"sort"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	KubernetesUnboundedAlertmanagerSilencesAnalyzerID        = "builtin.kubernetes_unbounded_alertmanager_silences"
	KubernetesInvalidAlertmanagerLimitsAnalyzerID            = "builtin.kubernetes_invalid_alertmanager_limits"
	KubernetesUnsupportedAlertmanagerLimitsVersionAnalyzerID = "builtin.kubernetes_unsupported_alertmanager_limits_version"
)

type KubernetesAlertmanagerLimitsAnalyzer struct {
	id   string
	name string
}

func NewKubernetesUnboundedAlertmanagerSilencesAnalyzer() *KubernetesAlertmanagerLimitsAnalyzer {
	return &KubernetesAlertmanagerLimitsAnalyzer{id: KubernetesUnboundedAlertmanagerSilencesAnalyzerID, name: "Kubernetes Unbounded Alertmanager Silences"}
}
func NewKubernetesInvalidAlertmanagerLimitsAnalyzer() *KubernetesAlertmanagerLimitsAnalyzer {
	return &KubernetesAlertmanagerLimitsAnalyzer{id: KubernetesInvalidAlertmanagerLimitsAnalyzerID, name: "Kubernetes Invalid Alertmanager Limits"}
}
func NewKubernetesUnsupportedAlertmanagerLimitsVersionAnalyzer() *KubernetesAlertmanagerLimitsAnalyzer {
	return &KubernetesAlertmanagerLimitsAnalyzer{id: KubernetesUnsupportedAlertmanagerLimitsVersionAnalyzerID, name: "Kubernetes Unsupported Alertmanager Limits Version"}
}
func (a *KubernetesAlertmanagerLimitsAnalyzer) ID() string      { return a.id }
func (a *KubernetesAlertmanagerLimitsAnalyzer) Name() string    { return a.name }
func (a *KubernetesAlertmanagerLimitsAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesAlertmanagerLimitsAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *KubernetesAlertmanagerLimitsAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || resource.Metadata["kubernetes_kind"] != "Alertmanager" {
			continue
		}
		finding, matched := kubernetesAlertmanagerLimitsFinding(a.id, resource, now)
		if matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesAlertmanagerLimitsFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	severity := model.SeverityCritical
	category := model.FindingCategoryConfiguration
	findingType := ""
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": "Alertmanager", "namespace": kubernetesResourceNamespace(resource)}
	switch analyzerID {
	case KubernetesUnboundedAlertmanagerSilencesAnalyzerID:
		if resource.Metadata["alertmanager_limits_declared"] == "" {
			return model.Finding{}, false
		}
		countEnabled := resource.Metadata["alertmanager_max_silences_enabled"] == "true"
		sizeEnabled := resource.Metadata["alertmanager_max_per_silence_bytes_enabled"] == "true"
		if countEnabled && sizeEnabled {
			return model.Finding{}, false
		}
		severity = model.SeverityWarning
		category = model.FindingCategoryReliability
		findingType = "KubernetesUnboundedAlertmanagerSilences"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q leaves silence count limit enabled=%t and per-silence size limit enabled=%t", resource.Name, countEnabled, sizeEnabled)
		recommendation = "根据运维规模配置正 limits.maxSilences 和 limits.maxPerSilenceBytes，防止异常 silence 数量或超大 matcher/comment 占用无界资源。"
		metadata["alertmanager_max_silences_enabled"] = fmt.Sprintf("%t", countEnabled)
		metadata["alertmanager_max_per_silence_bytes_enabled"] = fmt.Sprintf("%t", sizeEnabled)
	case KubernetesInvalidAlertmanagerLimitsAnalyzerID:
		count := alertmanagerStorageMetadataInt64(resource, "alertmanager_limits_invalid_setting_count")
		if count == 0 {
			return model.Finding{}, false
		}
		findingType = "KubernetesInvalidAlertmanagerLimits"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q declares %d invalid silence limit setting(s)", resource.Name, count)
		recommendation = "将 limits 配置为对象，maxSilences 使用非负 int32，maxPerSilenceBytes 使用有效非负 ByteSize；正值启用限制，零值关闭限制。"
		metadata["alertmanager_limits_invalid_setting_count"] = fmt.Sprintf("%d", count)
	case KubernetesUnsupportedAlertmanagerLimitsVersionAnalyzerID:
		if resource.Metadata["alertmanager_limits_version_unsupported"] != "true" {
			return model.Finding{}, false
		}
		category = model.FindingCategoryReliability
		findingType = "KubernetesUnsupportedAlertmanagerLimitsVersion"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q declares version %q with silence limits, which require Alertmanager 0.28 or newer", resource.Name, resource.Metadata["alertmanager_version"])
		recommendation = "升级 Alertmanager 到 0.28 或更高版本，或移除不受支持的 limits 字段，并确认 Operator 调谐和 Pod 启动成功。"
		metadata["alertmanager_version"] = resource.Metadata["alertmanager_version"]
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}
