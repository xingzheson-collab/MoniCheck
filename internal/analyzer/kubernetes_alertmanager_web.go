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
	KubernetesInvalidAlertmanagerWebConfigurationAnalyzerID = "builtin.kubernetes_invalid_alertmanager_web_configuration"
	KubernetesAlertmanagerWebTimeoutDisabledAnalyzerID      = "builtin.kubernetes_alertmanager_web_timeout_disabled"
	KubernetesPlaintextExternalAlertmanagerAnalyzerID       = "builtin.kubernetes_plaintext_external_alertmanager"
)

type KubernetesAlertmanagerWebAnalyzer struct {
	id   string
	name string
}

func NewKubernetesInvalidAlertmanagerWebConfigurationAnalyzer() *KubernetesAlertmanagerWebAnalyzer {
	return &KubernetesAlertmanagerWebAnalyzer{id: KubernetesInvalidAlertmanagerWebConfigurationAnalyzerID, name: "Kubernetes Invalid Alertmanager Web Configuration"}
}
func NewKubernetesAlertmanagerWebTimeoutDisabledAnalyzer() *KubernetesAlertmanagerWebAnalyzer {
	return &KubernetesAlertmanagerWebAnalyzer{id: KubernetesAlertmanagerWebTimeoutDisabledAnalyzerID, name: "Kubernetes Alertmanager Web Timeout Disabled"}
}
func NewKubernetesPlaintextExternalAlertmanagerAnalyzer() *KubernetesAlertmanagerWebAnalyzer {
	return &KubernetesAlertmanagerWebAnalyzer{id: KubernetesPlaintextExternalAlertmanagerAnalyzerID, name: "Kubernetes Plaintext External Alertmanager"}
}
func (a *KubernetesAlertmanagerWebAnalyzer) ID() string      { return a.id }
func (a *KubernetesAlertmanagerWebAnalyzer) Name() string    { return a.name }
func (a *KubernetesAlertmanagerWebAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesAlertmanagerWebAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *KubernetesAlertmanagerWebAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || resource.Metadata["kubernetes_kind"] != "Alertmanager" || resource.Metadata["alertmanager_web_metadata"] != "true" {
			continue
		}
		finding, matched := kubernetesAlertmanagerWebFinding(a.id, resource, now)
		if matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesAlertmanagerWebFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	severity := model.SeverityCritical
	category := model.FindingCategoryConfiguration
	findingType := ""
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": "Alertmanager", "namespace": kubernetesResourceNamespace(resource)}
	switch analyzerID {
	case KubernetesInvalidAlertmanagerWebConfigurationAnalyzerID:
		count := alertmanagerStorageMetadataInt64(resource, "alertmanager_web_invalid_setting_count")
		if count == 0 {
			return model.Finding{}, false
		}
		findingType = "KubernetesInvalidAlertmanagerWebConfiguration"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q declares %d malformed WebSpec setting(s)", resource.Name, count)
		recommendation = "将 web 配置为对象，getConcurrency/timeout 使用非负 uint32，并将 tlsConfig/httpConfig 配置为对象。"
		metadata["alertmanager_web_invalid_setting_count"] = fmt.Sprintf("%d", count)
	case KubernetesAlertmanagerWebTimeoutDisabledAnalyzerID:
		if resource.Metadata["alertmanager_web_invalid_setting_count"] != "0" || resource.Metadata["alertmanager_web_timeout_enabled"] == "true" {
			return model.Finding{}, false
		}
		severity = model.SeverityWarning
		category = model.FindingCategoryReliability
		findingType = "KubernetesAlertmanagerWebTimeoutDisabled"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q has no positive web request timeout, so HTTP handlers may run without a deadline", resource.Name)
		recommendation = "根据最大 API/UI 请求耗时配置正 web.timeout，并在入口层同时设置连接、请求和空闲超时。"
	case KubernetesPlaintextExternalAlertmanagerAnalyzerID:
		if resource.Metadata["alertmanager_external_url_valid"] != "true" || resource.Metadata["alertmanager_external_url_scheme"] != "http" {
			return model.Finding{}, false
		}
		category = model.FindingCategorySecurity
		findingType = "KubernetesPlaintextExternalAlertmanager"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q advertises an external HTTP URL for alert, silence, status, and configuration APIs", resource.Name)
		recommendation = "使用 HTTPS externalUrl 和受信任证书，并在入口层保护告警写入、silence 变更和管理 API 的认证、授权与审计。"
		metadata["alertmanager_external_url_scheme"] = "http"
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}
