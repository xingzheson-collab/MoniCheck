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
	KubernetesInvalidThanosRulerAlertmanagerURLsAnalyzerID       = "builtin.kubernetes_invalid_thanos_ruler_alertmanager_urls"
	KubernetesThanosRulerAlertingWithoutAlertmanagerAnalyzerID   = "builtin.kubernetes_thanos_ruler_alerting_without_alertmanager"
	KubernetesPlaintextThanosRulerAlertmanagerAnalyzerID         = "builtin.kubernetes_plaintext_thanos_ruler_alertmanager"
	KubernetesUnsupportedThanosRulerAlertmanagerConfigAnalyzerID = "builtin.kubernetes_unsupported_thanos_ruler_alertmanager_config_version"
)

type KubernetesThanosRulerAlertmanagerDeliveryAnalyzer struct {
	id   string
	name string
}

func NewKubernetesInvalidThanosRulerAlertmanagerURLsAnalyzer() *KubernetesThanosRulerAlertmanagerDeliveryAnalyzer {
	return &KubernetesThanosRulerAlertmanagerDeliveryAnalyzer{id: KubernetesInvalidThanosRulerAlertmanagerURLsAnalyzerID, name: "Kubernetes Invalid ThanosRuler Alertmanager URLs"}
}

func NewKubernetesThanosRulerAlertingWithoutAlertmanagerAnalyzer() *KubernetesThanosRulerAlertmanagerDeliveryAnalyzer {
	return &KubernetesThanosRulerAlertmanagerDeliveryAnalyzer{id: KubernetesThanosRulerAlertingWithoutAlertmanagerAnalyzerID, name: "Kubernetes ThanosRuler Alerting Without Alertmanager"}
}

func NewKubernetesPlaintextThanosRulerAlertmanagerAnalyzer() *KubernetesThanosRulerAlertmanagerDeliveryAnalyzer {
	return &KubernetesThanosRulerAlertmanagerDeliveryAnalyzer{id: KubernetesPlaintextThanosRulerAlertmanagerAnalyzerID, name: "Kubernetes Plaintext ThanosRuler Alertmanager"}
}

func NewKubernetesUnsupportedThanosRulerAlertmanagerConfigAnalyzer() *KubernetesThanosRulerAlertmanagerDeliveryAnalyzer {
	return &KubernetesThanosRulerAlertmanagerDeliveryAnalyzer{id: KubernetesUnsupportedThanosRulerAlertmanagerConfigAnalyzerID, name: "Kubernetes Unsupported ThanosRuler Alertmanager Config Version"}
}

func (a *KubernetesThanosRulerAlertmanagerDeliveryAnalyzer) ID() string      { return a.id }
func (a *KubernetesThanosRulerAlertmanagerDeliveryAnalyzer) Name() string    { return a.name }
func (a *KubernetesThanosRulerAlertmanagerDeliveryAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesThanosRulerAlertmanagerDeliveryAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *KubernetesThanosRulerAlertmanagerDeliveryAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || resource.Metadata["kubernetes_kind"] != "ThanosRuler" || resource.Metadata["thanos_ruler_alertmanager_delivery_metadata"] != "true" {
			continue
		}
		if finding, matched := kubernetesThanosRulerAlertmanagerDeliveryFinding(a.id, resource, now); matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesThanosRulerAlertmanagerDeliveryFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	severity := model.SeverityWarning
	category := model.FindingCategoryReliability
	findingType := ""
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": "ThanosRuler", "namespace": kubernetesResourceNamespace(resource)}
	switch analyzerID {
	case KubernetesInvalidThanosRulerAlertmanagerURLsAnalyzerID:
		invalid := alertmanagerStorageMetadataInt64(resource, "thanos_ruler_alertmanager_url_invalid_count")
		duplicates := alertmanagerStorageMetadataInt64(resource, "thanos_ruler_alertmanager_url_duplicate_count")
		if invalid+duplicates == 0 {
			return model.Finding{}, false
		}
		severity = model.SeverityCritical
		category = model.FindingCategoryConfiguration
		findingType = "KubernetesInvalidThanosRulerAlertmanagerURLs"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q has %d invalid and %d duplicate Alertmanager URL entries", resource.Name, invalid, duplicates)
		recommendation = "使用唯一且带 http/https 协议的 Alertmanager URL；DNS/SRV 发现仅使用 dns+ 或 dnssrv+ 前缀，并移除内嵌凭据。"
		metadata["thanos_ruler_alertmanager_url_invalid_count"] = fmt.Sprintf("%d", invalid)
		metadata["thanos_ruler_alertmanager_url_duplicate_count"] = fmt.Sprintf("%d", duplicates)
	case KubernetesThanosRulerAlertingWithoutAlertmanagerAnalyzerID:
		alerts := alertmanagerStorageMetadataInt64(resource, "thanos_ruler_selected_alert_rule_count")
		if alerts == 0 || resource.Metadata["thanos_ruler_alertmanager_delivery_configured"] == "true" {
			return model.Finding{}, false
		}
		severity = model.SeverityCritical
		findingType = "KubernetesThanosRulerAlertingWithoutAlertmanager"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q selects %d alert rule(s) but has no valid Alertmanager delivery destination", resource.Name, alerts)
		recommendation = "配置有效 alertmanagersConfig SecretKeySelector 或至少一个受控 Alertmanager URL，并验证告警投递与失败监控。"
		metadata["thanos_ruler_selected_alert_rule_count"] = fmt.Sprintf("%d", alerts)
	case KubernetesPlaintextThanosRulerAlertmanagerAnalyzerID:
		count := alertmanagerStorageMetadataInt64(resource, "thanos_ruler_plaintext_alertmanager_url_count")
		if count == 0 {
			return model.Finding{}, false
		}
		category = model.FindingCategorySecurity
		findingType = "KubernetesPlaintextThanosRulerAlertmanager"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q sends alerts to %d non-loopback plaintext HTTP Alertmanager destination(s)", resource.Name, count)
		recommendation = "使用 HTTPS Alertmanager URL 或在 alertmanagersConfig 中配置 TLS，并验证服务身份和证书轮换。"
		metadata["thanos_ruler_plaintext_alertmanager_url_count"] = fmt.Sprintf("%d", count)
	case KubernetesUnsupportedThanosRulerAlertmanagerConfigAnalyzerID:
		if resource.Metadata["thanos_ruler_alertmanager_config_version_unsupported"] != "true" {
			return model.Finding{}, false
		}
		severity = model.SeverityCritical
		category = model.FindingCategoryConfiguration
		findingType = "KubernetesUnsupportedThanosRulerAlertmanagerConfigVersion"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q declares version %q with alertmanagersConfig, which requires Thanos 0.10 or newer", resource.Name, resource.Metadata["thanos_ruler_version"])
		recommendation = "升级 Thanos 到 0.10 或更高版本，或迁移到该版本支持的 Alertmanager URL 配置。"
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}
