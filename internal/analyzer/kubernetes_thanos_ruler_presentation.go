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
	KubernetesInvalidThanosRulerPresentationAnalyzerID    = "builtin.kubernetes_invalid_thanos_ruler_presentation_configuration"
	KubernetesPlaintextThanosRulerAlertQueryAnalyzerID    = "builtin.kubernetes_plaintext_thanos_ruler_alert_query_url"
	KubernetesThanosRulerReplicaLabelOverrideAnalyzerID   = "builtin.kubernetes_thanos_ruler_replica_label_override"
	KubernetesThanosRulerDroppedExternalLabelsAnalyzerID  = "builtin.kubernetes_thanos_ruler_dropped_external_labels"
	KubernetesThanosRulerUserNamespaceIsolationAnalyzerID = "builtin.kubernetes_thanos_ruler_user_namespace_isolation"
)

type KubernetesThanosRulerPresentationAnalyzer struct {
	id   string
	name string
}

func NewKubernetesInvalidThanosRulerPresentationAnalyzer() *KubernetesThanosRulerPresentationAnalyzer {
	return &KubernetesThanosRulerPresentationAnalyzer{id: KubernetesInvalidThanosRulerPresentationAnalyzerID, name: "Kubernetes Invalid ThanosRuler Presentation Configuration"}
}

func NewKubernetesPlaintextThanosRulerAlertQueryAnalyzer() *KubernetesThanosRulerPresentationAnalyzer {
	return &KubernetesThanosRulerPresentationAnalyzer{id: KubernetesPlaintextThanosRulerAlertQueryAnalyzerID, name: "Kubernetes Plaintext ThanosRuler Alert Query URL"}
}

func NewKubernetesThanosRulerReplicaLabelOverrideAnalyzer() *KubernetesThanosRulerPresentationAnalyzer {
	return &KubernetesThanosRulerPresentationAnalyzer{id: KubernetesThanosRulerReplicaLabelOverrideAnalyzerID, name: "Kubernetes ThanosRuler Replica Label Override"}
}

func NewKubernetesThanosRulerDroppedExternalLabelsAnalyzer() *KubernetesThanosRulerPresentationAnalyzer {
	return &KubernetesThanosRulerPresentationAnalyzer{id: KubernetesThanosRulerDroppedExternalLabelsAnalyzerID, name: "Kubernetes ThanosRuler Dropped External Labels"}
}

func NewKubernetesThanosRulerUserNamespaceIsolationAnalyzer() *KubernetesThanosRulerPresentationAnalyzer {
	return &KubernetesThanosRulerPresentationAnalyzer{id: KubernetesThanosRulerUserNamespaceIsolationAnalyzerID, name: "Kubernetes ThanosRuler User Namespace Isolation"}
}

func (a *KubernetesThanosRulerPresentationAnalyzer) ID() string      { return a.id }
func (a *KubernetesThanosRulerPresentationAnalyzer) Name() string    { return a.name }
func (a *KubernetesThanosRulerPresentationAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesThanosRulerPresentationAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *KubernetesThanosRulerPresentationAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || resource.Metadata["kubernetes_kind"] != "ThanosRuler" || resource.Metadata["thanos_ruler_presentation_metadata"] != "true" {
			continue
		}
		if finding, matched := kubernetesThanosRulerPresentationFinding(a.id, resource, now); matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesThanosRulerPresentationFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	severity := model.SeverityWarning
	category := model.FindingCategoryConfiguration
	findingType := ""
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": "ThanosRuler", "namespace": kubernetesResourceNamespace(resource)}
	switch analyzerID {
	case KubernetesInvalidThanosRulerPresentationAnalyzerID:
		count := alertmanagerStorageMetadataInt64(resource, "thanos_ruler_presentation_invalid_setting_count")
		if count == 0 {
			return model.Finding{}, false
		}
		severity = model.SeverityCritical
		findingType = "KubernetesInvalidThanosRulerPresentationConfiguration"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q has %d invalid port, prefix, alert URL, label, or hostUsers setting(s)", resource.Name, count)
		recommendation = "使用合法端口名、URL/路径前缀、HTTP(S) Query URL、Prometheus 标签名及布尔 hostUsers，并删除重复 drop labels。"
		metadata["thanos_ruler_presentation_invalid_setting_count"] = fmt.Sprintf("%d", count)
	case KubernetesPlaintextThanosRulerAlertQueryAnalyzerID:
		if resource.Metadata["thanos_ruler_alert_query_url_valid"] != "true" || resource.Metadata["thanos_ruler_alert_query_url_scheme"] != "http" || resource.Metadata["thanos_ruler_alert_query_url_loopback"] == "true" {
			return model.Finding{}, false
		}
		category = model.FindingCategorySecurity
		findingType = "KubernetesPlaintextThanosRulerAlertQueryURL"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q places a non-loopback plaintext HTTP Query URL in every alert Source field", resource.Name)
		recommendation = "将 alertQueryUrl 改为受信任的 HTTPS Query 入口，并验证代理转发、证书和 Source 链接。"
	case KubernetesThanosRulerReplicaLabelOverrideAnalyzerID:
		if resource.Metadata["thanos_ruler_replica_label_override"] != "true" {
			return model.Finding{}, false
		}
		severity = model.SeverityCritical
		findingType = "KubernetesThanosRulerReplicaLabelOverride"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q declares the Operator-managed thanos_ruler_replica external label", resource.Name)
		recommendation = "删除 labels 中的 thanos_ruler_replica；由 Operator 生成每个 Pod 的副本标签，并在查询端配置对应去重。"
	case KubernetesThanosRulerDroppedExternalLabelsAnalyzerID:
		count := alertmanagerStorageMetadataInt64(resource, "thanos_ruler_dropped_external_label_count")
		if count == 0 {
			return model.Finding{}, false
		}
		category = model.FindingCategoryReliability
		findingType = "KubernetesThanosRulerDroppedExternalLabels"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q drops %d custom external label(s) before sending alerts", resource.Name, count)
		recommendation = "从 alertDropLabels 移除用于路由、归属或环境识别的外部标签；仅删除专用于 HA 副本去重的标签。"
		metadata["thanos_ruler_dropped_external_label_count"] = fmt.Sprintf("%d", count)
	case KubernetesThanosRulerUserNamespaceIsolationAnalyzerID:
		if resource.Metadata["thanos_ruler_host_users_valid"] != "true" || resource.Metadata["thanos_ruler_user_namespace_isolation_enabled"] != "true" {
			return model.Finding{}, false
		}
		findingType = "KubernetesThanosRulerUserNamespaceIsolation"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q enables Pod user namespace isolation with hostUsers=false", resource.Name)
		recommendation = "确认集群至少为 Kubernetes 1.28 且启用了 UserNamespacesSupport，并验证卷、权限、监控和升级兼容性。"
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}
