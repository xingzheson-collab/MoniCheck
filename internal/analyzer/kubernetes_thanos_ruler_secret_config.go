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
	KubernetesInvalidThanosRulerSecretConfigAnalyzerID  = "builtin.kubernetes_invalid_thanos_ruler_secret_configuration"
	KubernetesShadowedThanosRulerSecretConfigAnalyzerID = "builtin.kubernetes_shadowed_thanos_ruler_secret_configuration"
)

type KubernetesThanosRulerSecretConfigAnalyzer struct {
	id   string
	name string
}

func NewKubernetesInvalidThanosRulerSecretConfigAnalyzer() *KubernetesThanosRulerSecretConfigAnalyzer {
	return &KubernetesThanosRulerSecretConfigAnalyzer{id: KubernetesInvalidThanosRulerSecretConfigAnalyzerID, name: "Kubernetes Invalid ThanosRuler Secret Configuration"}
}
func NewKubernetesShadowedThanosRulerSecretConfigAnalyzer() *KubernetesThanosRulerSecretConfigAnalyzer {
	return &KubernetesThanosRulerSecretConfigAnalyzer{id: KubernetesShadowedThanosRulerSecretConfigAnalyzerID, name: "Kubernetes Shadowed ThanosRuler Secret Configuration"}
}
func (a *KubernetesThanosRulerSecretConfigAnalyzer) ID() string      { return a.id }
func (a *KubernetesThanosRulerSecretConfigAnalyzer) Name() string    { return a.name }
func (a *KubernetesThanosRulerSecretConfigAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesThanosRulerSecretConfigAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *KubernetesThanosRulerSecretConfigAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || resource.Metadata["kubernetes_kind"] != "ThanosRuler" || resource.Metadata["thanos_ruler_secret_config_metadata"] != "true" {
			continue
		}
		if finding, matched := kubernetesThanosRulerSecretConfigFinding(a.id, resource, now); matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesThanosRulerSecretConfigFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	severity := model.SeverityCritical
	findingType := ""
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": "ThanosRuler", "namespace": kubernetesResourceNamespace(resource)}
	invalid := alertmanagerStorageMetadataInt64(resource, "thanos_ruler_secret_config_invalid_setting_count")
	shadowed := alertmanagerStorageMetadataInt64(resource, "thanos_ruler_shadowed_secret_config_count")
	switch analyzerID {
	case KubernetesInvalidThanosRulerSecretConfigAnalyzerID:
		if invalid == 0 {
			return model.Finding{}, false
		}
		findingType = "KubernetesInvalidThanosRulerSecretConfiguration"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q declares %d malformed Secret selector or file configuration setting(s)", resource.Name, invalid)
		recommendation = "为每个 SecretKeySelector 配置合法同命名空间 name、非空 key 和布尔 optional；文件配置必须是非空路径字符串。"
		metadata["thanos_ruler_secret_config_invalid_setting_count"] = fmt.Sprintf("%d", invalid)
	case KubernetesShadowedThanosRulerSecretConfigAnalyzerID:
		if invalid > 0 || shadowed == 0 {
			return model.Finding{}, false
		}
		severity = model.SeverityWarning
		findingType = "KubernetesShadowedThanosRulerSecretConfiguration"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q declares %d lower-precedence Secret or legacy endpoint configuration(s) shadowed by another source", resource.Name, shadowed)
		recommendation = "每类配置只保留 Operator 实际采用的最高优先级来源，删除被文件配置或 Secret 配置覆盖的旧字段，避免审查与运行态不一致。"
		metadata["thanos_ruler_shadowed_secret_config_count"] = fmt.Sprintf("%d", shadowed)
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: model.FindingCategoryConfiguration, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}
