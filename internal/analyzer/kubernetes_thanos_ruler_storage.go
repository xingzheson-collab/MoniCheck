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
	KubernetesInvalidThanosRulerStorageAnalyzerID            = "builtin.kubernetes_invalid_thanos_ruler_storage"
	KubernetesConflictingThanosRulerStorageAnalyzerID        = "builtin.kubernetes_conflicting_thanos_ruler_storage"
	KubernetesEphemeralThanosRulerStorageAnalyzerID          = "builtin.kubernetes_ephemeral_thanos_ruler_storage"
	KubernetesImplicitThanosRulerRetentionAnalyzerID         = "builtin.kubernetes_implicit_thanos_ruler_retention"
	KubernetesInvalidThanosRulerRetentionAnalyzerID          = "builtin.kubernetes_invalid_thanos_ruler_retention"
	KubernetesIgnoredStatelessThanosRulerRetentionAnalyzerID = "builtin.kubernetes_ignored_stateless_thanos_ruler_retention"
)

type KubernetesThanosRulerStorageAnalyzer struct {
	id   string
	name string
}

func NewKubernetesInvalidThanosRulerStorageAnalyzer() *KubernetesThanosRulerStorageAnalyzer {
	return &KubernetesThanosRulerStorageAnalyzer{id: KubernetesInvalidThanosRulerStorageAnalyzerID, name: "Kubernetes Invalid ThanosRuler Storage"}
}
func NewKubernetesConflictingThanosRulerStorageAnalyzer() *KubernetesThanosRulerStorageAnalyzer {
	return &KubernetesThanosRulerStorageAnalyzer{id: KubernetesConflictingThanosRulerStorageAnalyzerID, name: "Kubernetes Conflicting ThanosRuler Storage"}
}
func NewKubernetesEphemeralThanosRulerStorageAnalyzer() *KubernetesThanosRulerStorageAnalyzer {
	return &KubernetesThanosRulerStorageAnalyzer{id: KubernetesEphemeralThanosRulerStorageAnalyzerID, name: "Kubernetes Ephemeral ThanosRuler Storage"}
}
func NewKubernetesImplicitThanosRulerRetentionAnalyzer() *KubernetesThanosRulerStorageAnalyzer {
	return &KubernetesThanosRulerStorageAnalyzer{id: KubernetesImplicitThanosRulerRetentionAnalyzerID, name: "Kubernetes Implicit ThanosRuler Retention"}
}
func NewKubernetesInvalidThanosRulerRetentionAnalyzer() *KubernetesThanosRulerStorageAnalyzer {
	return &KubernetesThanosRulerStorageAnalyzer{id: KubernetesInvalidThanosRulerRetentionAnalyzerID, name: "Kubernetes Invalid ThanosRuler Retention"}
}
func NewKubernetesIgnoredStatelessThanosRulerRetentionAnalyzer() *KubernetesThanosRulerStorageAnalyzer {
	return &KubernetesThanosRulerStorageAnalyzer{id: KubernetesIgnoredStatelessThanosRulerRetentionAnalyzerID, name: "Kubernetes Ignored Stateless ThanosRuler Retention"}
}

func (a *KubernetesThanosRulerStorageAnalyzer) ID() string      { return a.id }
func (a *KubernetesThanosRulerStorageAnalyzer) Name() string    { return a.name }
func (a *KubernetesThanosRulerStorageAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesThanosRulerStorageAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *KubernetesThanosRulerStorageAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || resource.Metadata["kubernetes_kind"] != "ThanosRuler" || resource.Metadata["thanos_ruler_storage_metadata"] != "true" {
			continue
		}
		if finding, matched := kubernetesThanosRulerStorageFinding(a.id, resource, now); matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesThanosRulerStorageFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	invalidCount := alertmanagerStorageMetadataInt64(resource, "thanos_ruler_storage_invalid_setting_count")
	optionCount := alertmanagerStorageMetadataInt64(resource, "thanos_ruler_storage_option_count")
	stateless := resource.Metadata["thanos_ruler_stateless_mode"] == "true"
	severity := model.SeverityCritical
	category := model.FindingCategoryConfiguration
	findingType := ""
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": "ThanosRuler", "namespace": kubernetesResourceNamespace(resource)}
	switch analyzerID {
	case KubernetesInvalidThanosRulerStorageAnalyzerID:
		if invalidCount == 0 {
			return model.Finding{}, false
		}
		findingType = "KubernetesInvalidThanosRulerStorage"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q declares %d malformed storage setting(s)", resource.Name, invalidCount)
		recommendation = "使用合法 StorageSpec 对象和卷选项；使用 volumeClaimTemplate 时配置正数 Kubernetes storage request，并通过 admission dry-run 验证。"
		metadata["thanos_ruler_storage_invalid_setting_count"] = fmt.Sprintf("%d", invalidCount)
	case KubernetesConflictingThanosRulerStorageAnalyzerID:
		if optionCount <= 1 {
			return model.Finding{}, false
		}
		findingType = "KubernetesConflictingThanosRulerStorage"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q declares %d storage options; the Operator applies a precedence order", resource.Name, optionCount)
		recommendation = "仅保留 emptyDir、ephemeral 或 volumeClaimTemplate 中的一种，避免清单意图与实际挂载类型不一致。"
		metadata["thanos_ruler_storage_option_count"] = fmt.Sprintf("%d", optionCount)
	case KubernetesEphemeralThanosRulerStorageAnalyzerID:
		mode := resource.Metadata["thanos_ruler_storage_mode"]
		if invalidCount > 0 || optionCount > 1 || stateless || (mode != "default-empty-dir" && mode != "empty-dir" && mode != "ephemeral") {
			return model.Finding{}, false
		}
		category = model.FindingCategoryReliability
		findingType = "KubernetesEphemeralThanosRulerStorage"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q uses %s storage in stateful mode, so local rule data is lost when a Pod is replaced", resource.Name, mode)
		recommendation = "为需要保留本地规则数据的生产 Ruler 配置有足够容量的 volumeClaimTemplate，或明确采用 remote-write stateless mode。"
		metadata["thanos_ruler_storage_mode"] = mode
	case KubernetesImplicitThanosRulerRetentionAnalyzerID:
		if stateless || resource.Metadata["thanos_ruler_retention_declared"] == "true" {
			return model.Finding{}, false
		}
		severity = model.SeverityWarning
		category = model.FindingCategoryReliability
		findingType = "KubernetesImplicitThanosRulerRetention"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q leaves retention unset in stateful mode and relies on the 24h Operator default", resource.Name)
		recommendation = "显式配置符合规则查询、告警状态恢复和容量目标的 retention，避免默认 24h 窗口不符合预期。"
	case KubernetesInvalidThanosRulerRetentionAnalyzerID:
		if resource.Metadata["thanos_ruler_retention_declared"] != "true" || resource.Metadata["thanos_ruler_retention_valid"] == "true" {
			return model.Finding{}, false
		}
		findingType = "KubernetesInvalidThanosRulerRetention"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q declares a retention value outside the Operator duration format", resource.Name)
		recommendation = "使用正整数和单个 ms、s、m、h、d、w 或 y 单位配置 retention，例如 24h 或 15d。"
		metadata["thanos_ruler_retention_invalid"] = "true"
	case KubernetesIgnoredStatelessThanosRulerRetentionAnalyzerID:
		if !stateless || resource.Metadata["thanos_ruler_retention_declared"] != "true" || resource.Metadata["thanos_ruler_retention_valid"] != "true" {
			return model.Finding{}, false
		}
		severity = model.SeverityWarning
		findingType = "KubernetesIgnoredStatelessThanosRulerRetention"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q declares retention while remoteWrite enables stateless mode, so the retention field has no effect", resource.Name)
		recommendation = "删除无效 retention 以减少配置歧义，或移除 remoteWrite 并为 stateful Ruler 配置持久存储和明确 retention。"
		metadata["thanos_ruler_stateless_mode"] = "true"
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}
