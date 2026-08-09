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
	KubernetesInvalidThanosRulerEvaluationAnalyzerID       = "builtin.kubernetes_invalid_thanos_ruler_evaluation_configuration"
	KubernetesUnsupportedThanosRulerEvaluationAnalyzerID   = "builtin.kubernetes_unsupported_thanos_ruler_evaluation_version"
	KubernetesInconsistentThanosRulerRestorationAnalyzerID = "builtin.kubernetes_inconsistent_thanos_ruler_restoration_timing"
)

type KubernetesThanosRulerEvaluationAnalyzer struct {
	id   string
	name string
}

func NewKubernetesInvalidThanosRulerEvaluationAnalyzer() *KubernetesThanosRulerEvaluationAnalyzer {
	return &KubernetesThanosRulerEvaluationAnalyzer{id: KubernetesInvalidThanosRulerEvaluationAnalyzerID, name: "Kubernetes Invalid ThanosRuler Evaluation Configuration"}
}
func NewKubernetesUnsupportedThanosRulerEvaluationAnalyzer() *KubernetesThanosRulerEvaluationAnalyzer {
	return &KubernetesThanosRulerEvaluationAnalyzer{id: KubernetesUnsupportedThanosRulerEvaluationAnalyzerID, name: "Kubernetes Unsupported ThanosRuler Evaluation Version"}
}
func NewKubernetesInconsistentThanosRulerRestorationAnalyzer() *KubernetesThanosRulerEvaluationAnalyzer {
	return &KubernetesThanosRulerEvaluationAnalyzer{id: KubernetesInconsistentThanosRulerRestorationAnalyzerID, name: "Kubernetes Inconsistent ThanosRuler Restoration Timing"}
}
func (a *KubernetesThanosRulerEvaluationAnalyzer) ID() string      { return a.id }
func (a *KubernetesThanosRulerEvaluationAnalyzer) Name() string    { return a.name }
func (a *KubernetesThanosRulerEvaluationAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesThanosRulerEvaluationAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *KubernetesThanosRulerEvaluationAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || resource.Metadata["kubernetes_kind"] != "ThanosRuler" || resource.Metadata["thanos_ruler_evaluation_metadata"] != "true" {
			continue
		}
		if finding, matched := kubernetesThanosRulerEvaluationFinding(a.id, resource, now); matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesThanosRulerEvaluationFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	severity := model.SeverityCritical
	findingType := ""
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": "ThanosRuler", "namespace": kubernetesResourceNamespace(resource)}
	invalid := alertmanagerStorageMetadataInt64(resource, "thanos_ruler_evaluation_invalid_setting_count")
	unsupported := alertmanagerStorageMetadataInt64(resource, "thanos_ruler_evaluation_unsupported_setting_count")
	switch analyzerID {
	case KubernetesInvalidThanosRulerEvaluationAnalyzerID:
		if invalid == 0 {
			return model.Finding{}, false
		}
		findingType = "KubernetesInvalidThanosRulerEvaluationConfiguration"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q declares %d invalid evaluation duration or concurrency setting(s)", resource.Name, invalid)
		recommendation = "使用正 Prometheus duration 配置评估/恢复时序，并将 ruleConcurrentEval 配置为正 int32。"
		metadata["thanos_ruler_evaluation_invalid_setting_count"] = fmt.Sprintf("%d", invalid)
	case KubernetesUnsupportedThanosRulerEvaluationAnalyzerID:
		if unsupported == 0 {
			return model.Finding{}, false
		}
		findingType = "KubernetesUnsupportedThanosRulerEvaluationVersion"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q declares version %q with %d evaluation setting(s) requiring a newer Thanos release", resource.Name, resource.Metadata["thanos_ruler_version"], unsupported)
		recommendation = "按字段升级 Thanos：状态恢复时序至少 0.30、并发评估至少 0.37、查询偏移至少 0.38；否则移除不受支持字段。"
		metadata["thanos_ruler_evaluation_unsupported_setting_count"] = fmt.Sprintf("%d", unsupported)
	case KubernetesInconsistentThanosRulerRestorationAnalyzerID:
		if invalid > 0 || resource.Metadata["thanos_ruler_restoration_timing_inconsistent"] != "true" {
			return model.Finding{}, false
		}
		severity = model.SeverityWarning
		findingType = "KubernetesInconsistentThanosRulerRestorationTiming"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q sets ruleGracePeriod longer than ruleOutageTolerance", resource.Name)
		recommendation = "将 ruleGracePeriod 控制在 ruleOutageTolerance 以内，并通过重启/短时中断演练验证告警 for 状态恢复。"
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: model.FindingCategoryReliability, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}
