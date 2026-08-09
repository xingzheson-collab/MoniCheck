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
	KubernetesInvalidThanosRulerRuntimeAnalyzerID           = "builtin.kubernetes_invalid_thanos_ruler_runtime_configuration"
	KubernetesThanosRulerDebugLoggingAnalyzerID             = "builtin.kubernetes_thanos_ruler_debug_logging"
	KubernetesThanosRulerManagedContainerOverrideAnalyzerID = "builtin.kubernetes_thanos_ruler_operator_managed_container_override"
)

type KubernetesThanosRulerRuntimeAnalyzer struct {
	id   string
	name string
}

func NewKubernetesInvalidThanosRulerRuntimeAnalyzer() *KubernetesThanosRulerRuntimeAnalyzer {
	return &KubernetesThanosRulerRuntimeAnalyzer{id: KubernetesInvalidThanosRulerRuntimeAnalyzerID, name: "Kubernetes Invalid ThanosRuler Runtime Configuration"}
}

func NewKubernetesThanosRulerDebugLoggingAnalyzer() *KubernetesThanosRulerRuntimeAnalyzer {
	return &KubernetesThanosRulerRuntimeAnalyzer{id: KubernetesThanosRulerDebugLoggingAnalyzerID, name: "Kubernetes ThanosRuler Debug Logging"}
}

func NewKubernetesThanosRulerManagedContainerOverrideAnalyzer() *KubernetesThanosRulerRuntimeAnalyzer {
	return &KubernetesThanosRulerRuntimeAnalyzer{id: KubernetesThanosRulerManagedContainerOverrideAnalyzerID, name: "Kubernetes ThanosRuler Operator-Managed Container Override"}
}

func (a *KubernetesThanosRulerRuntimeAnalyzer) ID() string      { return a.id }
func (a *KubernetesThanosRulerRuntimeAnalyzer) Name() string    { return a.name }
func (a *KubernetesThanosRulerRuntimeAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesThanosRulerRuntimeAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *KubernetesThanosRulerRuntimeAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || resource.Metadata["kubernetes_kind"] != "ThanosRuler" || resource.Metadata["thanos_ruler_runtime_metadata"] != "true" {
			continue
		}
		if finding, matched := kubernetesThanosRulerRuntimeFinding(a.id, resource, now); matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesThanosRulerRuntimeFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	severity := model.SeverityCritical
	category := model.FindingCategoryConfiguration
	findingType := ""
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": "ThanosRuler", "namespace": kubernetesResourceNamespace(resource)}
	containerInvalidCount := prometheusStorageMetadataInt64(resource, "thanos_ruler_container_invalid_count")
	initContainerInvalidCount := prometheusStorageMetadataInt64(resource, "thanos_ruler_init_container_invalid_count")
	switch analyzerID {
	case KubernetesInvalidThanosRulerRuntimeAnalyzerID:
		listenInvalid := resource.Metadata["thanos_ruler_listen_local_declared"] == "true" && resource.Metadata["thanos_ruler_listen_local_valid"] != "true"
		logLevelInvalid := resource.Metadata["thanos_ruler_log_level_declared"] == "true" && resource.Metadata["thanos_ruler_log_level_valid"] != "true"
		logFormatInvalid := resource.Metadata["thanos_ruler_log_format_declared"] == "true" && resource.Metadata["thanos_ruler_log_format_valid"] != "true"
		if !listenInvalid && !logLevelInvalid && !logFormatInvalid && containerInvalidCount == 0 && initContainerInvalidCount == 0 {
			return model.Finding{}, false
		}
		findingType = "KubernetesInvalidThanosRulerRuntimeConfiguration"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q has invalid runtime settings: listenLocal=%t, logLevel=%t, logFormat=%t, containers=%d, initContainers=%d", resource.Name, listenInvalid, logLevelInvalid, logFormatInvalid, containerInvalidCount, initContainerInvalidCount)
		recommendation = "使用布尔值配置 listenLocal，使用 debug/info/warn/error 日志级别、logfmt/json 格式，并为每个 container/initContainer 配置唯一非空名称。"
		metadata["thanos_ruler_container_invalid_count"] = fmt.Sprintf("%d", containerInvalidCount)
		metadata["thanos_ruler_init_container_invalid_count"] = fmt.Sprintf("%d", initContainerInvalidCount)
	case KubernetesThanosRulerDebugLoggingAnalyzerID:
		if resource.Metadata["thanos_ruler_log_level_valid"] != "true" || resource.Metadata["thanos_ruler_log_level"] != "debug" {
			return model.Finding{}, false
		}
		severity = model.SeverityWarning
		findingType = "KubernetesThanosRulerDebugLogging"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q enables debug logging, increasing log volume and operational detail exposure", resource.Name)
		recommendation = "故障排查结束后恢复 info 或 warn，并为临时 debug 日志设置采集限额、保留周期和访问控制。"
		metadata["thanos_ruler_log_level"] = "debug"
	case KubernetesThanosRulerManagedContainerOverrideAnalyzerID:
		managedContainers := prometheusStorageMetadataInt64(resource, "thanos_ruler_managed_container_override_count")
		managedInitContainers := prometheusStorageMetadataInt64(resource, "thanos_ruler_managed_init_container_override_count")
		if containerInvalidCount > 0 || initContainerInvalidCount > 0 || managedContainers+managedInitContainers == 0 {
			return model.Finding{}, false
		}
		severity = model.SeverityWarning
		category = model.FindingCategoryLifecycle
		findingType = "KubernetesThanosRulerOperatorManagedContainerOverride"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q overrides %d Operator-managed container(s) and %d Operator-managed init container(s)", resource.Name, managedContainers, managedInitContainers)
		recommendation = "优先使用 Operator 专用字段；必须覆盖受管容器时，固定 Operator 版本，并针对升级执行生成 Pod 差异、滚动发布和配置重载回归测试。"
		metadata["thanos_ruler_managed_container_override_count"] = fmt.Sprintf("%d", managedContainers)
		metadata["thanos_ruler_managed_init_container_override_count"] = fmt.Sprintf("%d", managedInitContainers)
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}
