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
	KubernetesInvalidPrometheusRuntimeConfigurationAnalyzerID = "builtin.kubernetes_invalid_prometheus_runtime_configuration"
	KubernetesPrometheusDebugLoggingAnalyzerID                = "builtin.kubernetes_prometheus_debug_logging"
	KubernetesExternalPrometheusLoopbackOnlyAnalyzerID        = "builtin.kubernetes_external_prometheus_loopback_only"
	KubernetesPrometheusManagedContainerOverrideAnalyzerID    = "builtin.kubernetes_prometheus_operator_managed_container_override"
)

type KubernetesPrometheusRuntimeAnalyzer struct {
	id   string
	name string
}

func NewKubernetesInvalidPrometheusRuntimeConfigurationAnalyzer() *KubernetesPrometheusRuntimeAnalyzer {
	return &KubernetesPrometheusRuntimeAnalyzer{id: KubernetesInvalidPrometheusRuntimeConfigurationAnalyzerID, name: "Kubernetes Invalid Prometheus Runtime Configuration"}
}

func NewKubernetesPrometheusDebugLoggingAnalyzer() *KubernetesPrometheusRuntimeAnalyzer {
	return &KubernetesPrometheusRuntimeAnalyzer{id: KubernetesPrometheusDebugLoggingAnalyzerID, name: "Kubernetes Prometheus Debug Logging"}
}

func NewKubernetesExternalPrometheusLoopbackOnlyAnalyzer() *KubernetesPrometheusRuntimeAnalyzer {
	return &KubernetesPrometheusRuntimeAnalyzer{id: KubernetesExternalPrometheusLoopbackOnlyAnalyzerID, name: "Kubernetes External Prometheus Loopback Only"}
}

func NewKubernetesPrometheusManagedContainerOverrideAnalyzer() *KubernetesPrometheusRuntimeAnalyzer {
	return &KubernetesPrometheusRuntimeAnalyzer{id: KubernetesPrometheusManagedContainerOverrideAnalyzerID, name: "Kubernetes Prometheus Operator-Managed Container Override"}
}

func (a *KubernetesPrometheusRuntimeAnalyzer) ID() string      { return a.id }
func (a *KubernetesPrometheusRuntimeAnalyzer) Name() string    { return a.name }
func (a *KubernetesPrometheusRuntimeAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesPrometheusRuntimeAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}

func (a *KubernetesPrometheusRuntimeAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTSDB})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		kind := resource.Metadata["kubernetes_kind"]
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || (kind != "Prometheus" && kind != "PrometheusAgent") || resource.Metadata["prometheus_runtime_metadata"] != "true" {
			continue
		}
		if finding, matched := kubernetesPrometheusRuntimeFinding(a.id, resource, now); matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesPrometheusRuntimeFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	kind := resource.Metadata["kubernetes_kind"]
	severity := model.SeverityCritical
	category := model.FindingCategoryConfiguration
	findingType := ""
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": kind, "namespace": kubernetesResourceNamespace(resource)}
	containerInvalidCount := prometheusStorageMetadataInt64(resource, "prometheus_container_invalid_count")
	initContainerInvalidCount := prometheusStorageMetadataInt64(resource, "prometheus_init_container_invalid_count")
	switch analyzerID {
	case KubernetesInvalidPrometheusRuntimeConfigurationAnalyzerID:
		listenInvalid := resource.Metadata["prometheus_listen_local_declared"] == "true" && resource.Metadata["prometheus_listen_local_valid"] != "true"
		logLevelInvalid := resource.Metadata["prometheus_log_level_declared"] == "true" && resource.Metadata["prometheus_log_level_valid"] != "true"
		logFormatInvalid := resource.Metadata["prometheus_log_format_declared"] == "true" && resource.Metadata["prometheus_log_format_valid"] != "true"
		if !listenInvalid && !logLevelInvalid && !logFormatInvalid && containerInvalidCount == 0 && initContainerInvalidCount == 0 {
			return model.Finding{}, false
		}
		findingType = "KubernetesInvalidPrometheusRuntimeConfiguration"
		evidence = fmt.Sprintf("Kubernetes %s %q has invalid runtime settings: listenLocal=%t, logLevel=%t, logFormat=%t, containers=%d, initContainers=%d", kind, resource.Name, listenInvalid, logLevelInvalid, logFormatInvalid, containerInvalidCount, initContainerInvalidCount)
		recommendation = "使用布尔值配置 listenLocal，使用 debug/info/warn/error 日志级别、logfmt/json 格式，并为每个 container/initContainer 配置非空名称。"
		metadata["prometheus_container_invalid_count"] = fmt.Sprintf("%d", containerInvalidCount)
		metadata["prometheus_init_container_invalid_count"] = fmt.Sprintf("%d", initContainerInvalidCount)
	case KubernetesPrometheusDebugLoggingAnalyzerID:
		if resource.Metadata["prometheus_log_level_valid"] != "true" || resource.Metadata["prometheus_log_level"] != "debug" {
			return model.Finding{}, false
		}
		severity = model.SeverityWarning
		findingType = "KubernetesPrometheusDebugLogging"
		evidence = fmt.Sprintf("Kubernetes %s %q enables debug logging, increasing log volume and operational detail exposure", kind, resource.Name)
		recommendation = "故障排查结束后恢复 info 或 warn，并为临时 debug 日志设置采集限额、保留周期和访问控制。"
		metadata["prometheus_log_level"] = "debug"
	case KubernetesExternalPrometheusLoopbackOnlyAnalyzerID:
		if resource.Metadata["prometheus_listen_local_valid"] != "true" || resource.Metadata["prometheus_listen_local_enabled"] != "true" || resource.Metadata["prometheus_external_url_valid"] != "true" || containerInvalidCount > 0 || prometheusStorageMetadataInt64(resource, "prometheus_sidecar_container_count") > 0 {
			return model.Finding{}, false
		}
		severity = model.SeverityWarning
		category = model.FindingCategoryReliability
		findingType = "KubernetesExternalPrometheusLoopbackOnly"
		evidence = fmt.Sprintf("Kubernetes %s %q declares an external URL but binds its UI/API to loopback with no declared proxy sidecar", kind, resource.Name)
		recommendation = "声明并验证认证代理 sidecar，或关闭 listenLocal 让 Service 可访问 Pod API；若由自动注入代理提供访问，请确认注入策略和健康检查。"
		metadata["prometheus_external_url_scheme"] = resource.Metadata["prometheus_external_url_scheme"]
	case KubernetesPrometheusManagedContainerOverrideAnalyzerID:
		managedContainers := prometheusStorageMetadataInt64(resource, "prometheus_managed_container_override_count")
		managedInitContainers := prometheusStorageMetadataInt64(resource, "prometheus_managed_init_container_override_count")
		if containerInvalidCount > 0 || initContainerInvalidCount > 0 || managedContainers+managedInitContainers == 0 {
			return model.Finding{}, false
		}
		severity = model.SeverityWarning
		category = model.FindingCategoryLifecycle
		findingType = "KubernetesPrometheusOperatorManagedContainerOverride"
		evidence = fmt.Sprintf("Kubernetes %s %q overrides %d Operator-managed container(s) and %d Operator-managed init container(s)", kind, resource.Name, managedContainers, managedInitContainers)
		recommendation = "优先使用 Operator 专用字段；必须覆盖受管容器时，固定 Operator 版本，针对升级执行生成 Pod 差异、滚动发布和配置重载回归测试。"
		metadata["prometheus_managed_container_override_count"] = fmt.Sprintf("%d", managedContainers)
		metadata["prometheus_managed_init_container_override_count"] = fmt.Sprintf("%d", managedInitContainers)
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}
