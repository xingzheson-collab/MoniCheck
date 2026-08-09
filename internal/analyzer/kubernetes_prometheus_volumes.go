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
	KubernetesInvalidPrometheusVolumeConfigurationAnalyzerID = "builtin.kubernetes_invalid_prometheus_volume_configuration"
	KubernetesPrometheusHostPathVolumeAnalyzerID             = "builtin.kubernetes_prometheus_host_path_volume"
	KubernetesPrometheusBidirectionalMountAnalyzerID         = "builtin.kubernetes_prometheus_bidirectional_mount_propagation"
)

type KubernetesPrometheusVolumeAnalyzer struct {
	id   string
	name string
}

func NewKubernetesInvalidPrometheusVolumeConfigurationAnalyzer() *KubernetesPrometheusVolumeAnalyzer {
	return &KubernetesPrometheusVolumeAnalyzer{id: KubernetesInvalidPrometheusVolumeConfigurationAnalyzerID, name: "Kubernetes Invalid Prometheus Volume Configuration"}
}

func NewKubernetesPrometheusHostPathVolumeAnalyzer() *KubernetesPrometheusVolumeAnalyzer {
	return &KubernetesPrometheusVolumeAnalyzer{id: KubernetesPrometheusHostPathVolumeAnalyzerID, name: "Kubernetes Prometheus HostPath Volume"}
}

func NewKubernetesPrometheusBidirectionalMountAnalyzer() *KubernetesPrometheusVolumeAnalyzer {
	return &KubernetesPrometheusVolumeAnalyzer{id: KubernetesPrometheusBidirectionalMountAnalyzerID, name: "Kubernetes Prometheus Bidirectional Mount Propagation"}
}

func (a *KubernetesPrometheusVolumeAnalyzer) ID() string      { return a.id }
func (a *KubernetesPrometheusVolumeAnalyzer) Name() string    { return a.name }
func (a *KubernetesPrometheusVolumeAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesPrometheusVolumeAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}

func (a *KubernetesPrometheusVolumeAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTSDB})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		kind := resource.Metadata["kubernetes_kind"]
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || (kind != "Prometheus" && kind != "PrometheusAgent") || resource.Metadata["prometheus_volume_metadata"] != "true" {
			continue
		}
		if finding, matched := kubernetesPrometheusVolumeFinding(a.id, resource, now); matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesPrometheusVolumeFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	invalidCount := prometheusStorageMetadataInt64(resource, "prometheus_volume_invalid_setting_count")
	kind := resource.Metadata["kubernetes_kind"]
	findingType := ""
	evidence := ""
	recommendation := ""
	category := model.FindingCategorySecurity
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": kind, "namespace": kubernetesResourceNamespace(resource)}
	switch analyzerID {
	case KubernetesInvalidPrometheusVolumeConfigurationAnalyzerID:
		if invalidCount == 0 {
			return model.Finding{}, false
		}
		category = model.FindingCategoryConfiguration
		findingType = "KubernetesInvalidPrometheusVolumeConfiguration"
		evidence = fmt.Sprintf("Kubernetes %s %q declares %d invalid additional volume or mount setting(s)", kind, resource.Name, invalidCount)
		recommendation = "为每个 volume 配置唯一非空名称和单一卷源，并为每个 volumeMount 配置非空名称、唯一挂载路径及合法 readOnly/mountPropagation 值。"
		metadata["prometheus_volume_invalid_setting_count"] = fmt.Sprintf("%d", invalidCount)
	case KubernetesPrometheusHostPathVolumeAnalyzerID:
		hostPathCount := prometheusStorageMetadataInt64(resource, "prometheus_host_path_volume_count")
		if invalidCount > 0 || hostPathCount == 0 {
			return model.Finding{}, false
		}
		writableCount := prometheusStorageMetadataInt64(resource, "prometheus_writable_host_path_mount_count")
		findingType = "KubernetesPrometheusHostPathVolume"
		evidence = fmt.Sprintf("Kubernetes %s %q declares %d hostPath volume(s), including %d writable mount(s)", kind, resource.Name, hostPathCount, writableCount)
		recommendation = "移除 hostPath 并改用 Secret、ConfigMap、emptyDir 或 PVC；确需主机目录时限制到专用只读路径、节点和最小权限，并由准入策略显式审批。"
		metadata["prometheus_host_path_volume_count"] = fmt.Sprintf("%d", hostPathCount)
		metadata["prometheus_writable_host_path_mount_count"] = fmt.Sprintf("%d", writableCount)
	case KubernetesPrometheusBidirectionalMountAnalyzerID:
		count := prometheusStorageMetadataInt64(resource, "prometheus_bidirectional_mount_count")
		if invalidCount > 0 || count == 0 {
			return model.Finding{}, false
		}
		findingType = "KubernetesPrometheusBidirectionalMountPropagation"
		evidence = fmt.Sprintf("Kubernetes %s %q declares %d Bidirectional volume mount(s)", kind, resource.Name, count)
		recommendation = "移除 Bidirectional mountPropagation；仅在受控特权组件确有传播回宿主机的需求时使用，并通过 Pod Security、准入策略和节点隔离限制影响范围。"
		metadata["prometheus_bidirectional_mount_count"] = fmt.Sprintf("%d", count)
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: model.SeverityCritical, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}
