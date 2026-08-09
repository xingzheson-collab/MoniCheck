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
	KubernetesInvalidThanosRulerVolumeConfigurationAnalyzerID = "builtin.kubernetes_invalid_thanos_ruler_volume_configuration"
	KubernetesThanosRulerHostPathVolumeAnalyzerID             = "builtin.kubernetes_thanos_ruler_host_path_volume"
	KubernetesThanosRulerBidirectionalMountAnalyzerID         = "builtin.kubernetes_thanos_ruler_bidirectional_mount_propagation"
)

type KubernetesThanosRulerVolumeAnalyzer struct {
	id   string
	name string
}

func NewKubernetesInvalidThanosRulerVolumeConfigurationAnalyzer() *KubernetesThanosRulerVolumeAnalyzer {
	return &KubernetesThanosRulerVolumeAnalyzer{id: KubernetesInvalidThanosRulerVolumeConfigurationAnalyzerID, name: "Kubernetes Invalid ThanosRuler Volume Configuration"}
}

func NewKubernetesThanosRulerHostPathVolumeAnalyzer() *KubernetesThanosRulerVolumeAnalyzer {
	return &KubernetesThanosRulerVolumeAnalyzer{id: KubernetesThanosRulerHostPathVolumeAnalyzerID, name: "Kubernetes ThanosRuler HostPath Volume"}
}

func NewKubernetesThanosRulerBidirectionalMountAnalyzer() *KubernetesThanosRulerVolumeAnalyzer {
	return &KubernetesThanosRulerVolumeAnalyzer{id: KubernetesThanosRulerBidirectionalMountAnalyzerID, name: "Kubernetes ThanosRuler Bidirectional Mount Propagation"}
}

func (a *KubernetesThanosRulerVolumeAnalyzer) ID() string      { return a.id }
func (a *KubernetesThanosRulerVolumeAnalyzer) Name() string    { return a.name }
func (a *KubernetesThanosRulerVolumeAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesThanosRulerVolumeAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *KubernetesThanosRulerVolumeAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || resource.Metadata["kubernetes_kind"] != "ThanosRuler" || resource.Metadata["thanos_ruler_volume_metadata"] != "true" {
			continue
		}
		if finding, matched := kubernetesThanosRulerVolumeFinding(a.id, resource, now); matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesThanosRulerVolumeFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	invalidCount := alertmanagerStorageMetadataInt64(resource, "thanos_ruler_volume_invalid_setting_count")
	findingType := ""
	evidence := ""
	recommendation := ""
	category := model.FindingCategorySecurity
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": "ThanosRuler", "namespace": kubernetesResourceNamespace(resource)}
	switch analyzerID {
	case KubernetesInvalidThanosRulerVolumeConfigurationAnalyzerID:
		if invalidCount == 0 {
			return model.Finding{}, false
		}
		category = model.FindingCategoryConfiguration
		findingType = "KubernetesInvalidThanosRulerVolumeConfiguration"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q declares %d invalid additional volume or mount setting(s)", resource.Name, invalidCount)
		recommendation = "为每个 volume 配置唯一非空名称和单一卷源，并为每个 volumeMount 配置非空名称、唯一挂载路径及合法 readOnly/mountPropagation 值。"
		metadata["thanos_ruler_volume_invalid_setting_count"] = fmt.Sprintf("%d", invalidCount)
	case KubernetesThanosRulerHostPathVolumeAnalyzerID:
		hostPathCount := alertmanagerStorageMetadataInt64(resource, "thanos_ruler_host_path_volume_count")
		if invalidCount > 0 || hostPathCount == 0 {
			return model.Finding{}, false
		}
		writableCount := alertmanagerStorageMetadataInt64(resource, "thanos_ruler_writable_host_path_mount_count")
		findingType = "KubernetesThanosRulerHostPathVolume"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q declares %d hostPath volume(s), including %d writable mount(s)", resource.Name, hostPathCount, writableCount)
		recommendation = "移除 hostPath 并改用 Secret、ConfigMap、emptyDir 或 PVC；确需主机目录时限制到专用只读路径、节点和最小权限，并由准入策略显式审批。"
		metadata["thanos_ruler_host_path_volume_count"] = fmt.Sprintf("%d", hostPathCount)
		metadata["thanos_ruler_writable_host_path_mount_count"] = fmt.Sprintf("%d", writableCount)
	case KubernetesThanosRulerBidirectionalMountAnalyzerID:
		bidirectionalCount := alertmanagerStorageMetadataInt64(resource, "thanos_ruler_bidirectional_mount_count")
		if invalidCount > 0 || bidirectionalCount == 0 {
			return model.Finding{}, false
		}
		findingType = "KubernetesThanosRulerBidirectionalMountPropagation"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q declares %d Bidirectional volume mount(s)", resource.Name, bidirectionalCount)
		recommendation = "移除 Bidirectional mountPropagation；仅在受控特权组件确有传播回宿主机的需求时使用，并通过 Pod Security、准入策略和节点隔离限制影响范围。"
		metadata["thanos_ruler_bidirectional_mount_count"] = fmt.Sprintf("%d", bidirectionalCount)
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: model.SeverityCritical, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}
