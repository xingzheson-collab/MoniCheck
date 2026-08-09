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
	KubernetesInvalidAlertmanagerConfigSourceAnalyzerID    = "builtin.kubernetes_invalid_alertmanager_config_source"
	KubernetesShadowedAlertmanagerConfigSecretAnalyzerID   = "builtin.kubernetes_shadowed_alertmanager_config_secret"
	KubernetesMissingAlertmanagerConfigurationAnalyzerID   = "builtin.kubernetes_missing_alertmanager_configuration"
	KubernetesSharedAlertmanagerGoverningServiceAnalyzerID = "builtin.kubernetes_shared_alertmanager_governing_service"
)

type KubernetesAlertmanagerConfigSourceAnalyzer struct {
	id   string
	name string
}

func NewKubernetesInvalidAlertmanagerConfigSourceAnalyzer() *KubernetesAlertmanagerConfigSourceAnalyzer {
	return &KubernetesAlertmanagerConfigSourceAnalyzer{id: KubernetesInvalidAlertmanagerConfigSourceAnalyzerID, name: "Kubernetes Invalid Alertmanager Config Source"}
}

func NewKubernetesShadowedAlertmanagerConfigSecretAnalyzer() *KubernetesAlertmanagerConfigSourceAnalyzer {
	return &KubernetesAlertmanagerConfigSourceAnalyzer{id: KubernetesShadowedAlertmanagerConfigSecretAnalyzerID, name: "Kubernetes Shadowed Alertmanager Config Secret"}
}

func NewKubernetesMissingAlertmanagerConfigurationAnalyzer() *KubernetesAlertmanagerConfigSourceAnalyzer {
	return &KubernetesAlertmanagerConfigSourceAnalyzer{id: KubernetesMissingAlertmanagerConfigurationAnalyzerID, name: "Kubernetes Missing Alertmanager Configuration"}
}

func NewKubernetesSharedAlertmanagerGoverningServiceAnalyzer() *KubernetesAlertmanagerConfigSourceAnalyzer {
	return &KubernetesAlertmanagerConfigSourceAnalyzer{id: KubernetesSharedAlertmanagerGoverningServiceAnalyzerID, name: "Kubernetes Shared Alertmanager Governing Service"}
}

func (a *KubernetesAlertmanagerConfigSourceAnalyzer) ID() string      { return a.id }
func (a *KubernetesAlertmanagerConfigSourceAnalyzer) Name() string    { return a.name }
func (a *KubernetesAlertmanagerConfigSourceAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesAlertmanagerConfigSourceAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *KubernetesAlertmanagerConfigSourceAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || resource.Metadata["kubernetes_kind"] != "Alertmanager" || resource.Metadata["alertmanager_config_source_metadata"] != "true" {
			continue
		}
		if finding, matched := kubernetesAlertmanagerConfigSourceFinding(a.id, resource, now); matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesAlertmanagerConfigSourceFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	severity := model.SeverityCritical
	category := model.FindingCategoryConfiguration
	findingType := ""
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": "Alertmanager", "namespace": kubernetesResourceNamespace(resource)}
	switch analyzerID {
	case KubernetesInvalidAlertmanagerConfigSourceAnalyzerID:
		secretInvalid := resource.Metadata["alertmanager_config_secret_declared"] == "true" && resource.Metadata["alertmanager_config_secret_valid"] != "true"
		configurationInvalid := resource.Metadata["alertmanager_configuration_declared"] == "true" && resource.Metadata["alertmanager_configuration_valid"] != "true"
		serviceInvalid := resource.Metadata["alertmanager_service_name_declared"] == "true" && resource.Metadata["alertmanager_service_name_valid"] != "true"
		portInvalid := resource.Metadata["alertmanager_port_name_declared"] == "true" && resource.Metadata["alertmanager_port_name_valid"] != "true"
		if !secretInvalid && !configurationInvalid && !serviceInvalid && !portInvalid {
			return model.Finding{}, false
		}
		findingType = "KubernetesInvalidAlertmanagerConfigSource"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q has malformed config/service fields: configSecret=%t, alertmanagerConfiguration=%t, serviceName=%t, portName=%t", resource.Name, secretInvalid, configurationInvalid, serviceInvalid, portInvalid)
		recommendation = "使用字符串配置 configSecret/serviceName/portName，并为 alertmanagerConfiguration 提供对象形式的非空同命名空间 name。"
	case KubernetesShadowedAlertmanagerConfigSecretAnalyzerID:
		if resource.Metadata["alertmanager_config_source_conflict"] != "true" {
			return model.Finding{}, false
		}
		severity = model.SeverityWarning
		findingType = "KubernetesShadowedAlertmanagerConfigSecret"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q declares both configSecret and alertmanagerConfiguration; the AlertmanagerConfig source takes precedence", resource.Name)
		recommendation = "删除被覆盖的 configSecret 声明，或移除 alertmanagerConfiguration 并明确使用 Secret，确保唯一配置来源和变更审计路径。"
	case KubernetesMissingAlertmanagerConfigurationAnalyzerID:
		if resource.Metadata["alertmanager_configuration_valid"] != "true" || resource.Metadata["alertmanager_configuration_found"] == "true" {
			return model.Finding{}, false
		}
		findingType = "KubernetesMissingAlertmanagerConfiguration"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q references an AlertmanagerConfig that is absent from the imported manifest snapshot", resource.Name)
		recommendation = "导入并创建同命名空间的目标 AlertmanagerConfig，核对名称和 Operator Reconciled 状态，确认生成配置包含有效默认 receiver。"
	case KubernetesSharedAlertmanagerGoverningServiceAnalyzerID:
		sharedCount := alertmanagerStorageMetadataInt64(resource, "alertmanager_shared_service_count")
		serviceInvalid := resource.Metadata["alertmanager_service_name_declared"] == "true" && resource.Metadata["alertmanager_service_name_valid"] != "true"
		if sharedCount == 0 || serviceInvalid {
			return model.Finding{}, false
		}
		severity = model.SeverityWarning
		category = model.FindingCategoryReliability
		findingType = "KubernetesSharedAlertmanagerGoverningService"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q shares its governing Service identity with %d other Alertmanager resource(s) in the namespace", resource.Name, sharedCount)
		recommendation = "为同命名空间的每个 Alertmanager 配置不同 serviceName，并确保对应 headless Service 在 CR 之前创建且 selector 匹配 Pod。"
		metadata["alertmanager_shared_service_count"] = fmt.Sprintf("%d", sharedCount)
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}
