package analyzer

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	KubernetesInvalidRemoteReadDestinationAnalyzerID = "builtin.kubernetes_invalid_remote_read_destination"
	KubernetesInsecureRemoteReadAnalyzerID           = "builtin.kubernetes_insecure_remote_read"
	KubernetesConflictingRemoteReadAuthAnalyzerID    = "builtin.kubernetes_conflicting_remote_read_auth"
	KubernetesDuplicateRemoteReadNameAnalyzerID      = "builtin.kubernetes_duplicate_remote_read_name"
	KubernetesBroadRemoteReadAnalyzerID              = "builtin.kubernetes_broad_remote_read"
	KubernetesCleartextRemoteReadBearerAnalyzerID    = "builtin.kubernetes_cleartext_remote_read_bearer"
)

type KubernetesInvalidRemoteReadDestinationAnalyzer struct{}
type KubernetesInsecureRemoteReadAnalyzer struct{}
type KubernetesConflictingRemoteReadAuthAnalyzer struct{}
type KubernetesDuplicateRemoteReadNameAnalyzer struct{}
type KubernetesBroadRemoteReadAnalyzer struct{}
type KubernetesCleartextRemoteReadBearerAnalyzer struct{}

func NewKubernetesInvalidRemoteReadDestinationAnalyzer() *KubernetesInvalidRemoteReadDestinationAnalyzer {
	return &KubernetesInvalidRemoteReadDestinationAnalyzer{}
}
func NewKubernetesInsecureRemoteReadAnalyzer() *KubernetesInsecureRemoteReadAnalyzer {
	return &KubernetesInsecureRemoteReadAnalyzer{}
}
func NewKubernetesConflictingRemoteReadAuthAnalyzer() *KubernetesConflictingRemoteReadAuthAnalyzer {
	return &KubernetesConflictingRemoteReadAuthAnalyzer{}
}
func NewKubernetesDuplicateRemoteReadNameAnalyzer() *KubernetesDuplicateRemoteReadNameAnalyzer {
	return &KubernetesDuplicateRemoteReadNameAnalyzer{}
}
func NewKubernetesBroadRemoteReadAnalyzer() *KubernetesBroadRemoteReadAnalyzer {
	return &KubernetesBroadRemoteReadAnalyzer{}
}
func NewKubernetesCleartextRemoteReadBearerAnalyzer() *KubernetesCleartextRemoteReadBearerAnalyzer {
	return &KubernetesCleartextRemoteReadBearerAnalyzer{}
}

func (a *KubernetesInvalidRemoteReadDestinationAnalyzer) ID() string {
	return KubernetesInvalidRemoteReadDestinationAnalyzerID
}
func (a *KubernetesInvalidRemoteReadDestinationAnalyzer) Name() string {
	return "Kubernetes Invalid RemoteRead Destination"
}
func (a *KubernetesInvalidRemoteReadDestinationAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesInvalidRemoteReadDestinationAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeDatasource}
}
func (a *KubernetesInvalidRemoteReadDestinationAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return kubernetesRemoteReadDatasourceFindings(ctx, analysis, a.ID())
}

func (a *KubernetesInsecureRemoteReadAnalyzer) ID() string {
	return KubernetesInsecureRemoteReadAnalyzerID
}
func (a *KubernetesInsecureRemoteReadAnalyzer) Name() string {
	return "Kubernetes Insecure RemoteRead Transport"
}
func (a *KubernetesInsecureRemoteReadAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesInsecureRemoteReadAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeDatasource}
}
func (a *KubernetesInsecureRemoteReadAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return kubernetesRemoteReadDatasourceFindings(ctx, analysis, a.ID())
}

func (a *KubernetesConflictingRemoteReadAuthAnalyzer) ID() string {
	return KubernetesConflictingRemoteReadAuthAnalyzerID
}
func (a *KubernetesConflictingRemoteReadAuthAnalyzer) Name() string {
	return "Kubernetes Conflicting RemoteRead Authentication"
}
func (a *KubernetesConflictingRemoteReadAuthAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesConflictingRemoteReadAuthAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeDatasource}
}
func (a *KubernetesConflictingRemoteReadAuthAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return kubernetesRemoteReadDatasourceFindings(ctx, analysis, a.ID())
}

func (a *KubernetesBroadRemoteReadAnalyzer) ID() string      { return KubernetesBroadRemoteReadAnalyzerID }
func (a *KubernetesBroadRemoteReadAnalyzer) Name() string    { return "Kubernetes Broad RemoteRead" }
func (a *KubernetesBroadRemoteReadAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesBroadRemoteReadAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeDatasource}
}
func (a *KubernetesBroadRemoteReadAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return kubernetesRemoteReadDatasourceFindings(ctx, analysis, a.ID())
}

func (a *KubernetesCleartextRemoteReadBearerAnalyzer) ID() string {
	return KubernetesCleartextRemoteReadBearerAnalyzerID
}
func (a *KubernetesCleartextRemoteReadBearerAnalyzer) Name() string {
	return "Kubernetes Cleartext RemoteRead Bearer Token"
}
func (a *KubernetesCleartextRemoteReadBearerAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesCleartextRemoteReadBearerAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeDatasource}
}
func (a *KubernetesCleartextRemoteReadBearerAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return kubernetesRemoteReadDatasourceFindings(ctx, analysis, a.ID())
}

func kubernetesRemoteReadDatasourceFindings(ctx context.Context, analysis Context, analyzerID string) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeDatasource})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || resource.Metadata["kubernetes_kind"] != "RemoteRead" {
			continue
		}
		finding, matched := kubernetesRemoteReadFinding(analyzerID, resource, now)
		if matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesRemoteReadFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	severity := model.SeverityCritical
	category := model.FindingCategoryConfiguration
	findingType := ""
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": analyzerID, "namespace": resource.Metadata["namespace"]}
	switch analyzerID {
	case KubernetesInvalidRemoteReadDestinationAnalyzerID:
		if resource.Metadata["remote_read_destination_declared"] == "true" && resource.Metadata["remote_read_url_valid"] == "true" {
			return model.Finding{}, false
		}
		findingType = "KubernetesInvalidRemoteReadDestination"
		category = model.FindingCategoryReliability
		evidence = fmt.Sprintf("Kubernetes RemoteRead %q has no valid HTTP/HTTPS destination", resource.Name)
		recommendation = "配置有效的 HTTPS remote read URL，并确认 Operator 已成功生成配置。"
	case KubernetesInsecureRemoteReadAnalyzerID:
		if resource.Metadata["remote_read_url_scheme"] != "http" && resource.Metadata["remote_read_tls_insecure"] != "true" {
			return model.Finding{}, false
		}
		findingType = "KubernetesInsecureRemoteRead"
		severity = model.SeverityWarning
		category = model.FindingCategorySecurity
		evidence = fmt.Sprintf("Kubernetes RemoteRead %q uses plaintext HTTP or disables TLS certificate verification", resource.Name)
		recommendation = "使用 HTTPS、启用服务端证书校验并配置可信 CA，避免查询和认证信息暴露。"
	case KubernetesConflictingRemoteReadAuthAnalyzerID:
		count := remoteReadMetadataInt(resource, "remote_read_auth_method_count")
		if count <= 1 {
			return model.Finding{}, false
		}
		findingType = "KubernetesConflictingRemoteReadAuth"
		evidence = fmt.Sprintf("Kubernetes RemoteRead %q declares %d mutually exclusive authentication methods", resource.Name, count)
		recommendation = "仅保留 authorization、basicAuth、oauth2 或兼容 bearer 配置中的一种，并优先使用非弃用的 Secret 引用方式。"
		metadata["remote_read_auth_method_count"] = strconv.Itoa(count)
	case KubernetesBroadRemoteReadAnalyzerID:
		if resource.Metadata["remote_read_read_recent"] != "true" || resource.Metadata["remote_read_filter_external_labels_declared"] != "true" || resource.Metadata["remote_read_filter_external_labels"] != "false" || remoteReadMetadataInt(resource, "remote_read_required_matcher_count") != 0 {
			return model.Finding{}, false
		}
		findingType = "KubernetesBroadRemoteRead"
		severity = model.SeverityWarning
		category = model.FindingCategoryCost
		evidence = fmt.Sprintf("Kubernetes RemoteRead %q reads recent data without external-label filtering or required matchers", resource.Name)
		recommendation = "启用 filterExternalLabels，或配置 requiredMatchers 限定远端查询范围；仅在确有实时远端读取需求时启用 readRecent。"
	case KubernetesCleartextRemoteReadBearerAnalyzerID:
		if resource.Metadata["remote_read_cleartext_bearer_declared"] != "true" {
			return model.Finding{}, false
		}
		findingType = "KubernetesCleartextRemoteReadBearer"
		category = model.FindingCategorySecurity
		evidence = fmt.Sprintf("Kubernetes RemoteRead %q declares the deprecated cleartext bearerToken field", resource.Name)
		recommendation = "删除清单中的明文 bearerToken，改用 authorization.credentials 的 SecretKeySelector。"
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}

func (a *KubernetesDuplicateRemoteReadNameAnalyzer) ID() string {
	return KubernetesDuplicateRemoteReadNameAnalyzerID
}
func (a *KubernetesDuplicateRemoteReadNameAnalyzer) Name() string {
	return "Kubernetes Duplicate RemoteRead Name"
}
func (a *KubernetesDuplicateRemoteReadNameAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesDuplicateRemoteReadNameAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}
func (a *KubernetesDuplicateRemoteReadNameAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTSDB})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		count := remoteReadMetadataInt(resource, "remote_read_duplicate_name_count")
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || resource.Metadata["kubernetes_kind"] != "Prometheus" || count == 0 {
			continue
		}
		findings = append(findings, model.Finding{ID: model.StableID(a.ID(), resource.ID), Type: "KubernetesDuplicateRemoteReadName", Severity: model.SeverityCritical, Category: model.FindingCategoryConfiguration, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{fmt.Sprintf("Kubernetes Prometheus %q has %d duplicate declared remote read name(s)", resource.Name, count)}, Recommendation: "为 Prometheus remoteRead 条目配置唯一的非空 name，确保运行指标和生成配置可以明确区分。", Metadata: map[string]string{"analyzer_id": a.ID(), "namespace": resource.Metadata["namespace"], "remote_read_duplicate_name_count": strconv.Itoa(count)}, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now})
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func remoteReadMetadataInt(resource model.Resource, key string) int {
	value, err := strconv.Atoi(strings.TrimSpace(resource.Metadata[key]))
	if err != nil {
		return 0
	}
	return value
}
