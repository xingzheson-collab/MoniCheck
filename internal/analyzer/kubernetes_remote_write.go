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
	KubernetesInvalidRemoteWriteDestinationAnalyzerID = "builtin.kubernetes_invalid_remote_write_destination"
	KubernetesInsecureRemoteWriteAnalyzerID           = "builtin.kubernetes_insecure_remote_write"
	KubernetesConflictingRemoteWriteAuthAnalyzerID    = "builtin.kubernetes_conflicting_remote_write_auth"
	KubernetesInvalidRemoteWriteQueueAnalyzerID       = "builtin.kubernetes_invalid_remote_write_queue"
	KubernetesDuplicateRemoteWriteNameAnalyzerID      = "builtin.kubernetes_duplicate_remote_write_name"
	KubernetesRemoteWriteNotSelectedAnalyzerID        = "builtin.kubernetes_remote_write_not_selected"
)

type KubernetesInvalidRemoteWriteDestinationAnalyzer struct{}
type KubernetesInsecureRemoteWriteAnalyzer struct{}
type KubernetesConflictingRemoteWriteAuthAnalyzer struct{}
type KubernetesInvalidRemoteWriteQueueAnalyzer struct{}
type KubernetesDuplicateRemoteWriteNameAnalyzer struct{}
type KubernetesRemoteWriteNotSelectedAnalyzer struct{}

func NewKubernetesInvalidRemoteWriteDestinationAnalyzer() *KubernetesInvalidRemoteWriteDestinationAnalyzer {
	return &KubernetesInvalidRemoteWriteDestinationAnalyzer{}
}
func NewKubernetesInsecureRemoteWriteAnalyzer() *KubernetesInsecureRemoteWriteAnalyzer {
	return &KubernetesInsecureRemoteWriteAnalyzer{}
}
func NewKubernetesConflictingRemoteWriteAuthAnalyzer() *KubernetesConflictingRemoteWriteAuthAnalyzer {
	return &KubernetesConflictingRemoteWriteAuthAnalyzer{}
}
func NewKubernetesInvalidRemoteWriteQueueAnalyzer() *KubernetesInvalidRemoteWriteQueueAnalyzer {
	return &KubernetesInvalidRemoteWriteQueueAnalyzer{}
}
func NewKubernetesDuplicateRemoteWriteNameAnalyzer() *KubernetesDuplicateRemoteWriteNameAnalyzer {
	return &KubernetesDuplicateRemoteWriteNameAnalyzer{}
}
func NewKubernetesRemoteWriteNotSelectedAnalyzer() *KubernetesRemoteWriteNotSelectedAnalyzer {
	return &KubernetesRemoteWriteNotSelectedAnalyzer{}
}

func (a *KubernetesInvalidRemoteWriteDestinationAnalyzer) ID() string {
	return KubernetesInvalidRemoteWriteDestinationAnalyzerID
}
func (a *KubernetesInvalidRemoteWriteDestinationAnalyzer) Name() string {
	return "Kubernetes Invalid RemoteWrite Destination"
}
func (a *KubernetesInvalidRemoteWriteDestinationAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesInvalidRemoteWriteDestinationAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeExporter}
}
func (a *KubernetesInvalidRemoteWriteDestinationAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return kubernetesRemoteWriteExporterFindings(ctx, analysis, a.ID())
}

func (a *KubernetesInsecureRemoteWriteAnalyzer) ID() string {
	return KubernetesInsecureRemoteWriteAnalyzerID
}
func (a *KubernetesInsecureRemoteWriteAnalyzer) Name() string {
	return "Kubernetes Insecure RemoteWrite Transport"
}
func (a *KubernetesInsecureRemoteWriteAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesInsecureRemoteWriteAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeExporter}
}
func (a *KubernetesInsecureRemoteWriteAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return kubernetesRemoteWriteExporterFindings(ctx, analysis, a.ID())
}

func (a *KubernetesConflictingRemoteWriteAuthAnalyzer) ID() string {
	return KubernetesConflictingRemoteWriteAuthAnalyzerID
}
func (a *KubernetesConflictingRemoteWriteAuthAnalyzer) Name() string {
	return "Kubernetes Conflicting RemoteWrite Authentication"
}
func (a *KubernetesConflictingRemoteWriteAuthAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesConflictingRemoteWriteAuthAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeExporter}
}
func (a *KubernetesConflictingRemoteWriteAuthAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return kubernetesRemoteWriteExporterFindings(ctx, analysis, a.ID())
}

func (a *KubernetesInvalidRemoteWriteQueueAnalyzer) ID() string {
	return KubernetesInvalidRemoteWriteQueueAnalyzerID
}
func (a *KubernetesInvalidRemoteWriteQueueAnalyzer) Name() string {
	return "Kubernetes Invalid RemoteWrite Queue"
}
func (a *KubernetesInvalidRemoteWriteQueueAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesInvalidRemoteWriteQueueAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeExporter}
}
func (a *KubernetesInvalidRemoteWriteQueueAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return kubernetesRemoteWriteExporterFindings(ctx, analysis, a.ID())
}

func (a *KubernetesRemoteWriteNotSelectedAnalyzer) ID() string {
	return KubernetesRemoteWriteNotSelectedAnalyzerID
}
func (a *KubernetesRemoteWriteNotSelectedAnalyzer) Name() string {
	return "Kubernetes RemoteWrite CRD Not Selected"
}
func (a *KubernetesRemoteWriteNotSelectedAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesRemoteWriteNotSelectedAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeExporter}
}
func (a *KubernetesRemoteWriteNotSelectedAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return kubernetesRemoteWriteExporterFindings(ctx, analysis, a.ID())
}

func kubernetesRemoteWriteExporterFindings(ctx context.Context, analysis Context, analyzerID string) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeExporter})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || resource.Metadata["kubernetes_kind"] != "RemoteWrite" {
			continue
		}
		finding, matched := kubernetesRemoteWriteFinding(analyzerID, resource, now)
		if matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesRemoteWriteFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	severity := model.SeverityCritical
	category := model.FindingCategoryConfiguration
	findingType := ""
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": analyzerID, "namespace": resource.Metadata["namespace"], "remote_write_origin": resource.Metadata["remote_write_origin"]}
	switch analyzerID {
	case KubernetesInvalidRemoteWriteDestinationAnalyzerID:
		if resource.Metadata["remote_write_destination_declared"] == "true" && resource.Metadata["remote_write_url_valid"] == "true" {
			return model.Finding{}, false
		}
		findingType = "KubernetesInvalidRemoteWriteDestination"
		category = model.FindingCategoryReliability
		evidence = fmt.Sprintf("Kubernetes RemoteWrite %q has no valid HTTP/HTTPS destination", resource.Name)
		recommendation = "配置有效的 HTTPS remote write URL，并确认 Operator 已成功生成配置；不要在清单中遗漏目标或使用非 HTTP(S) scheme。"
		metadata["remote_write_destination_declared"] = resource.Metadata["remote_write_destination_declared"]
		metadata["remote_write_url_scheme"] = resource.Metadata["remote_write_url_scheme"]
	case KubernetesInsecureRemoteWriteAnalyzerID:
		if resource.Metadata["remote_write_url_scheme"] != "http" && resource.Metadata["remote_write_tls_insecure"] != "true" {
			return model.Finding{}, false
		}
		findingType = "KubernetesInsecureRemoteWrite"
		severity = model.SeverityWarning
		category = model.FindingCategorySecurity
		evidence = fmt.Sprintf("Kubernetes RemoteWrite %q uses plaintext HTTP or disables TLS certificate verification", resource.Name)
		recommendation = "使用 HTTPS、启用服务端证书校验并配置可信 CA，避免指标、租户 Header 或认证信息在传输中被窃取或篡改。"
		metadata["remote_write_url_scheme"] = resource.Metadata["remote_write_url_scheme"]
		metadata["remote_write_tls_insecure"] = resource.Metadata["remote_write_tls_insecure"]
	case KubernetesConflictingRemoteWriteAuthAnalyzerID:
		count := kubernetesRemoteWriteMetadataInt(resource, "remote_write_auth_method_count")
		if count <= 1 {
			return model.Finding{}, false
		}
		findingType = "KubernetesConflictingRemoteWriteAuth"
		evidence = fmt.Sprintf("Kubernetes RemoteWrite %q declares %d mutually exclusive authentication methods", resource.Name, count)
		recommendation = "仅保留 authorization、basicAuth、oauth2、sigv4、azureAd 或兼容 bearer 配置中的一种，并优先使用非弃用的 Secret 引用方式。"
		metadata["remote_write_auth_method_count"] = strconv.Itoa(count)
	case KubernetesInvalidRemoteWriteQueueAnalyzerID:
		reasons := invalidKubernetesRemoteWriteQueueReasons(resource)
		if len(reasons) == 0 {
			return model.Finding{}, false
		}
		findingType = "KubernetesInvalidRemoteWriteQueue"
		evidence = fmt.Sprintf("Kubernetes RemoteWrite %q has invalid queue settings: %s", resource.Name, strings.Join(reasons, ", "))
		recommendation = "使用正数配置 capacity、minShards、maxShards 和 maxSamplesPerSend，并确保 minShards 不大于 maxShards。"
		metadata["remote_write_queue_issue_count"] = strconv.Itoa(len(reasons))
	case KubernetesRemoteWriteNotSelectedAnalyzerID:
		if resource.Metadata["remote_write_origin"] != "crd" || resource.Metadata["remote_write_selection_evaluable"] != "true" || resource.Metadata["remote_write_selected_count"] != "0" {
			return model.Finding{}, false
		}
		findingType = "KubernetesRemoteWriteNotSelected"
		severity = model.SeverityWarning
		category = model.FindingCategoryReliability
		evidence = fmt.Sprintf("Kubernetes RemoteWrite CRD %q is selected by no imported Prometheus or PrometheusAgent workload", resource.Name)
		recommendation = "检查 workload 的 remoteWriteSelector、remoteWriteNamespaceSelector、Namespace 标签和 RemoteWrite 标签，或删除不再使用的 CRD。"
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}

func (a *KubernetesDuplicateRemoteWriteNameAnalyzer) ID() string {
	return KubernetesDuplicateRemoteWriteNameAnalyzerID
}
func (a *KubernetesDuplicateRemoteWriteNameAnalyzer) Name() string {
	return "Kubernetes Duplicate RemoteWrite Name"
}
func (a *KubernetesDuplicateRemoteWriteNameAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesDuplicateRemoteWriteNameAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB, model.ResourceTypeInstance}
}
func (a *KubernetesDuplicateRemoteWriteNameAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		kind := resource.Metadata["kubernetes_kind"]
		count := kubernetesRemoteWriteMetadataInt(resource, "remote_write_duplicate_name_count")
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || (kind != "Prometheus" && kind != "PrometheusAgent" && kind != "ThanosRuler") || count == 0 {
			continue
		}
		findings = append(findings, model.Finding{ID: model.StableID(a.ID(), resource.ID), Type: "KubernetesDuplicateRemoteWriteName", Severity: model.SeverityCritical, Category: model.FindingCategoryConfiguration, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{fmt.Sprintf("Kubernetes %s %q has %d duplicate declared remote write queue name(s)", kind, resource.Name, count)}, Recommendation: "为 workload 的 inline 和选中 RemoteWrite CRD 配置全局唯一的非空 name，确保队列指标、日志和生成配置可以明确区分。", Metadata: map[string]string{"analyzer_id": a.ID(), "kubernetes_kind": kind, "namespace": resource.Metadata["namespace"], "remote_write_duplicate_name_count": strconv.Itoa(count)}, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now})
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func invalidKubernetesRemoteWriteQueueReasons(resource model.Resource) []string {
	reasons := make([]string, 0, 3)
	for _, setting := range []struct {
		declared string
		value    string
		name     string
	}{
		{"remote_write_queue_capacity_declared", "remote_write_queue_capacity", "capacity must be positive"},
		{"remote_write_queue_min_shards_declared", "remote_write_queue_min_shards", "minShards must be positive"},
		{"remote_write_queue_max_shards_declared", "remote_write_queue_max_shards", "maxShards must be positive"},
		{"remote_write_queue_max_samples_declared", "remote_write_queue_max_samples_per_send", "maxSamplesPerSend must be positive"},
	} {
		if resource.Metadata[setting.declared] == "true" && kubernetesRemoteWriteMetadataInt(resource, setting.value) <= 0 {
			reasons = append(reasons, setting.name)
		}
	}
	if resource.Metadata["remote_write_queue_min_shards_declared"] == "true" && resource.Metadata["remote_write_queue_max_shards_declared"] == "true" && kubernetesRemoteWriteMetadataInt(resource, "remote_write_queue_min_shards") > kubernetesRemoteWriteMetadataInt(resource, "remote_write_queue_max_shards") {
		reasons = append(reasons, "minShards exceeds maxShards")
	}
	return reasons
}

func kubernetesRemoteWriteMetadataInt(resource model.Resource, key string) int {
	value, err := strconv.Atoi(strings.TrimSpace(resource.Metadata[key]))
	if err != nil {
		return 0
	}
	return value
}
