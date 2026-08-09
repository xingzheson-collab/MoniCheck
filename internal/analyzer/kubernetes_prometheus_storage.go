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
	KubernetesEphemeralPrometheusStorageAnalyzerID             = "builtin.kubernetes_ephemeral_prometheus_storage"
	KubernetesConflictingPrometheusStorageAnalyzerID           = "builtin.kubernetes_conflicting_prometheus_storage"
	KubernetesImplicitPrometheusRetentionAnalyzerID            = "builtin.kubernetes_implicit_prometheus_retention"
	KubernetesInvalidPrometheusRetentionAnalyzerID             = "builtin.kubernetes_invalid_prometheus_retention"
	KubernetesRetentionExceedsPVCAnalyzerID                    = "builtin.kubernetes_retention_exceeds_pvc"
	KubernetesWALCompressionDisabledAnalyzerID                 = "builtin.kubernetes_wal_compression_disabled"
	KubernetesDisabledCompactionWithoutObjectStorageAnalyzerID = "builtin.kubernetes_disabled_compaction_without_object_storage"
)

type KubernetesEphemeralPrometheusStorageAnalyzer struct{}
type KubernetesConflictingPrometheusStorageAnalyzer struct{}
type KubernetesImplicitPrometheusRetentionAnalyzer struct{}
type KubernetesInvalidPrometheusRetentionAnalyzer struct{}
type KubernetesRetentionExceedsPVCAnalyzer struct{}
type KubernetesWALCompressionDisabledAnalyzer struct{}
type KubernetesDisabledCompactionWithoutObjectStorageAnalyzer struct{}

func NewKubernetesEphemeralPrometheusStorageAnalyzer() *KubernetesEphemeralPrometheusStorageAnalyzer {
	return &KubernetesEphemeralPrometheusStorageAnalyzer{}
}
func NewKubernetesConflictingPrometheusStorageAnalyzer() *KubernetesConflictingPrometheusStorageAnalyzer {
	return &KubernetesConflictingPrometheusStorageAnalyzer{}
}
func NewKubernetesImplicitPrometheusRetentionAnalyzer() *KubernetesImplicitPrometheusRetentionAnalyzer {
	return &KubernetesImplicitPrometheusRetentionAnalyzer{}
}
func NewKubernetesInvalidPrometheusRetentionAnalyzer() *KubernetesInvalidPrometheusRetentionAnalyzer {
	return &KubernetesInvalidPrometheusRetentionAnalyzer{}
}
func NewKubernetesRetentionExceedsPVCAnalyzer() *KubernetesRetentionExceedsPVCAnalyzer {
	return &KubernetesRetentionExceedsPVCAnalyzer{}
}
func NewKubernetesWALCompressionDisabledAnalyzer() *KubernetesWALCompressionDisabledAnalyzer {
	return &KubernetesWALCompressionDisabledAnalyzer{}
}
func NewKubernetesDisabledCompactionWithoutObjectStorageAnalyzer() *KubernetesDisabledCompactionWithoutObjectStorageAnalyzer {
	return &KubernetesDisabledCompactionWithoutObjectStorageAnalyzer{}
}

func (a *KubernetesEphemeralPrometheusStorageAnalyzer) ID() string {
	return KubernetesEphemeralPrometheusStorageAnalyzerID
}
func (a *KubernetesEphemeralPrometheusStorageAnalyzer) Name() string {
	return "Kubernetes Ephemeral Prometheus Storage"
}
func (a *KubernetesEphemeralPrometheusStorageAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesEphemeralPrometheusStorageAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}
func (a *KubernetesEphemeralPrometheusStorageAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return kubernetesPrometheusStorageFindings(ctx, analysis, a.ID())
}

func (a *KubernetesConflictingPrometheusStorageAnalyzer) ID() string {
	return KubernetesConflictingPrometheusStorageAnalyzerID
}
func (a *KubernetesConflictingPrometheusStorageAnalyzer) Name() string {
	return "Kubernetes Conflicting Prometheus Storage"
}
func (a *KubernetesConflictingPrometheusStorageAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesConflictingPrometheusStorageAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}
func (a *KubernetesConflictingPrometheusStorageAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return kubernetesPrometheusStorageFindings(ctx, analysis, a.ID())
}

func (a *KubernetesImplicitPrometheusRetentionAnalyzer) ID() string {
	return KubernetesImplicitPrometheusRetentionAnalyzerID
}
func (a *KubernetesImplicitPrometheusRetentionAnalyzer) Name() string {
	return "Kubernetes Implicit Prometheus Retention"
}
func (a *KubernetesImplicitPrometheusRetentionAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesImplicitPrometheusRetentionAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}
func (a *KubernetesImplicitPrometheusRetentionAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return kubernetesPrometheusStorageFindings(ctx, analysis, a.ID())
}

func (a *KubernetesInvalidPrometheusRetentionAnalyzer) ID() string {
	return KubernetesInvalidPrometheusRetentionAnalyzerID
}
func (a *KubernetesInvalidPrometheusRetentionAnalyzer) Name() string {
	return "Kubernetes Invalid Prometheus Retention"
}
func (a *KubernetesInvalidPrometheusRetentionAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesInvalidPrometheusRetentionAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}
func (a *KubernetesInvalidPrometheusRetentionAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return kubernetesPrometheusStorageFindings(ctx, analysis, a.ID())
}

func (a *KubernetesRetentionExceedsPVCAnalyzer) ID() string {
	return KubernetesRetentionExceedsPVCAnalyzerID
}
func (a *KubernetesRetentionExceedsPVCAnalyzer) Name() string {
	return "Kubernetes Prometheus Retention Exceeds PVC"
}
func (a *KubernetesRetentionExceedsPVCAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesRetentionExceedsPVCAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}
func (a *KubernetesRetentionExceedsPVCAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return kubernetesPrometheusStorageFindings(ctx, analysis, a.ID())
}

func (a *KubernetesWALCompressionDisabledAnalyzer) ID() string {
	return KubernetesWALCompressionDisabledAnalyzerID
}
func (a *KubernetesWALCompressionDisabledAnalyzer) Name() string {
	return "Kubernetes Prometheus WAL Compression Disabled"
}
func (a *KubernetesWALCompressionDisabledAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesWALCompressionDisabledAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}
func (a *KubernetesWALCompressionDisabledAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return kubernetesPrometheusStorageFindings(ctx, analysis, a.ID())
}

func (a *KubernetesDisabledCompactionWithoutObjectStorageAnalyzer) ID() string {
	return KubernetesDisabledCompactionWithoutObjectStorageAnalyzerID
}
func (a *KubernetesDisabledCompactionWithoutObjectStorageAnalyzer) Name() string {
	return "Kubernetes Disabled Compaction Without Object Storage"
}
func (a *KubernetesDisabledCompactionWithoutObjectStorageAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesDisabledCompactionWithoutObjectStorageAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}
func (a *KubernetesDisabledCompactionWithoutObjectStorageAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return kubernetesPrometheusStorageFindings(ctx, analysis, a.ID())
}

func kubernetesPrometheusStorageFindings(ctx context.Context, analysis Context, analyzerID string) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTSDB})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		kind := resource.Metadata["kubernetes_kind"]
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || (kind != "Prometheus" && kind != "PrometheusAgent") {
			continue
		}
		finding, matched := kubernetesPrometheusStorageFinding(analyzerID, resource, now)
		if matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesPrometheusStorageFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	kind := resource.Metadata["kubernetes_kind"]
	severity := model.SeverityCritical
	category := model.FindingCategoryConfiguration
	findingType := ""
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": kind, "namespace": resource.Metadata["namespace"]}
	switch analyzerID {
	case KubernetesEphemeralPrometheusStorageAnalyzerID:
		mode := resource.Metadata["prometheus_storage_mode"]
		if mode != "default-empty-dir" && mode != "empty-dir" && mode != "ephemeral" {
			return model.Finding{}, false
		}
		findingType = "KubernetesEphemeralPrometheusStorage"
		category = model.FindingCategoryReliability
		metadata["prometheus_storage_mode"] = mode
		if kind == "PrometheusAgent" {
			severity = model.SeverityWarning
			evidence = fmt.Sprintf("Kubernetes PrometheusAgent %q uses %s storage, so buffered WAL samples can be lost when a Pod is replaced", resource.Name, mode)
			recommendation = "评估可接受的数据丢失窗口；需要重启缓冲可靠性时，为 Agent 配置 volumeClaimTemplate，并确认 remote write 队列持续可用。"
		} else {
			evidence = fmt.Sprintf("Kubernetes Prometheus %q uses %s storage, so local TSDB data is lost when a Pod is replaced", resource.Name, mode)
			recommendation = "为生产 Prometheus 配置有足够容量的 volumeClaimTemplate；仅在明确接受重建全部本地历史数据时使用临时卷。"
		}
	case KubernetesConflictingPrometheusStorageAnalyzerID:
		count := prometheusStorageMetadataInt64(resource, "prometheus_storage_option_count")
		if count <= 1 {
			return model.Finding{}, false
		}
		findingType = "KubernetesConflictingPrometheusStorage"
		evidence = fmt.Sprintf("Kubernetes %s %q declares %d storage options; the Operator silently applies its precedence order", kind, resource.Name, count)
		recommendation = "仅保留 emptyDir、ephemeral 或 volumeClaimTemplate 中的一种，避免清单意图与实际挂载类型不一致。"
		metadata["prometheus_storage_option_count"] = strconv.FormatInt(count, 10)
	case KubernetesImplicitPrometheusRetentionAnalyzerID:
		if kind != "Prometheus" || resource.Metadata["prometheus_retention_declared"] == "true" || resource.Metadata["prometheus_retention_size_declared"] == "true" {
			return model.Finding{}, false
		}
		findingType = "KubernetesImplicitPrometheusRetention"
		severity = model.SeverityWarning
		category = model.FindingCategoryReliability
		evidence = fmt.Sprintf("Kubernetes Prometheus %q leaves both retention and retentionSize unset and therefore relies on the Operator default retention", resource.Name)
		recommendation = "显式配置符合查询、合规和容量目标的 retention 和/或 retentionSize，避免 Operator 默认值变化或 24h 历史窗口不符合预期。"
	case KubernetesInvalidPrometheusRetentionAnalyzerID:
		invalidDuration := resource.Metadata["prometheus_retention_declared"] == "true" && resource.Metadata["prometheus_retention_valid"] != "true"
		invalidSize := resource.Metadata["prometheus_retention_size_declared"] == "true" && resource.Metadata["prometheus_retention_size_valid"] != "true"
		if kind != "Prometheus" || (!invalidDuration && !invalidSize) {
			return model.Finding{}, false
		}
		findingType = "KubernetesInvalidPrometheusRetention"
		evidence = fmt.Sprintf("Kubernetes Prometheus %q declares an invalid retention duration or size", resource.Name)
		recommendation = "使用 Prometheus duration（如 15d、1h30m）和带单位的正 ByteSize（如 50GB），并通过 Operator CRD 校验后部署。"
		metadata["prometheus_retention_invalid"] = strconv.FormatBool(invalidDuration)
		metadata["prometheus_retention_size_invalid"] = strconv.FormatBool(invalidSize)
	case KubernetesRetentionExceedsPVCAnalyzerID:
		retentionBytes := prometheusStorageMetadataInt64(resource, "prometheus_retention_size_bytes")
		pvcBytes := prometheusStorageMetadataInt64(resource, "prometheus_pvc_request_bytes")
		if kind != "Prometheus" || resource.Metadata["prometheus_retention_exceeds_pvc"] != "true" {
			return model.Finding{}, false
		}
		findingType = "KubernetesRetentionExceedsPVC"
		category = model.FindingCategoryReliability
		evidence = fmt.Sprintf("Kubernetes Prometheus %q sets retentionSize to %d bytes for a PVC request of %d bytes, leaving no room for WAL and head chunks", resource.Name, retentionBytes, pvcBytes)
		recommendation = "将 retentionSize 调低到 PVC 容量以内并为 WAL、head chunks、文件系统和峰值增长预留空间，或增大 PVC 请求容量。"
		metadata["prometheus_retention_size_bytes"] = strconv.FormatInt(retentionBytes, 10)
		metadata["prometheus_pvc_request_bytes"] = strconv.FormatInt(pvcBytes, 10)
	case KubernetesWALCompressionDisabledAnalyzerID:
		if resource.Metadata["prometheus_wal_compression_declared"] != "true" || resource.Metadata["prometheus_wal_compression_enabled"] != "false" {
			return model.Finding{}, false
		}
		findingType = "KubernetesWALCompressionDisabled"
		severity = model.SeverityWarning
		category = model.FindingCategoryCost
		evidence = fmt.Sprintf("Kubernetes %s %q explicitly disables WAL compression", kind, resource.Name)
		recommendation = "移除 walCompression: false 或显式启用 WAL 压缩；升级前先确认所用 Prometheus 版本满足 Operator 的版本要求。"
	case KubernetesDisabledCompactionWithoutObjectStorageAnalyzerID:
		if kind != "Prometheus" || resource.Metadata["prometheus_disable_compaction"] != "true" || resource.Metadata["prometheus_thanos_object_storage_declared"] == "true" {
			return model.Finding{}, false
		}
		findingType = "KubernetesDisabledCompactionWithoutObjectStorage"
		severity = model.SeverityWarning
		category = model.FindingCategoryReliability
		evidence = fmt.Sprintf("Kubernetes Prometheus %q explicitly disables local TSDB compaction without a declared Thanos object storage configuration", resource.Name)
		recommendation = "移除 disableCompaction: true，让 Prometheus 管理本地块压缩；仅在 Thanos sidecar 已配置 objectStorageConfig/objectStorageConfigFile 且外部 Thanos Compactor 已可靠运行时关闭本地 compaction。"
		metadata["prometheus_disable_compaction"] = "true"
		metadata["prometheus_thanos_object_storage_declared"] = "false"
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}

func prometheusStorageMetadataInt64(resource model.Resource, key string) int64 {
	value, err := strconv.ParseInt(strings.TrimSpace(resource.Metadata[key]), 10, 64)
	if err != nil {
		return 0
	}
	return value
}
