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
	KubernetesIneffectiveIngestionLimitAnalyzerID        = "builtin.kubernetes_ineffective_ingestion_limit"
	KubernetesMonitorWithoutSampleLimitAnalyzerID        = "builtin.kubernetes_monitor_without_sample_limit"
	KubernetesMonitorWithoutTargetLimitAnalyzerID        = "builtin.kubernetes_monitor_without_target_limit"
	KubernetesMonitorWithoutLabelLimitAnalyzerID         = "builtin.kubernetes_monitor_without_label_limit"
	KubernetesMonitorWithoutLabelLengthAnalyzerID        = "builtin.kubernetes_monitor_without_label_length_limit"
	KubernetesMonitorWithoutBodySizeLimitAnalyzerID      = "builtin.kubernetes_monitor_without_body_size_limit"
	KubernetesMonitorWithoutDroppedTargetLimitAnalyzerID = "builtin.kubernetes_monitor_without_dropped_target_limit"
)

type KubernetesIneffectiveIngestionLimitAnalyzer struct{}
type KubernetesMonitorWithoutSampleLimitAnalyzer struct{}
type KubernetesMonitorWithoutTargetLimitAnalyzer struct{}
type KubernetesMonitorWithoutLabelLimitAnalyzer struct{}
type KubernetesMonitorWithoutLabelLengthAnalyzer struct{}
type KubernetesMonitorWithoutBodySizeLimitAnalyzer struct{}
type KubernetesMonitorWithoutDroppedTargetLimitAnalyzer struct{}

func NewKubernetesIneffectiveIngestionLimitAnalyzer() *KubernetesIneffectiveIngestionLimitAnalyzer {
	return &KubernetesIneffectiveIngestionLimitAnalyzer{}
}
func NewKubernetesMonitorWithoutSampleLimitAnalyzer() *KubernetesMonitorWithoutSampleLimitAnalyzer {
	return &KubernetesMonitorWithoutSampleLimitAnalyzer{}
}
func NewKubernetesMonitorWithoutTargetLimitAnalyzer() *KubernetesMonitorWithoutTargetLimitAnalyzer {
	return &KubernetesMonitorWithoutTargetLimitAnalyzer{}
}
func NewKubernetesMonitorWithoutLabelLimitAnalyzer() *KubernetesMonitorWithoutLabelLimitAnalyzer {
	return &KubernetesMonitorWithoutLabelLimitAnalyzer{}
}
func NewKubernetesMonitorWithoutLabelLengthAnalyzer() *KubernetesMonitorWithoutLabelLengthAnalyzer {
	return &KubernetesMonitorWithoutLabelLengthAnalyzer{}
}
func NewKubernetesMonitorWithoutBodySizeLimitAnalyzer() *KubernetesMonitorWithoutBodySizeLimitAnalyzer {
	return &KubernetesMonitorWithoutBodySizeLimitAnalyzer{}
}
func NewKubernetesMonitorWithoutDroppedTargetLimitAnalyzer() *KubernetesMonitorWithoutDroppedTargetLimitAnalyzer {
	return &KubernetesMonitorWithoutDroppedTargetLimitAnalyzer{}
}

func (a *KubernetesIneffectiveIngestionLimitAnalyzer) ID() string {
	return KubernetesIneffectiveIngestionLimitAnalyzerID
}
func (a *KubernetesIneffectiveIngestionLimitAnalyzer) Name() string {
	return "Kubernetes Ineffective Ingestion Limit"
}
func (a *KubernetesIneffectiveIngestionLimitAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesIneffectiveIngestionLimitAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB, model.ResourceTypeTarget}
}
func (a *KubernetesIneffectiveIngestionLimitAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return kubernetesIngestionLimitFindings(ctx, analysis, a.ID())
}

func (a *KubernetesMonitorWithoutSampleLimitAnalyzer) ID() string {
	return KubernetesMonitorWithoutSampleLimitAnalyzerID
}
func (a *KubernetesMonitorWithoutSampleLimitAnalyzer) Name() string {
	return "Kubernetes Monitor Without Sample Limit"
}
func (a *KubernetesMonitorWithoutSampleLimitAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesMonitorWithoutSampleLimitAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTarget}
}
func (a *KubernetesMonitorWithoutSampleLimitAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return kubernetesIngestionLimitFindings(ctx, analysis, a.ID())
}

func (a *KubernetesMonitorWithoutTargetLimitAnalyzer) ID() string {
	return KubernetesMonitorWithoutTargetLimitAnalyzerID
}
func (a *KubernetesMonitorWithoutTargetLimitAnalyzer) Name() string {
	return "Kubernetes Monitor Without Target Limit"
}
func (a *KubernetesMonitorWithoutTargetLimitAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesMonitorWithoutTargetLimitAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTarget}
}
func (a *KubernetesMonitorWithoutTargetLimitAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return kubernetesIngestionLimitFindings(ctx, analysis, a.ID())
}

func (a *KubernetesMonitorWithoutLabelLimitAnalyzer) ID() string {
	return KubernetesMonitorWithoutLabelLimitAnalyzerID
}
func (a *KubernetesMonitorWithoutLabelLimitAnalyzer) Name() string {
	return "Kubernetes Monitor Without Label Limit"
}
func (a *KubernetesMonitorWithoutLabelLimitAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesMonitorWithoutLabelLimitAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTarget}
}
func (a *KubernetesMonitorWithoutLabelLimitAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return kubernetesIngestionLimitFindings(ctx, analysis, a.ID())
}

func (a *KubernetesMonitorWithoutLabelLengthAnalyzer) ID() string {
	return KubernetesMonitorWithoutLabelLengthAnalyzerID
}
func (a *KubernetesMonitorWithoutLabelLengthAnalyzer) Name() string {
	return "Kubernetes Monitor Without Label Length Limits"
}
func (a *KubernetesMonitorWithoutLabelLengthAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesMonitorWithoutLabelLengthAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTarget}
}
func (a *KubernetesMonitorWithoutLabelLengthAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return kubernetesIngestionLimitFindings(ctx, analysis, a.ID())
}

func (a *KubernetesMonitorWithoutBodySizeLimitAnalyzer) ID() string {
	return KubernetesMonitorWithoutBodySizeLimitAnalyzerID
}
func (a *KubernetesMonitorWithoutBodySizeLimitAnalyzer) Name() string {
	return "Kubernetes Monitor Without Body Size Limit"
}
func (a *KubernetesMonitorWithoutBodySizeLimitAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesMonitorWithoutBodySizeLimitAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTarget}
}
func (a *KubernetesMonitorWithoutBodySizeLimitAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return kubernetesIngestionLimitFindings(ctx, analysis, a.ID())
}

func (a *KubernetesMonitorWithoutDroppedTargetLimitAnalyzer) ID() string {
	return KubernetesMonitorWithoutDroppedTargetLimitAnalyzerID
}
func (a *KubernetesMonitorWithoutDroppedTargetLimitAnalyzer) Name() string {
	return "Kubernetes Monitor Without Dropped Target Limit"
}
func (a *KubernetesMonitorWithoutDroppedTargetLimitAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesMonitorWithoutDroppedTargetLimitAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTarget}
}
func (a *KubernetesMonitorWithoutDroppedTargetLimitAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return kubernetesIngestionLimitFindings(ctx, analysis, a.ID())
}

func kubernetesIngestionLimitFindings(ctx context.Context, analysis Context, analyzerID string) ([]model.Finding, error) {
	filter := storage.ResourceFilter{Type: model.ResourceTypeTarget}
	if analyzerID == KubernetesIneffectiveIngestionLimitAnalyzerID {
		filter = storage.ResourceFilter{}
	}
	resources, err := analysis.Resources.List(ctx, filter)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive {
			continue
		}
		finding, matched := kubernetesIngestionLimitFinding(analyzerID, resource, now)
		if matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesIngestionLimitFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	kind := resource.Metadata["kubernetes_kind"]
	severity := model.SeverityWarning
	category := model.FindingCategoryReliability
	findingType := ""
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": kind, "namespace": resource.Metadata["namespace"]}
	switch analyzerID {
	case KubernetesIneffectiveIngestionLimitAnalyzerID:
		key := ""
		if resource.Type == model.ResourceTypeTSDB && (kind == "Prometheus" || kind == "PrometheusAgent") {
			key = "prometheus_enforced_ingestion_limit_invalid_setting_count"
		}
		if resource.Type == model.ResourceTypeTarget && isKubernetesIngestionMonitorKind(kind) {
			key = "monitor_ingestion_limit_invalid_setting_count"
		}
		count := ingestionLimitMetadataInt(resource, key)
		if key == "" || count == 0 {
			return model.Finding{}, false
		}
		findingType = "KubernetesIneffectiveIngestionLimit"
		severity = model.SeverityCritical
		category = model.FindingCategoryConfiguration
		evidence = fmt.Sprintf("Kubernetes %s %q declares %d non-positive or invalid ingestion limit setting(s)", kind, resource.Name, count)
		recommendation = "删除无效 limit，或使用正整数 sample/target/label limits 和带单位的正 bodySizeLimit；确认 Operator 已接受并生成预期配置。"
		metadata["invalid_setting_count"] = strconv.Itoa(count)
	case KubernetesMonitorWithoutSampleLimitAnalyzerID:
		count, ok := kubernetesMonitorUnprotectedCount(resource, "sample")
		if !ok || count == 0 {
			return model.Finding{}, false
		}
		findingType = "KubernetesMonitorWithoutSampleLimit"
		category = model.FindingCategoryCost
		evidence = fmt.Sprintf("Kubernetes %s %q has no effective sample limit for %d selecting workload(s)", kind, resource.Name, count)
		recommendation = "在 Monitor 配置正 sampleLimit，或在所有选中它的 Prometheus/Agent 配置 enforcedSampleLimit，限制单次采集可写入的样本数。"
		metadata["unprotected_workload_count"] = strconv.Itoa(count)
	case KubernetesMonitorWithoutTargetLimitAnalyzerID:
		count, ok := kubernetesMonitorUnprotectedCount(resource, "target")
		if !ok || count == 0 {
			return model.Finding{}, false
		}
		findingType = "KubernetesMonitorWithoutTargetLimit"
		evidence = fmt.Sprintf("Kubernetes %s %q has no effective target limit for %d selecting workload(s)", kind, resource.Name, count)
		recommendation = "在 Monitor 配置正 targetLimit，或在所有选中它的 Prometheus/Agent 配置 enforcedTargetLimit，避免服务发现意外扩张。"
		metadata["unprotected_workload_count"] = strconv.Itoa(count)
	case KubernetesMonitorWithoutLabelLimitAnalyzerID:
		count, ok := kubernetesMonitorUnprotectedCount(resource, "label")
		if !ok || count == 0 {
			return model.Finding{}, false
		}
		findingType = "KubernetesMonitorWithoutLabelLimit"
		category = model.FindingCategoryCost
		evidence = fmt.Sprintf("Kubernetes %s %q has no effective per-sample label-count limit for %d selecting workload(s)", kind, resource.Name, count)
		recommendation = "配置 labelLimit 或 enforcedLabelLimit，阻止异常 exporter 通过超多标签放大解析和存储成本。"
		metadata["unprotected_workload_count"] = strconv.Itoa(count)
	case KubernetesMonitorWithoutLabelLengthAnalyzerID:
		nameCount, ok := kubernetesMonitorUnprotectedCount(resource, "label_name_length")
		if !ok {
			return model.Finding{}, false
		}
		valueCount, _ := kubernetesMonitorUnprotectedCount(resource, "label_value_length")
		if nameCount == 0 && valueCount == 0 {
			return model.Finding{}, false
		}
		findingType = "KubernetesMonitorWithoutLabelLengthLimit"
		category = model.FindingCategoryCost
		evidence = fmt.Sprintf("Kubernetes %s %q lacks effective label name/value length limits for %d/%d selecting workload(s)", kind, resource.Name, nameCount, valueCount)
		recommendation = "配置 labelNameLengthLimit、labelValueLengthLimit 或对应 enforced limits，限制异常超长标签占用内存和磁盘。"
		metadata["label_name_unprotected_workload_count"] = strconv.Itoa(nameCount)
		metadata["label_value_unprotected_workload_count"] = strconv.Itoa(valueCount)
	case KubernetesMonitorWithoutBodySizeLimitAnalyzerID:
		count, ok := kubernetesMonitorUnprotectedCount(resource, "body")
		if !ok || count == 0 {
			return model.Finding{}, false
		}
		findingType = "KubernetesMonitorWithoutBodySizeLimit"
		severity = model.SeverityCritical
		category = model.FindingCategorySecurity
		evidence = fmt.Sprintf("Kubernetes %s %q has no effective uncompressed response body limit for %d selecting workload(s)", kind, resource.Name, count)
		recommendation = "配置带单位的 bodySizeLimit 或 enforcedBodySizeLimit，避免异常或不可信目标返回超大响应耗尽 Prometheus 资源。"
		metadata["unprotected_workload_count"] = strconv.Itoa(count)
	case KubernetesMonitorWithoutDroppedTargetLimitAnalyzerID:
		count, ok := kubernetesMonitorUnprotectedCount(resource, "keep_dropped_targets")
		if !ok || count == 0 {
			return model.Finding{}, false
		}
		findingType = "KubernetesMonitorWithoutDroppedTargetLimit"
		category = model.FindingCategoryCost
		evidence = fmt.Sprintf("Kubernetes %s %q has no effective dropped-target retention limit for %d selecting workload(s)", kind, resource.Name, count)
		recommendation = "配置正 keepDroppedTargets，或在所有选中它的 Prometheus/Agent 配置 enforcedKeepDroppedTargets，限制 relabel 后保留在内存中的 dropped targets。"
		metadata["unprotected_workload_count"] = strconv.Itoa(count)
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}

func isKubernetesIngestionMonitorKind(kind string) bool {
	return kind == "ServiceMonitor" || kind == "PodMonitor" || kind == "Probe" || kind == "ScrapeConfig"
}

func kubernetesMonitorUnprotectedCount(resource model.Resource, dimension string) (int, bool) {
	if resource.Type != model.ResourceTypeTarget || !isKubernetesIngestionMonitorKind(resource.Metadata["kubernetes_kind"]) || ingestionLimitMetadataInt(resource, "prometheus_selected_count") == 0 {
		return 0, false
	}
	return ingestionLimitMetadataInt(resource, "prometheus_"+dimension+"_limit_unprotected_count"), true
}

func ingestionLimitMetadataInt(resource model.Resource, key string) int {
	value, err := strconv.Atoi(strings.TrimSpace(resource.Metadata[key]))
	if err != nil {
		return 0
	}
	return value
}
