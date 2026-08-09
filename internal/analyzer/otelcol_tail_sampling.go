package analyzer

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	OTelTailSamplingWithoutPolicyAnalyzerID           = "builtin.otelcol_tail_sampling_without_policy"
	OTelTailSamplingInvalidConfigAnalyzerID           = "builtin.otelcol_tail_sampling_invalid_config"
	OTelTailSamplingFullCaptureAnalyzerID             = "builtin.otelcol_tail_sampling_full_capture"
	OTelTailSamplingDropPendingAnalyzerID             = "builtin.otelcol_tail_sampling_drop_pending_on_shutdown"
	OTelTailSamplingZeroTraceCapacityID               = "builtin.otelcol_tail_sampling_zero_trace_capacity"
	OTelTailSamplingUndersizedDecisionCacheID         = "builtin.otelcol_tail_sampling_undersized_decision_cache"
	OTelTailSamplingTailStorageGateDisabledID         = "builtin.otelcol_tail_sampling_tail_storage_gate_disabled"
	OTelTailSamplingTailStorageExtensionUnavailableID = "builtin.otelcol_tail_sampling_tail_storage_extension_unavailable"
	OTelTailSamplingUnboundedTraceSizeID              = "builtin.otelcol_tail_sampling_unbounded_trace_size"
	OTelTailSamplingOverflowEvictionEnabledID         = "builtin.otelcol_tail_sampling_overflow_eviction_enabled"
	OTelTailSamplingPolicyAttributionEnabledID        = "builtin.otelcol_tail_sampling_policy_attribution_enabled"
	OTelTailSamplingDetailedMetricsEnabledID          = "builtin.otelcol_tail_sampling_detailed_metrics_enabled"
)

type OTelTailSamplingAnalyzer struct {
	id   string
	name string
}

func NewOTelTailSamplingWithoutPolicyAnalyzer() *OTelTailSamplingAnalyzer {
	return &OTelTailSamplingAnalyzer{
		id:   OTelTailSamplingWithoutPolicyAnalyzerID,
		name: "OpenTelemetry Collector Tail Sampling Without Policy",
	}
}

func NewOTelTailSamplingInvalidConfigAnalyzer() *OTelTailSamplingAnalyzer {
	return &OTelTailSamplingAnalyzer{
		id:   OTelTailSamplingInvalidConfigAnalyzerID,
		name: "OpenTelemetry Collector Tail Sampling Invalid Configuration",
	}
}

func NewOTelTailSamplingFullCaptureAnalyzer() *OTelTailSamplingAnalyzer {
	return &OTelTailSamplingAnalyzer{
		id:   OTelTailSamplingFullCaptureAnalyzerID,
		name: "OpenTelemetry Collector Tail Sampling Full Capture",
	}
}

func NewOTelTailSamplingDropPendingAnalyzer() *OTelTailSamplingAnalyzer {
	return &OTelTailSamplingAnalyzer{
		id:   OTelTailSamplingDropPendingAnalyzerID,
		name: "OpenTelemetry Collector Tail Sampling Drops Pending Traces On Shutdown",
	}
}

func NewOTelTailSamplingZeroTraceCapacityAnalyzer() *OTelTailSamplingAnalyzer {
	return &OTelTailSamplingAnalyzer{
		id:   OTelTailSamplingZeroTraceCapacityID,
		name: "OpenTelemetry Collector Tail Sampling Zero Trace Capacity",
	}
}

func NewOTelTailSamplingUndersizedDecisionCacheAnalyzer() *OTelTailSamplingAnalyzer {
	return &OTelTailSamplingAnalyzer{
		id:   OTelTailSamplingUndersizedDecisionCacheID,
		name: "OpenTelemetry Collector Tail Sampling Undersized Decision Cache",
	}
}

func NewOTelTailSamplingTailStorageGateDisabledAnalyzer() *OTelTailSamplingAnalyzer {
	return &OTelTailSamplingAnalyzer{
		id:   OTelTailSamplingTailStorageGateDisabledID,
		name: "OpenTelemetry Collector Tail Sampling Tail Storage Feature Gate Disabled",
	}
}

func NewOTelTailSamplingTailStorageExtensionUnavailableAnalyzer() *OTelTailSamplingAnalyzer {
	return &OTelTailSamplingAnalyzer{
		id:   OTelTailSamplingTailStorageExtensionUnavailableID,
		name: "OpenTelemetry Collector Tail Sampling Tail Storage Extension Unavailable",
	}
}

func NewOTelTailSamplingUnboundedTraceSizeAnalyzer() *OTelTailSamplingAnalyzer {
	return &OTelTailSamplingAnalyzer{
		id:   OTelTailSamplingUnboundedTraceSizeID,
		name: "OpenTelemetry Collector Tail Sampling Unbounded Trace Size",
	}
}

func NewOTelTailSamplingOverflowEvictionEnabledAnalyzer() *OTelTailSamplingAnalyzer {
	return &OTelTailSamplingAnalyzer{
		id:   OTelTailSamplingOverflowEvictionEnabledID,
		name: "OpenTelemetry Collector Tail Sampling Overflow Eviction Enabled",
	}
}

func NewOTelTailSamplingPolicyAttributionEnabledAnalyzer() *OTelTailSamplingAnalyzer {
	return &OTelTailSamplingAnalyzer{
		id:   OTelTailSamplingPolicyAttributionEnabledID,
		name: "OpenTelemetry Collector Tail Sampling Policy Attribution Enabled",
	}
}

func NewOTelTailSamplingDetailedMetricsEnabledAnalyzer() *OTelTailSamplingAnalyzer {
	return &OTelTailSamplingAnalyzer{
		id:   OTelTailSamplingDetailedMetricsEnabledID,
		name: "OpenTelemetry Collector Tail Sampling Detailed Metrics Enabled",
	}
}

func (a *OTelTailSamplingAnalyzer) ID() string      { return a.id }
func (a *OTelTailSamplingAnalyzer) Name() string    { return a.name }
func (a *OTelTailSamplingAnalyzer) Version() string { return "0.1.0" }
func (a *OTelTailSamplingAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeProcessor}
}

func (a *OTelTailSamplingAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	processors, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeProcessor})
	if err != nil {
		return nil, err
	}
	usedByPipeline := activeOTelPipelineComponents(analysis)
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, processor := range processors {
		if !isActiveOTelComponent(processor) ||
			!usedByPipeline[processor.ID] ||
			processor.Metadata[model.MetadataOTelTailSamplingConfig] != "true" {
			continue
		}
		if finding, ok := a.finding(processor, now); ok {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Resource.Name < findings[j].Resource.Name
	})
	return findings, nil
}

func (a *OTelTailSamplingAnalyzer) finding(processor model.Resource, now time.Time) (model.Finding, bool) {
	findingType := ""
	evidence := ""
	recommendation := ""
	severity := model.SeverityCritical
	category := model.FindingCategoryReliability
	metadata := map[string]string{"analyzer_id": a.id}

	switch a.id {
	case OTelTailSamplingWithoutPolicyAnalyzerID:
		if processor.Metadata[model.MetadataOTelTailSamplingPoliciesEvaluable] != "true" ||
			processor.Metadata[model.MetadataOTelTailSamplingPolicyCount] != "0" {
			return model.Finding{}, false
		}
		findingType = "OTelTailSamplingWithoutPolicy"
		evidence = fmt.Sprintf("OpenTelemetry Collector tail_sampling processor %q has no evaluable sampling policy", processor.Name)
		recommendation = "为 tail_sampling 配置至少一条明确的 sampling policy，并验证错误、延迟和基线流量均按预期保留；上线后监控实际采样率及过早丢弃指标。"
		metadata["policy_count"] = "0"
	case OTelTailSamplingInvalidConfigAnalyzerID:
		issueCount, err := strconv.Atoi(processor.Metadata[model.MetadataOTelTailSamplingConfigIssueCount])
		if err != nil || issueCount <= 0 {
			return model.Finding{}, false
		}
		findingType = "OTelTailSamplingInvalidConfig"
		evidence = fmt.Sprintf("OpenTelemetry Collector tail_sampling processor %q has %d explicit structural configuration issue(s)", processor.Name, issueCount)
		recommendation = "修正 policies、policy name、sampling_strategy、duration、bool 和无符号容量字段；仅对 stateless policy 使用 span-ingest。修改后执行 Collector 配置校验并验证 trace 采样结果。"
		metadata["configuration_issue_count"] = strconv.Itoa(issueCount)
	case OTelTailSamplingFullCaptureAnalyzerID:
		if processor.Metadata[model.MetadataOTelTailSamplingFullCaptureEvaluable] != "true" ||
			processor.Metadata[model.MetadataOTelTailSamplingFullCapture] != "true" {
			return model.Finding{}, false
		}
		findingType = "OTelTailSamplingFullCapture"
		evidence = fmt.Sprintf("OpenTelemetry Collector tail_sampling processor %q deterministically retains every trace not overridden by a top-level drop policy", processor.Name)
		recommendation = "移除无条件 always_sample，改用错误、延迟、属性或受控概率策略限制保留范围；如果确需全量 trace，请记录容量预算并持续监控实际采样率、Collector 内存和后端摄入成本。"
		severity = model.SeverityWarning
		category = model.FindingCategoryCost
		metadata["full_capture"] = "true"
	case OTelTailSamplingDropPendingAnalyzerID:
		if processor.Metadata[model.MetadataOTelTailSamplingDropPendingEvaluable] != "true" ||
			processor.Metadata[model.MetadataOTelTailSamplingDropPendingOnShutdown] != "true" {
			return model.Finding{}, false
		}
		findingType = "OTelTailSamplingDropsPendingOnShutdown"
		evidence = fmt.Sprintf("OpenTelemetry Collector tail_sampling processor %q drops pending traces instead of deciding from partial data during shutdown", processor.Name)
		recommendation = "关闭 drop_pending_traces_on_shutdown，让 Collector 在关机时基于已接收数据完成采样决策；同时为滚动升级配置足够的优雅终止时间，并验证 pending trace、导出失败和数据缺口指标。"
		severity = model.SeverityWarning
		metadata["drop_pending_on_shutdown"] = "true"
	case OTelTailSamplingZeroTraceCapacityID:
		if processor.Metadata[model.MetadataOTelTailSamplingTraceCapacityEvaluable] != "true" ||
			processor.Metadata[model.MetadataOTelTailSamplingZeroTraceCapacity] != "true" {
			return model.Finding{}, false
		}
		findingType = "OTelTailSamplingZeroTraceCapacity"
		evidence = fmt.Sprintf("OpenTelemetry Collector tail_sampling processor %q has an explicit zero in-memory trace capacity", processor.Name)
		recommendation = "将 num_traces 设置为基于峰值新 trace 速率和 decision_wait 估算的正容量；上线后监控 sampling_trace_dropped_too_early、trace removal age、Collector 内存和接收背压。"
		severity = model.SeverityWarning
		metadata["zero_trace_capacity"] = "true"
	case OTelTailSamplingUndersizedDecisionCacheID:
		count, err := strconv.Atoi(processor.Metadata[model.MetadataOTelTailSamplingUndersizedDecisionCacheCnt])
		if processor.Metadata[model.MetadataOTelTailSamplingDecisionCacheEvaluable] != "true" ||
			err != nil || count <= 0 {
			return model.Finding{}, false
		}
		findingType = "OTelTailSamplingUndersizedDecisionCache"
		evidence = fmt.Sprintf("OpenTelemetry Collector tail_sampling processor %q has %d enabled decision cache(s) no larger than its in-memory trace capacity", processor.Name, count)
		recommendation = "将启用的 sampled_cache_size 和 non_sampled_cache_size 调整为显著大于 num_traces，或在不需要 late-span 决策一致性时显式禁用；变更后监控 late span age、重复决策和缓存命中。"
		severity = model.SeverityWarning
		metadata["undersized_decision_cache_count"] = strconv.Itoa(count)
	case OTelTailSamplingTailStorageGateDisabledID:
		if processor.Metadata[model.MetadataOTelTailSamplingTailStorageConfigured] != "true" ||
			processor.Metadata[model.MetadataOTelTailSamplingTailStorageGateEvaluable] != "true" ||
			processor.Metadata[model.MetadataOTelTailSamplingTailStorageGateEnabled] != "false" {
			return model.Finding{}, false
		}
		findingType = "OTelTailSamplingTailStorageGateDisabled"
		evidence = fmt.Sprintf("OpenTelemetry Collector tail_sampling processor %q configures tail_storage while its required feature gate is explicitly disabled", processor.Name)
		recommendation = "启用 processor.tailsamplingprocessor.tailstorageextension feature gate，或移除 tail_storage 并继续使用默认内存存储；修改后执行 Collector 配置校验并验证启动、trace 缓冲与关机行为。"
		metadata["tail_storage_configured"] = "true"
		metadata["tail_storage_feature_gate_enabled"] = "false"
	case OTelTailSamplingTailStorageExtensionUnavailableID:
		if processor.Metadata[model.MetadataOTelTailSamplingTailStorageConfigured] != "true" ||
			processor.Metadata[model.MetadataOTelTailSamplingTailStorageRefEvaluable] != "true" ||
			processor.Metadata[model.MetadataOTelTailSamplingTailStorageExtensionReady] != "false" {
			return model.Finding{}, false
		}
		findingType = "OTelTailSamplingTailStorageExtensionUnavailable"
		evidence = fmt.Sprintf("OpenTelemetry Collector tail_sampling processor %q references a tail storage extension that is not both declared and enabled", processor.Name)
		recommendation = "声明 tail_storage 引用的 Extension，并将同一 ID 加入 service.extensions；同时确认该 Extension 实现 TailStorage 接口、启用所需 feature gate，并执行 Collector 启动及 trace 缓冲验证。"
		metadata["tail_storage_configured"] = "true"
		metadata["tail_storage_extension_ready"] = "false"
	case OTelTailSamplingUnboundedTraceSizeID:
		if processor.Metadata[model.MetadataOTelTailSamplingMaxTraceSizeConfigured] != "true" ||
			processor.Metadata[model.MetadataOTelTailSamplingMaxTraceSizeEvaluable] != "true" ||
			processor.Metadata[model.MetadataOTelTailSamplingMaxTraceSizeUnbounded] != "true" {
			return model.Finding{}, false
		}
		findingType = "OTelTailSamplingUnboundedTraceSize"
		evidence = fmt.Sprintf("OpenTelemetry Collector tail_sampling processor %q explicitly disables early dropping for oversized traces", processor.Name)
		recommendation = "将 maximum_trace_size_bytes 设置为基于最大正常 trace 大小和 Collector 内存预算确定的正值；变更后监控 traces_dropped_too_large、内存、过早移除和接收背压。"
		severity = model.SeverityWarning
		metadata["maximum_trace_size_protection"] = "disabled"
	case OTelTailSamplingOverflowEvictionEnabledID:
		if processor.Metadata[model.MetadataOTelTailSamplingBlockOverflowConfigured] != "true" ||
			processor.Metadata[model.MetadataOTelTailSamplingBlockOverflowEvaluable] != "true" ||
			processor.Metadata[model.MetadataOTelTailSamplingBlockOverflowEnabled] != "false" {
			return model.Finding{}, false
		}
		findingType = "OTelTailSamplingOverflowEvictionEnabled"
		evidence = fmt.Sprintf("OpenTelemetry Collector tail_sampling processor %q explicitly evicts old traces when its in-memory trace capacity is full", processor.Name)
		recommendation = "在上游能够承受背压时启用 block_on_overflow，并按峰值新 trace 速率和 decision_wait 调整 num_traces；变更后监控过早丢弃、trace removal age、接收背压和 Collector 内存。"
		severity = model.SeverityWarning
		metadata["overflow_behavior"] = "evict_old_traces"
	case OTelTailSamplingPolicyAttributionEnabledID:
		if processor.Metadata[model.MetadataOTelTailSamplingRecordPolicyGateEvaluable] != "true" ||
			processor.Metadata[model.MetadataOTelTailSamplingRecordPolicyGateEnabled] != "true" {
			return model.Finding{}, false
		}
		findingType = "OTelTailSamplingPolicyAttributionEnabled"
		evidence = fmt.Sprintf("OpenTelemetry Collector tail_sampling processor %q has policy attribution enabled for sampled spans", processor.Name)
		recommendation = "仅在需要采样决策归因时启用 processor.tailsamplingprocessor.recordpolicy；完成排障后关闭，或量化新增 span 属性对后端摄入、索引基数和存储成本的影响并设置预算。"
		severity = model.SeverityWarning
		category = model.FindingCategoryCost
		metadata["policy_attribution"] = "enabled"
	case OTelTailSamplingDetailedMetricsEnabledID:
		count, err := strconv.Atoi(processor.Metadata[model.MetadataOTelTailSamplingDetailedMetricsEnabledCnt])
		if err != nil || count <= 0 {
			return model.Finding{}, false
		}
		findingType = "OTelTailSamplingDetailedMetricsEnabled"
		evidence = fmt.Sprintf("OpenTelemetry Collector tail_sampling processor %q has %d alpha detailed sampling metric feature gate(s) enabled", processor.Name, count)
		recommendation = "不需要按 policy 统计 sampled span 或 byte 数量时，关闭对应的 tail-sampling detailed metric feature gate；如需长期启用，请量化新增时序数量、policy 标签基数、Prometheus 摄入和保留成本。"
		severity = model.SeverityWarning
		category = model.FindingCategoryCost
		metadata["detailed_metric_gate_count"] = strconv.Itoa(count)
	default:
		return model.Finding{}, false
	}

	return model.Finding{
		ID:             model.StableID(a.id, processor.ID),
		Type:           findingType,
		Severity:       severity,
		Category:       category,
		Resource:       model.ResourceRef{ID: processor.ID, Type: processor.Type, Name: processor.Name},
		Evidence:       []string{evidence},
		Recommendation: recommendation,
		Metadata:       metadata,
		Status:         model.FindingStatusOpen,
		CreatedAt:      now,
		UpdatedAt:      now,
	}, true
}
