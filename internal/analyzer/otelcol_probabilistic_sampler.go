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
	OTelProbabilisticSamplerFullCaptureAnalyzerID                  = "builtin.otelcol_probabilistic_sampler_full_capture"
	OTelProbabilisticSamplerDropAllAnalyzerID                      = "builtin.otelcol_probabilistic_sampler_drop_all"
	OTelProbabilisticSamplerInvalidConfigAnalyzerID                = "builtin.otelcol_probabilistic_sampler_invalid_config"
	OTelProbabilisticSamplerInvalidOptionsAnalyzerID               = "builtin.otelcol_probabilistic_sampler_invalid_options"
	OTelProbabilisticSamplerFailOpenAnalyzerID                     = "builtin.otelcol_probabilistic_sampler_fail_open"
	OTelProbabilisticSamplerRecordSourceWithoutAttributeAnalyzerID = "builtin.otelcol_probabilistic_sampler_record_source_without_attribute"
	OTelProbabilisticSamplerRecordSourceUnsupportedModeAnalyzerID  = "builtin.otelcol_probabilistic_sampler_record_source_unsupported_mode"
)

type OTelProbabilisticSamplerAnalyzer struct {
	id   string
	name string
}

func NewOTelProbabilisticSamplerFullCaptureAnalyzer() *OTelProbabilisticSamplerAnalyzer {
	return &OTelProbabilisticSamplerAnalyzer{
		id:   OTelProbabilisticSamplerFullCaptureAnalyzerID,
		name: "OpenTelemetry Collector Probabilistic Sampler Full Capture",
	}
}

func NewOTelProbabilisticSamplerDropAllAnalyzer() *OTelProbabilisticSamplerAnalyzer {
	return &OTelProbabilisticSamplerAnalyzer{
		id:   OTelProbabilisticSamplerDropAllAnalyzerID,
		name: "OpenTelemetry Collector Probabilistic Sampler Drops All Telemetry",
	}
}

func NewOTelProbabilisticSamplerInvalidConfigAnalyzer() *OTelProbabilisticSamplerAnalyzer {
	return &OTelProbabilisticSamplerAnalyzer{
		id:   OTelProbabilisticSamplerInvalidConfigAnalyzerID,
		name: "OpenTelemetry Collector Probabilistic Sampler Invalid Configuration",
	}
}

func NewOTelProbabilisticSamplerInvalidOptionsAnalyzer() *OTelProbabilisticSamplerAnalyzer {
	return &OTelProbabilisticSamplerAnalyzer{
		id:   OTelProbabilisticSamplerInvalidOptionsAnalyzerID,
		name: "OpenTelemetry Collector Probabilistic Sampler Invalid Options",
	}
}

func NewOTelProbabilisticSamplerFailOpenAnalyzer() *OTelProbabilisticSamplerAnalyzer {
	return &OTelProbabilisticSamplerAnalyzer{
		id:   OTelProbabilisticSamplerFailOpenAnalyzerID,
		name: "OpenTelemetry Collector Probabilistic Sampler Fail Open",
	}
}

func NewOTelProbabilisticSamplerRecordSourceWithoutAttributeAnalyzer() *OTelProbabilisticSamplerAnalyzer {
	return &OTelProbabilisticSamplerAnalyzer{
		id:   OTelProbabilisticSamplerRecordSourceWithoutAttributeAnalyzerID,
		name: "OpenTelemetry Collector Probabilistic Sampler Record Source Without Attribute",
	}
}

func NewOTelProbabilisticSamplerRecordSourceUnsupportedModeAnalyzer() *OTelProbabilisticSamplerAnalyzer {
	return &OTelProbabilisticSamplerAnalyzer{
		id:   OTelProbabilisticSamplerRecordSourceUnsupportedModeAnalyzerID,
		name: "OpenTelemetry Collector Probabilistic Sampler Record Source Unsupported Mode",
	}
}

func (a *OTelProbabilisticSamplerAnalyzer) ID() string      { return a.id }
func (a *OTelProbabilisticSamplerAnalyzer) Name() string    { return a.name }
func (a *OTelProbabilisticSamplerAnalyzer) Version() string { return "0.1.0" }
func (a *OTelProbabilisticSamplerAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeProcessor}
}

func (a *OTelProbabilisticSamplerAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
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
			processor.Metadata[model.MetadataOTelProbabilisticSamplerConfig] != "true" {
			continue
		}
		if (a.id == OTelProbabilisticSamplerRecordSourceWithoutAttributeAnalyzerID ||
			a.id == OTelProbabilisticSamplerRecordSourceUnsupportedModeAnalyzerID) &&
			processor.Metadata[model.MetadataOTelProbabilisticUsedByLogs] != "true" {
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

func (a *OTelProbabilisticSamplerAnalyzer) finding(processor model.Resource, now time.Time) (model.Finding, bool) {
	findingType := ""
	evidence := ""
	recommendation := ""
	severity := model.SeverityCritical
	category := model.FindingCategoryReliability
	metadata := map[string]string{"analyzer_id": a.id}

	switch a.id {
	case OTelProbabilisticSamplerFullCaptureAnalyzerID:
		if processor.Metadata[model.MetadataOTelProbabilisticPercentageEvaluable] != "true" ||
			processor.Metadata[model.MetadataOTelProbabilisticFullCapture] != "true" {
			return model.Finding{}, false
		}
		findingType = "OTelProbabilisticSamplerFullCapture"
		evidence = fmt.Sprintf("OpenTelemetry Collector probabilistic_sampler processor %q has an effective full-capture sampling percentage", processor.Name)
		recommendation = "将 sampling_percentage 降到有容量预算支撑的比例，并通过后端摄入量、关键 trace 保留率和业务覆盖验证节省效果；如果必须全量采集，请移除无效 sampler 或记录明确例外。"
		severity = model.SeverityWarning
		category = model.FindingCategoryCost
		metadata["full_capture"] = "true"
	case OTelProbabilisticSamplerDropAllAnalyzerID:
		if processor.Metadata[model.MetadataOTelProbabilisticPercentageEvaluable] != "true" ||
			processor.Metadata[model.MetadataOTelProbabilisticDropAll] != "true" {
			return model.Finding{}, false
		}
		findingType = "OTelProbabilisticSamplerDropAll"
		evidence = fmt.Sprintf("OpenTelemetry Collector probabilistic_sampler processor %q has an effective zero sampling percentage", processor.Name)
		recommendation = "设置大于零且符合保留目标的 sampling_percentage，或从 active pipeline 移除该 sampler；变更后验证 traces/logs 已恢复并监控 Collector 接收与导出数量。"
		metadata["drop_all"] = "true"
	case OTelProbabilisticSamplerInvalidConfigAnalyzerID:
		issueCount, err := strconv.Atoi(processor.Metadata[model.MetadataOTelProbabilisticConfigIssueCount])
		if err != nil || issueCount <= 0 {
			return model.Finding{}, false
		}
		findingType = "OTelProbabilisticSamplerInvalidConfig"
		evidence = fmt.Sprintf("OpenTelemetry Collector probabilistic_sampler processor %q has %d explicit sampling percentage configuration issue(s)", processor.Name, issueCount)
		recommendation = "将 sampling_percentage 设置为非负有限数值，并运行 Collector 配置校验；使用 0 会丢弃全部数据，使用 100 或更高会保留全部数据。"
		metadata["configuration_issue_count"] = strconv.Itoa(issueCount)
	case OTelProbabilisticSamplerInvalidOptionsAnalyzerID:
		issueCount, err := strconv.Atoi(processor.Metadata[model.MetadataOTelProbabilisticOptionIssueCount])
		if err != nil || issueCount <= 0 {
			return model.Finding{}, false
		}
		findingType = "OTelProbabilisticSamplerInvalidOptions"
		evidence = fmt.Sprintf("OpenTelemetry Collector probabilistic_sampler processor %q has %d explicit option configuration issue(s)", processor.Name, issueCount)
		recommendation = "使用受支持的 mode、attribute_source 和 1 至 14 的 sampling_precision，并将 fail_closed 配置为布尔值；修改后运行 Collector 配置校验并验证采样结果。"
		metadata["option_issue_count"] = strconv.Itoa(issueCount)
	case OTelProbabilisticSamplerFailOpenAnalyzerID:
		if processor.Metadata[model.MetadataOTelProbabilisticFailClosedEvaluable] != "true" ||
			processor.Metadata[model.MetadataOTelProbabilisticFailClosed] != "false" {
			return model.Finding{}, false
		}
		findingType = "OTelProbabilisticSamplerFailOpen"
		evidence = fmt.Sprintf("OpenTelemetry Collector probabilistic_sampler processor %q is configured to pass telemetry when sampling randomness cannot be determined", processor.Name)
		recommendation = "将 fail_closed 设为 true，避免采样判定错误绕过容量预算；若业务明确要求 fail open，请记录例外并监控 Collector 错误、后端摄入量与成本突增。"
		severity = model.SeverityWarning
		category = model.FindingCategoryCost
		metadata["fail_closed"] = "false"
	case OTelProbabilisticSamplerRecordSourceWithoutAttributeAnalyzerID:
		if processor.Metadata[model.MetadataOTelProbabilisticAttributeSourceEvaluable] != "true" ||
			processor.Metadata[model.MetadataOTelProbabilisticAttributeSourceRecord] != "true" ||
			processor.Metadata[model.MetadataOTelProbabilisticFromAttributeEvaluable] != "true" ||
			processor.Metadata[model.MetadataOTelProbabilisticFromAttributeConfigured] != "false" {
			return model.Finding{}, false
		}
		findingType = "OTelProbabilisticSamplerRecordSourceWithoutAttribute"
		evidence = fmt.Sprintf("OpenTelemetry Collector probabilistic_sampler processor %q is used by a logs pipeline with record attribute randomness enabled but no source attribute configured", processor.Name)
		recommendation = "为 from_attribute 配置稳定且高熵的日志记录属性，或将 attribute_source 恢复为 traceID；变更后验证无 TraceID 日志的接收、采样率和 Collector sampling error 指标。"
		metadata["attribute_source_record"] = "true"
		metadata["from_attribute_configured"] = "false"
	case OTelProbabilisticSamplerRecordSourceUnsupportedModeAnalyzerID:
		if processor.Metadata[model.MetadataOTelProbabilisticAttributeSourceEvaluable] != "true" ||
			processor.Metadata[model.MetadataOTelProbabilisticAttributeSourceRecord] != "true" ||
			processor.Metadata[model.MetadataOTelProbabilisticFromAttributeEvaluable] != "true" ||
			processor.Metadata[model.MetadataOTelProbabilisticFromAttributeConfigured] != "true" ||
			processor.Metadata[model.MetadataOTelProbabilisticModeEvaluable] != "true" ||
			processor.Metadata[model.MetadataOTelProbabilisticRecordSourceModeCompatible] != "false" {
			return model.Finding{}, false
		}
		findingType = "OTelProbabilisticSamplerRecordSourceUnsupportedMode"
		evidence = fmt.Sprintf("OpenTelemetry Collector probabilistic_sampler processor %q is used by a logs pipeline with record attribute randomness configured in a mode that ignores the record attribute", processor.Name)
		recommendation = "移除显式 mode 让 Collector 为日志记录属性选择 hash_seed，或将 mode 设为 hash_seed；如果必须使用 proportional/equalizing，请将 attribute_source 恢复为 traceID 并验证无 TraceID 日志的处理结果。"
		metadata["attribute_source_record"] = "true"
		metadata["record_source_mode_compatible"] = "false"
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
