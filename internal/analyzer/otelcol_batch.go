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
	OTelBatchInvalidConfigAnalyzerID = "builtin.otelcol_batch_invalid_config"
	OTelBatchPassThroughAnalyzerID   = "builtin.otelcol_batch_pass_through"
)

type OTelBatchAnalyzer struct {
	id   string
	name string
}

func NewOTelBatchInvalidConfigAnalyzer() *OTelBatchAnalyzer {
	return &OTelBatchAnalyzer{
		id:   OTelBatchInvalidConfigAnalyzerID,
		name: "OpenTelemetry Collector Batch Invalid Configuration",
	}
}

func NewOTelBatchPassThroughAnalyzer() *OTelBatchAnalyzer {
	return &OTelBatchAnalyzer{
		id:   OTelBatchPassThroughAnalyzerID,
		name: "OpenTelemetry Collector Batch Pass Through",
	}
}

func (a *OTelBatchAnalyzer) ID() string      { return a.id }
func (a *OTelBatchAnalyzer) Name() string    { return a.name }
func (a *OTelBatchAnalyzer) Version() string { return "0.1.0" }
func (a *OTelBatchAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeProcessor}
}

func (a *OTelBatchAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
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
			processor.Metadata[model.MetadataOTelBatchConfig] != "true" {
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

func (a *OTelBatchAnalyzer) finding(processor model.Resource, now time.Time) (model.Finding, bool) {
	findingType := ""
	severity := model.SeverityWarning
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": a.id}

	switch a.id {
	case OTelBatchInvalidConfigAnalyzerID:
		issueCount, err := strconv.Atoi(processor.Metadata[model.MetadataOTelBatchConfigIssueCount])
		if err != nil || issueCount <= 0 {
			return model.Finding{}, false
		}
		findingType = "OTelBatchInvalidConfig"
		severity = model.SeverityCritical
		evidence = fmt.Sprintf("OpenTelemetry Collector batch processor %q has %d explicit invalid size or timeout setting(s)", processor.Name, issueCount)
		recommendation = "使用非负 timeout 和 batch size；当 send_batch_max_size 大于零时，确保它不小于 send_batch_size。修改后验证 Collector 能启动并监控 batch 发送大小与导出失败。"
		metadata["configuration_issue_count"] = strconv.Itoa(issueCount)
	case OTelBatchPassThroughAnalyzerID:
		if processor.Metadata[model.MetadataOTelBatchPassThroughEvaluable] != "true" ||
			processor.Metadata[model.MetadataOTelBatchPassThrough] != "true" {
			return model.Finding{}, false
		}
		findingType = "OTelBatchPassThrough"
		evidence = fmt.Sprintf("OpenTelemetry Collector batch processor %q explicitly flushes immediately without enforcing a maximum batch size", processor.Name)
		recommendation = "恢复正 timeout 以获得时间/数量批处理，或在确需零延迟时设置正 send_batch_max_size 以保留拆分职责；结合后端请求率、压缩率和延迟验证取值。"
		metadata["pass_through"] = "true"
	default:
		return model.Finding{}, false
	}

	return model.Finding{
		ID:             model.StableID(a.id, processor.ID),
		Type:           findingType,
		Severity:       severity,
		Category:       model.FindingCategoryReliability,
		Resource:       model.ResourceRef{ID: processor.ID, Type: processor.Type, Name: processor.Name},
		Evidence:       []string{evidence},
		Recommendation: recommendation,
		Metadata:       metadata,
		Status:         model.FindingStatusOpen,
		CreatedAt:      now,
		UpdatedAt:      now,
	}, true
}
