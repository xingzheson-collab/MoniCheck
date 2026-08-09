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
	OTelMemoryLimiterWithoutLimitAnalyzerID  = "builtin.otelcol_memory_limiter_without_limit"
	OTelMemoryLimiterInvalidConfigAnalyzerID = "builtin.otelcol_memory_limiter_invalid_config"
)

type OTelMemoryLimiterAnalyzer struct {
	id   string
	name string
}

func NewOTelMemoryLimiterWithoutLimitAnalyzer() *OTelMemoryLimiterAnalyzer {
	return &OTelMemoryLimiterAnalyzer{
		id:   OTelMemoryLimiterWithoutLimitAnalyzerID,
		name: "OpenTelemetry Collector Memory Limiter Without Limit",
	}
}

func NewOTelMemoryLimiterInvalidConfigAnalyzer() *OTelMemoryLimiterAnalyzer {
	return &OTelMemoryLimiterAnalyzer{
		id:   OTelMemoryLimiterInvalidConfigAnalyzerID,
		name: "OpenTelemetry Collector Memory Limiter Invalid Configuration",
	}
}

func (a *OTelMemoryLimiterAnalyzer) ID() string      { return a.id }
func (a *OTelMemoryLimiterAnalyzer) Name() string    { return a.name }
func (a *OTelMemoryLimiterAnalyzer) Version() string { return "0.1.0" }
func (a *OTelMemoryLimiterAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeProcessor}
}

func (a *OTelMemoryLimiterAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
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
			processor.Metadata[model.MetadataOTelMemoryLimiterConfig] != "true" {
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

func (a *OTelMemoryLimiterAnalyzer) finding(processor model.Resource, now time.Time) (model.Finding, bool) {
	findingType := ""
	severity := model.SeverityCritical
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": a.id}

	switch a.id {
	case OTelMemoryLimiterWithoutLimitAnalyzerID:
		if processor.Metadata[model.MetadataOTelMemoryLimiterLimitConfigured] != "false" ||
			processor.Metadata[model.MetadataOTelMemoryLimiterLimitEvaluable] != "true" {
			return model.Finding{}, false
		}
		findingType = "OTelMemoryLimiterWithoutLimit"
		evidence = fmt.Sprintf("OpenTelemetry Collector memory_limiter processor %q is used by an active pipeline but defines neither limit_mib nor limit_percentage", processor.Name)
		recommendation = "为 memory_limiter 设置与部署资源约束一致的 limit_percentage，或在固定容量环境设置 limit_mib；同时让它位于 pipeline 的首个 processor，并结合流量峰值设置 spike limit。"
		metadata["limit_configured"] = "false"
	case OTelMemoryLimiterInvalidConfigAnalyzerID:
		if processor.Metadata[model.MetadataOTelMemoryLimiterLimitEvaluable] != "true" {
			return model.Finding{}, false
		}
		issueCount, err := strconv.Atoi(processor.Metadata[model.MetadataOTelMemoryLimiterConfigIssueCount])
		if err != nil || issueCount <= 0 {
			return model.Finding{}, false
		}
		findingType = "OTelMemoryLimiterInvalidConfig"
		evidence = fmt.Sprintf("OpenTelemetry Collector memory_limiter processor %q has %d explicit invalid limit or spike-limit relationship(s)", processor.Name, issueCount)
		recommendation = "设置大于零的 hard limit；百分比不得超过 100，并确保 spike limit 非负且严格小于对应 hard limit。固定 MiB 和百分比模式同时存在时，以 limit_mib 模式校验并清理无效的冗余配置。"
		metadata["configuration_issue_count"] = strconv.Itoa(issueCount)
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
