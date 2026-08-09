package analyzer

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const OTelMemoryLimiterNotFirstAnalyzerID = "builtin.otelcol_memory_limiter_not_first"

type OTelMemoryLimiterNotFirstAnalyzer struct{}

func NewOTelMemoryLimiterNotFirstAnalyzer() *OTelMemoryLimiterNotFirstAnalyzer {
	return &OTelMemoryLimiterNotFirstAnalyzer{}
}

func (a *OTelMemoryLimiterNotFirstAnalyzer) ID() string {
	return OTelMemoryLimiterNotFirstAnalyzerID
}

func (a *OTelMemoryLimiterNotFirstAnalyzer) Name() string {
	return "OpenTelemetry Collector Memory Limiter Not First"
}

func (a *OTelMemoryLimiterNotFirstAnalyzer) Version() string {
	return "0.1.0"
}

func (a *OTelMemoryLimiterNotFirstAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypePipeline}
}

func (a *OTelMemoryLimiterNotFirstAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	pipelines, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypePipeline})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, pipeline := range pipelines {
		if !isActiveOTelPipeline(pipeline) {
			continue
		}
		processors := otelPipelineProcessorTypes(pipeline)
		if len(processors) < 2 || processors[0] == "memory_limiter" || !containsString(processors, "memory_limiter") {
			continue
		}
		signal := strings.TrimSpace(pipeline.Metadata[model.MetadataPipelineSignal])
		if signal == "" {
			signal = "unknown"
		}
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), pipeline.ID),
			Type:     "OTelMemoryLimiterNotFirst",
			Severity: model.SeverityWarning,
			Category: model.FindingCategoryReliability,
			Resource: model.ResourceRef{ID: pipeline.ID, Type: pipeline.Type, Name: pipeline.Name},
			Evidence: []string{
				fmt.Sprintf("OpenTelemetry Collector %s pipeline %q uses memory_limiter after another processor", signal, pipeline.Name),
			},
			Recommendation: "将 memory_limiter 移到 pipeline processors 列表首位，使内存压力下的拒绝和背压在其他 processor 分配更多内存前生效；变更后验证 receiver 重试和数据丢失指标。",
			Metadata: map[string]string{
				"analyzer_id": a.ID(),
				"signal":      signal,
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Resource.Name < findings[j].Resource.Name
	})
	return findings, nil
}

func otelPipelineProcessorTypes(pipeline model.Resource) []string {
	values := strings.Split(pipeline.Metadata[model.MetadataPipelineProcessors], ",")
	result := make([]string, 0, len(values))
	for _, value := range values {
		if normalized := normalizeOTelProcessorName(value); normalized != "" {
			result = append(result, normalized)
		}
	}
	return result
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
