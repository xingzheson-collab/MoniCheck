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

const OTelBatchBeforeSamplingAnalyzerID = "builtin.otelcol_batch_before_sampling"

type OTelBatchBeforeSamplingAnalyzer struct{}

func NewOTelBatchBeforeSamplingAnalyzer() *OTelBatchBeforeSamplingAnalyzer {
	return &OTelBatchBeforeSamplingAnalyzer{}
}

func (a *OTelBatchBeforeSamplingAnalyzer) ID() string {
	return OTelBatchBeforeSamplingAnalyzerID
}

func (a *OTelBatchBeforeSamplingAnalyzer) Name() string {
	return "OpenTelemetry Collector Batch Before Sampling"
}

func (a *OTelBatchBeforeSamplingAnalyzer) Version() string {
	return "0.1.0"
}

func (a *OTelBatchBeforeSamplingAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypePipeline}
}

func (a *OTelBatchBeforeSamplingAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	pipelines, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypePipeline})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, pipeline := range pipelines {
		if !isActiveOTelPipeline(pipeline) || !batchPrecedesSamplingProcessor(otelPipelineProcessorTypes(pipeline)) {
			continue
		}
		signal := strings.TrimSpace(pipeline.Metadata[model.MetadataPipelineSignal])
		if signal == "" {
			signal = "unknown"
		}
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), pipeline.ID),
			Type:     "OTelBatchBeforeSampling",
			Severity: model.SeverityWarning,
			Category: model.FindingCategoryReliability,
			Resource: model.ResourceRef{ID: pipeline.ID, Type: pipeline.Type, Name: pipeline.Name},
			Evidence: []string{
				fmt.Sprintf("OpenTelemetry Collector %s pipeline %q places batch before a sampling processor", signal, pipeline.Name),
			},
			Recommendation: "将 tail_sampling 或 probabilistic_sampler 放在 batch 之前，避免先缓存随后被采样丢弃的数据；调整后验证 Collector 内存、批次大小、采样率和导出吞吐。",
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

func batchPrecedesSamplingProcessor(processors []string) bool {
	batchSeen := false
	for _, processor := range processors {
		if processor == "batch" {
			batchSeen = true
			continue
		}
		if batchSeen && isOTelSamplingProcessor(processor) {
			return true
		}
	}
	return false
}

func isOTelSamplingProcessor(processor string) bool {
	return processor == "tail_sampling" || processor == "probabilistic_sampler"
}
