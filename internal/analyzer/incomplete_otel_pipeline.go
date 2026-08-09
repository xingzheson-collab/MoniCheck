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

const IncompleteOTelPipelineAnalyzerID = "builtin.incomplete_otel_pipeline"

type IncompleteOTelPipelineAnalyzer struct{}

func NewIncompleteOTelPipelineAnalyzer() *IncompleteOTelPipelineAnalyzer {
	return &IncompleteOTelPipelineAnalyzer{}
}

func (a *IncompleteOTelPipelineAnalyzer) ID() string {
	return IncompleteOTelPipelineAnalyzerID
}

func (a *IncompleteOTelPipelineAnalyzer) Name() string {
	return "Incomplete OpenTelemetry Collector Pipeline"
}

func (a *IncompleteOTelPipelineAnalyzer) Version() string {
	return "0.1.0"
}

func (a *IncompleteOTelPipelineAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypePipeline}
}

func (a *IncompleteOTelPipelineAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
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
		missing := missingOTelPipelineStages(pipeline)
		if len(missing) == 0 {
			continue
		}
		signal := strings.TrimSpace(pipeline.Metadata[model.MetadataPipelineSignal])
		if signal == "" {
			signal = "unknown"
		}
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), pipeline.ID, strings.Join(missing, ",")),
			Type:     "IncompleteOTelPipeline",
			Severity: model.SeverityCritical,
			Resource: model.ResourceRef{
				ID:   pipeline.ID,
				Type: pipeline.Type,
				Name: pipeline.Name,
			},
			Evidence: []string{
				fmt.Sprintf("OpenTelemetry Collector %s pipeline %q is missing %s", signal, pipeline.Name, strings.Join(missing, " and ")),
			},
			Recommendation: "为 OpenTelemetry Collector pipeline 补齐 receivers 和 exporters，确保遥测数据能被接收并发送到目标后端；不需要的 pipeline 建议删除。",
			Metadata: map[string]string{
				"analyzer_id": a.ID(),
				"signal":      signal,
				"missing":     strings.Join(missing, ","),
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

func missingOTelPipelineStages(pipeline model.Resource) []string {
	missing := make([]string, 0, 2)
	if strings.TrimSpace(pipeline.Metadata[model.MetadataPipelineReceivers]) == "" {
		missing = append(missing, "receivers")
	}
	if strings.TrimSpace(pipeline.Metadata[model.MetadataPipelineExporters]) == "" {
		missing = append(missing, "exporters")
	}
	return missing
}
