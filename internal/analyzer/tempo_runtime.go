package analyzer

import (
	"context"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const TempoNotReadyAnalyzerID = "builtin.tempo_not_ready"

type TempoNotReadyAnalyzer struct{}

func NewTempoNotReadyAnalyzer() *TempoNotReadyAnalyzer {
	return &TempoNotReadyAnalyzer{}
}

func (a *TempoNotReadyAnalyzer) ID() string {
	return TempoNotReadyAnalyzerID
}

func (a *TempoNotReadyAnalyzer) Name() string {
	return "Tempo Runtime Not Ready"
}

func (a *TempoNotReadyAnalyzer) Version() string {
	return "0.1.0"
}

func (a *TempoNotReadyAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *TempoNotReadyAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Status != model.ResourceStatusActive ||
			resource.Source.System != "tempo" ||
			resource.Metadata[model.MetadataTempoRuntime] != "true" ||
			resource.Metadata[model.MetadataTempoReadinessAvailable] != "true" ||
			resource.Metadata[model.MetadataTempoReady] != "false" {
			continue
		}
		findings = append(findings, model.Finding{
			ID:             model.StableID(a.ID(), resource.ID),
			Type:           "TempoNotReady",
			Severity:       model.SeverityCritical,
			Category:       model.FindingCategoryReliability,
			Resource:       model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
			Evidence:       []string{"Tempo /ready returned HTTP 503 and explicitly reported the configured service as not ready"},
			Recommendation: "检查 Tempo 服务依赖、ring、存储、query-frontend/querier 和 ingester 状态；恢复 `/ready` 为 HTTP 200 后重新同步，并验证查询与写入链路。",
			Metadata: map[string]string{
				"analyzer_id": a.ID(),
				"ready":       "false",
				"scope":       "configured_service",
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}
