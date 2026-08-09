package analyzer

import (
	"context"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const PyroscopeNotReadyAnalyzerID = "builtin.pyroscope_not_ready"

type PyroscopeNotReadyAnalyzer struct{}

func NewPyroscopeNotReadyAnalyzer() *PyroscopeNotReadyAnalyzer {
	return &PyroscopeNotReadyAnalyzer{}
}

func (a *PyroscopeNotReadyAnalyzer) ID() string {
	return PyroscopeNotReadyAnalyzerID
}

func (a *PyroscopeNotReadyAnalyzer) Name() string {
	return "Pyroscope Runtime Not Ready"
}

func (a *PyroscopeNotReadyAnalyzer) Version() string {
	return "0.1.0"
}

func (a *PyroscopeNotReadyAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *PyroscopeNotReadyAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Status != model.ResourceStatusActive ||
			resource.Source.System != "pyroscope" ||
			resource.Metadata[model.MetadataPyroscopeRuntime] != "true" ||
			resource.Metadata[model.MetadataPyroscopeReadinessAvailable] != "true" ||
			resource.Metadata[model.MetadataPyroscopeReady] != "false" {
			continue
		}
		findings = append(findings, model.Finding{
			ID:             model.StableID(a.ID(), resource.ID),
			Type:           "PyroscopeNotReady",
			Severity:       model.SeverityCritical,
			Category:       model.FindingCategoryReliability,
			Resource:       model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
			Evidence:       []string{"Pyroscope /ready returned HTTP 503 and explicitly reported the runtime as not ready"},
			Recommendation: "检查 Pyroscope 服务依赖、存储、ring 成员和启动日志；恢复 `/ready` 为成功响应后重新同步并确认 profile 查询链路可用。",
			Metadata: map[string]string{
				"analyzer_id": a.ID(),
				"ready":       "false",
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}
