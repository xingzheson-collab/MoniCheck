package analyzer

import (
	"context"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const JaegerRuntimeUnhealthyAnalyzerID = "builtin.jaeger_runtime_unhealthy"

type JaegerRuntimeUnhealthyAnalyzer struct{}

func NewJaegerRuntimeUnhealthyAnalyzer() *JaegerRuntimeUnhealthyAnalyzer {
	return &JaegerRuntimeUnhealthyAnalyzer{}
}

func (a *JaegerRuntimeUnhealthyAnalyzer) ID() string {
	return JaegerRuntimeUnhealthyAnalyzerID
}

func (a *JaegerRuntimeUnhealthyAnalyzer) Name() string {
	return "Jaeger Runtime Unhealthy"
}

func (a *JaegerRuntimeUnhealthyAnalyzer) Version() string {
	return "0.1.0"
}

func (a *JaegerRuntimeUnhealthyAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *JaegerRuntimeUnhealthyAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Status != model.ResourceStatusActive ||
			resource.Source.System != "jaeger" ||
			resource.Metadata[model.MetadataJaegerRuntime] != "true" ||
			resource.Metadata[model.MetadataJaegerHealthAvailable] != "true" ||
			resource.Metadata[model.MetadataJaegerHealthy] != "false" {
			continue
		}
		findings = append(findings, model.Finding{
			ID:             model.StableID(a.ID(), resource.ID),
			Type:           "JaegerRuntimeUnhealthy",
			Severity:       model.SeverityCritical,
			Category:       model.FindingCategoryReliability,
			Resource:       model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
			Evidence:       []string{"The configured Jaeger management health endpoint explicitly reported an unhealthy runtime"},
			Recommendation: "检查 Jaeger Query/Collector 组件、存储连接和启动状态；恢复管理健康端点后重新同步，并验证 trace 查询与写入链路。",
			Metadata: map[string]string{
				"analyzer_id":   a.ID(),
				"healthy":       "false",
				"health_source": resource.Metadata[model.MetadataJaegerHealthSource],
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}
