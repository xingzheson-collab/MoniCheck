package analyzer

import (
	"context"
	"fmt"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const SkyWalkingOAPUnhealthyAnalyzerID = "builtin.skywalking_oap_unhealthy"

type SkyWalkingOAPUnhealthyAnalyzer struct{}

func NewSkyWalkingOAPUnhealthyAnalyzer() *SkyWalkingOAPUnhealthyAnalyzer {
	return &SkyWalkingOAPUnhealthyAnalyzer{}
}

func (a *SkyWalkingOAPUnhealthyAnalyzer) ID() string {
	return SkyWalkingOAPUnhealthyAnalyzerID
}

func (a *SkyWalkingOAPUnhealthyAnalyzer) Name() string {
	return "SkyWalking OAP Unhealthy"
}

func (a *SkyWalkingOAPUnhealthyAnalyzer) Version() string {
	return "0.1.0"
}

func (a *SkyWalkingOAPUnhealthyAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *SkyWalkingOAPUnhealthyAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Status != model.ResourceStatusActive ||
			resource.Source.System != "skywalking" ||
			resource.Metadata[model.MetadataSkyWalkingRuntime] != "true" ||
			resource.Metadata[model.MetadataSkyWalkingHealthAvailable] != "true" ||
			resource.Metadata[model.MetadataSkyWalkingHealthy] != "false" {
			continue
		}
		evidence := "SkyWalking /healthcheck returned HTTP 503 and explicitly reported the OAP runtime as unhealthy"
		if resource.Metadata[model.MetadataSkyWalkingHealthSource] == "graphql" {
			evidence = fmt.Sprintf(
				"SkyWalking GraphQL checkHealth returned score %s; score 0 is healthy and non-zero is unhealthy",
				resource.Metadata[model.MetadataSkyWalkingHealthScore],
			)
		}
		findings = append(findings, model.Finding{
			ID:             model.StableID(a.ID(), resource.ID),
			Type:           "SkyWalkingOAPUnhealthy",
			Severity:       model.SeverityCritical,
			Category:       model.FindingCategoryReliability,
			Resource:       model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
			Evidence:       []string{evidence},
			Recommendation: "检查 SkyWalking OAP 的存储、模块状态、GraphQL/gRPC readiness 和内部队列；恢复 `/healthcheck` 为 HTTP 200 后重新同步。",
			Metadata: map[string]string{
				"analyzer_id":   a.ID(),
				"healthy":       "false",
				"health_source": resource.Metadata[model.MetadataSkyWalkingHealthSource],
				"health_score":  resource.Metadata[model.MetadataSkyWalkingHealthScore],
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}
