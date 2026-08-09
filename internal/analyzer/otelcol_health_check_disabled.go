package analyzer

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const OTelCollectorHealthCheckDisabledAnalyzerID = "builtin.otelcol_health_check_disabled"

type OTelCollectorHealthCheckDisabledAnalyzer struct{}

func NewOTelCollectorHealthCheckDisabledAnalyzer() *OTelCollectorHealthCheckDisabledAnalyzer {
	return &OTelCollectorHealthCheckDisabledAnalyzer{}
}

func (a *OTelCollectorHealthCheckDisabledAnalyzer) ID() string {
	return OTelCollectorHealthCheckDisabledAnalyzerID
}

func (a *OTelCollectorHealthCheckDisabledAnalyzer) Name() string {
	return "OpenTelemetry Collector Health Check Disabled"
}

func (a *OTelCollectorHealthCheckDisabledAnalyzer) Version() string {
	return "0.1.0"
}

func (a *OTelCollectorHealthCheckDisabledAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *OTelCollectorHealthCheckDisabledAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	instances, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, instance := range instances {
		pipelineCount, _ := strconv.Atoi(instance.Metadata[model.MetadataOTelPipelineCount])
		if instance.Source.System != "otelcol" ||
			instance.Status != model.ResourceStatusActive ||
			instance.Metadata[model.MetadataOTelCollectorConfigInstance] != "true" ||
			pipelineCount <= 0 ||
			instance.Metadata[model.MetadataOTelHealthCheckEnabled] == "true" {
			continue
		}
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), instance.ID),
			Type:     "OTelCollectorHealthCheckDisabled",
			Severity: model.SeverityWarning,
			Category: model.FindingCategoryReliability,
			Resource: model.ResourceRef{ID: instance.ID, Type: instance.Type, Name: instance.Name},
			Evidence: []string{
				fmt.Sprintf("OpenTelemetry Collector has %d configured service pipeline(s) and no enabled health-check extension", pipelineCount),
			},
			Recommendation: "声明 health_check 扩展并将其加入 service.extensions，再把健康端点接入编排系统的存活/就绪探针；仅声明但未启用不会提供健康检查。",
			Metadata: map[string]string{
				"analyzer_id":    a.ID(),
				"pipeline_count": strconv.Itoa(pipelineCount),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}
