package analyzer

import (
	"context"
	"fmt"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const OTelCollectorRuntimeRestartAnalyzerID = "builtin.otelcol_runtime_restart"

type OTelCollectorRuntimeRestartAnalyzer struct{}

func NewOTelCollectorRuntimeRestartAnalyzer() *OTelCollectorRuntimeRestartAnalyzer {
	return &OTelCollectorRuntimeRestartAnalyzer{}
}

func (a *OTelCollectorRuntimeRestartAnalyzer) ID() string {
	return OTelCollectorRuntimeRestartAnalyzerID
}

func (a *OTelCollectorRuntimeRestartAnalyzer) Name() string {
	return "OpenTelemetry Collector Runtime Restart"
}

func (a *OTelCollectorRuntimeRestartAnalyzer) Version() string { return "0.1.0" }

func (a *OTelCollectorRuntimeRestartAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *OTelCollectorRuntimeRestartAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Status != model.ResourceStatusActive ||
			resource.Source.System != "otelcol" ||
			resource.Metadata[model.MetadataOTelRuntimeMetricsAvailable] != "true" ||
			resource.Metadata[model.MetadataOTelProcessUptimeMetricsAvailable] != "true" ||
			resource.Metadata[model.MetadataOTelRuntimeRestartEvaluable] != "true" ||
			resource.Metadata[model.MetadataOTelRuntimeRestartObserved] != "true" {
			continue
		}
		interval := positiveOTelColRuntimeMetric(resource.Metadata[model.MetadataOTelRuntimeCounterDeltaIntervalSeconds])
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), resource.ID),
			Type:     "OTelCollectorRuntimeRestart",
			Severity: model.SeverityWarning,
			Category: model.FindingCategoryReliability,
			Status:   model.FindingStatusOpen,
			Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
			Evidence: []string{fmt.Sprintf(
				"The OpenTelemetry Collector process uptime counter moved backwards during the latest %s-second successful-scrape interval, proving that the runtime restarted",
				formatOTelColRuntimeEvidenceValue(interval),
			)},
			Recommendation: "检查 Collector 重启原因、容器退出状态、OOM、部署变更和启动日志；确认所有 pipeline、队列与客户端重试均已恢复，并验证重启期间不存在遥测缺口。",
			Metadata: map[string]string{
				"analyzer_id":              a.ID(),
				"restart_observed":         "true",
				"counter_interval_seconds": formatOTelColRuntimeEvidenceValue(interval),
			},
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}
