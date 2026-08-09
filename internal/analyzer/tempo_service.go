package analyzer

import (
	"context"
	"fmt"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const TempoServiceDiscoveryTruncatedAnalyzerID = "builtin.tempo_service_discovery_truncated"

type TempoServiceDiscoveryTruncatedAnalyzer struct{}

func NewTempoServiceDiscoveryTruncatedAnalyzer() *TempoServiceDiscoveryTruncatedAnalyzer {
	return &TempoServiceDiscoveryTruncatedAnalyzer{}
}

func (a *TempoServiceDiscoveryTruncatedAnalyzer) ID() string {
	return TempoServiceDiscoveryTruncatedAnalyzerID
}

func (a *TempoServiceDiscoveryTruncatedAnalyzer) Name() string {
	return "Tempo Service Discovery Truncated"
}

func (a *TempoServiceDiscoveryTruncatedAnalyzer) Version() string {
	return "0.1.0"
}

func (a *TempoServiceDiscoveryTruncatedAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTraceTag}
}

func (a *TempoServiceDiscoveryTruncatedAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	tags, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTraceTag})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, tag := range tags {
		if tag.Status != model.ResourceStatusActive ||
			tag.Source.System != "tempo" ||
			!isTempoServiceIdentityTag(tag.Name) ||
			tag.Metadata[model.MetadataValueDiscoveryAvailable] != "true" ||
			tag.Metadata[model.MetadataTraceServiceDiscoveryTruncated] != "true" {
			continue
		}
		count := tag.Metadata[model.MetadataTraceServiceCount]
		limit := tag.Metadata[model.MetadataTraceServiceLimit]
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), tag.ID),
			Type:     "TempoServiceDiscoveryTruncated",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{ID: tag.ID, Type: tag.Type, Name: tag.Name},
			Evidence: []string{
				fmt.Sprintf("Tempo service discovery through %q reached limit %s and retained at least %s services", tag.Name, limit, count),
				fmt.Sprintf("discovery lookback is %s; the service catalog is incomplete for this snapshot", tag.Metadata[model.MetadataTraceLookback]),
			},
			Recommendation: "检查 service.name 基数和服务命名稳定性；若服务数量合理，调高 tempo_tag_value_limit，并确保 Tempo 查询前端能覆盖配置的 lookback 窗口。",
			Metadata: map[string]string{
				"analyzer_id": a.ID(),
				"count":       count,
				"limit":       limit,
				"lookback":    tag.Metadata[model.MetadataTraceLookback],
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func isTempoServiceIdentityTag(tag string) bool {
	return tag == "service.name" || tag == "resource.service.name"
}
