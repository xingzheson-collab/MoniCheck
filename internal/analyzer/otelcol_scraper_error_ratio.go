package analyzer

import (
	"context"
	"fmt"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	OTelScraperHighErrorRatioAnalyzerID       = "builtin.otelcol_scraper_high_error_ratio"
	OTelScraperHighErrorRatioThresholdPercent = 10.0
)

type OTelScraperHighErrorRatioAnalyzer struct{}

func NewOTelScraperHighErrorRatioAnalyzer() *OTelScraperHighErrorRatioAnalyzer {
	return &OTelScraperHighErrorRatioAnalyzer{}
}

func (a *OTelScraperHighErrorRatioAnalyzer) ID() string {
	return OTelScraperHighErrorRatioAnalyzerID
}

func (a *OTelScraperHighErrorRatioAnalyzer) Name() string {
	return "OpenTelemetry Collector Scraper High Error Ratio"
}

func (a *OTelScraperHighErrorRatioAnalyzer) Version() string { return "0.1.0" }

func (a *OTelScraperHighErrorRatioAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *OTelScraperHighErrorRatioAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
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
			!otelColScraperHighErrorRatio(resource.Metadata) {
			continue
		}
		errored := positiveOTelColRuntimeMetric(resource.Metadata[model.MetadataOTelScraperErrorDelta])
		scraped := positiveOTelColRuntimeMetric(resource.Metadata[model.MetadataOTelScraperScrapedMetricPointsDelta])
		ratio := positiveOTelColRuntimeMetric(resource.Metadata[model.MetadataOTelScraperErrorRatioPercent])
		interval := positiveOTelColRuntimeMetric(resource.Metadata[model.MetadataOTelRuntimeCounterDeltaIntervalSeconds])
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), resource.ID),
			Type:     "OTelScraperHighErrorRatio",
			Severity: model.SeverityCritical,
			Category: model.FindingCategoryReliability,
			Status:   model.FindingStatusOpen,
			Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
			Evidence: []string{fmt.Sprintf(
				"OpenTelemetry Collector scrapers failed to collect %s metric point(s) and scraped %s during the latest %s-second successful-scrape interval, a %s%% error ratio at or above the %s%% critical threshold",
				formatOTelColRuntimeEvidenceValue(errored),
				formatOTelColRuntimeEvidenceValue(scraped),
				formatOTelColRuntimeEvidenceValue(interval),
				formatOTelColRuntimeEvidenceValue(ratio),
				formatOTelColRuntimeEvidenceValue(OTelScraperHighErrorRatioThresholdPercent),
			)},
			Recommendation: "立即检查 Collector 日志并定位失败的 scraper；修复采集源可用性、权限、超时或解析问题，必要时调整采集频率或水平扩容，并确认错误率回落且 scraped 增量恢复。",
			Metadata: map[string]string{
				"analyzer_id":              a.ID(),
				"errored_delta":            formatOTelColRuntimeEvidenceValue(errored),
				"scraped_delta":            formatOTelColRuntimeEvidenceValue(scraped),
				"error_ratio_percent":      formatOTelColRuntimeEvidenceValue(ratio),
				"threshold_percent":        formatOTelColRuntimeEvidenceValue(OTelScraperHighErrorRatioThresholdPercent),
				"counter_interval_seconds": formatOTelColRuntimeEvidenceValue(interval),
			},
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func otelColScraperHighErrorRatio(metadata map[string]string) bool {
	if metadata[model.MetadataOTelRuntimeCounterDeltaAvailable] != "true" ||
		metadata[model.MetadataOTelScraperErrorRatioEvaluable] != "true" {
		return false
	}
	errored := positiveOTelColRuntimeMetric(metadata[model.MetadataOTelScraperErrorDelta])
	ratio := positiveOTelColRuntimeMetric(metadata[model.MetadataOTelScraperErrorRatioPercent])
	return errored > 0 && ratio >= OTelScraperHighErrorRatioThresholdPercent
}
