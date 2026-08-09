package analyzer

import (
	"context"
	"fmt"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const OTelScraperErrorsAnalyzerID = "builtin.otelcol_scraper_errors"

type OTelScraperErrorsAnalyzer struct{}

func NewOTelScraperErrorsAnalyzer() *OTelScraperErrorsAnalyzer {
	return &OTelScraperErrorsAnalyzer{}
}

func (a *OTelScraperErrorsAnalyzer) ID() string {
	return OTelScraperErrorsAnalyzerID
}

func (a *OTelScraperErrorsAnalyzer) Name() string {
	return "OpenTelemetry Collector Scraper Errors"
}

func (a *OTelScraperErrorsAnalyzer) Version() string { return "0.1.0" }

func (a *OTelScraperErrorsAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *OTelScraperErrorsAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Status != model.ResourceStatusActive ||
			resource.Source.System != "otelcol" ||
			resource.Metadata[model.MetadataOTelRuntimeMetricsAvailable] != "true" {
			continue
		}
		metricPoints := positiveOTelColRuntimeMetric(resource.Metadata[model.MetadataOTelScraperErroredMetricPoints])
		counterEvidence := otelColRuntimeCounterEvidence(resource.Metadata, model.MetadataOTelScraperErrorDelta)
		if !counterEvidence.shouldReport(metricPoints) ||
			otelColScraperHighErrorRatio(resource.Metadata) {
			continue
		}
		evidence := ""
		if counterEvidence.DeltaAvailable {
			evidence = fmt.Sprintf(
				"OpenTelemetry Collector scraper error counters increased by %s metric point(s) during the latest %s-second successful-scrape interval; the cumulative total is %s",
				formatOTelColRuntimeEvidenceValue(counterEvidence.Delta),
				formatOTelColRuntimeEvidenceValue(counterEvidence.IntervalSeconds),
				formatOTelColRuntimeEvidenceValue(metricPoints),
			)
		} else {
			evidence = fmt.Sprintf(
				"OpenTelemetry Collector scrapers have observed %s metric point collection error(s) since runtime counters were reset",
				formatOTelColRuntimeEvidenceValue(metricPoints),
			)
		}
		findingMetadata := map[string]string{
			"analyzer_id":   a.ID(),
			"metric_points": formatOTelColRuntimeEvidenceValue(metricPoints),
		}
		addOTelColRuntimeCounterEvidence(findingMetadata, counterEvidence)
		findings = append(findings, model.Finding{
			ID:             model.StableID(a.ID(), resource.ID),
			Type:           "OTelScraperErrors",
			Severity:       model.SeverityWarning,
			Category:       model.FindingCategoryReliability,
			Status:         model.FindingStatusOpen,
			Resource:       model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
			Evidence:       []string{evidence},
			Recommendation: "检查 scraper_errored_metric_points 的当前增长率和 Collector 日志，定位失败的 scraper；修复采集源可用性、权限、超时或解析问题，并通过 scraped_metric_points 与目标端数据新鲜度验证采集恢复。",
			Metadata:       findingMetadata,
			CreatedAt:      now,
			UpdatedAt:      now,
		})
	}
	return findings, nil
}
