package report

import (
	"context"
	"encoding/json"
	"math"
	"sort"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	DefaultCostMetricDriftLookback        = 7 * 24 * time.Hour
	DefaultCostMetricGrowthRatioThreshold = 0.20
	DefaultCostMetricGrowthMinimum        = int64(1000)
)

type CostMetricDriftConfig struct {
	Lookback             time.Duration `json:"lookback"`
	GrowthRatioThreshold float64       `json:"growth_ratio_threshold"`
	GrowthMinimum        int64         `json:"growth_minimum"`
}

type CostMetricSeriesSnapshot struct {
	Resource          model.ResourceRef `json:"resource"`
	SourceSystem      string            `json:"source_system"`
	ConnectorID       string            `json:"connector_id"`
	MeasurementSource string            `json:"measurement_source"`
	MeasuredAt        time.Time         `json:"measured_at"`
	Series            int64             `json:"series"`
}

type CostMetricDriftSummary struct {
	BaselineFound          bool                  `json:"baseline_found"`
	BaselineAt             *time.Time            `json:"baseline_at,omitempty"`
	LookbackSeconds        int64                 `json:"lookback_seconds"`
	GrowthRatioThreshold   float64               `json:"growth_ratio_threshold"`
	GrowthMinimum          int64                 `json:"growth_minimum"`
	CurrentQuantifiedCount int                   `json:"current_quantified_count"`
	ComparedMetricCount    int                   `json:"compared_metric_count"`
	DriftMetricCount       int                   `json:"drift_metric_count"`
	SeriesIncrease         int64                 `json:"series_increase"`
	PricingConfigured      bool                  `json:"pricing_configured"`
	Currency               string                `json:"currency"`
	MonthlyCostIncrease    *float64              `json:"monthly_cost_increase,omitempty"`
	Basis                  string                `json:"basis"`
	Caveats                []string              `json:"caveats"`
	Items                  []CostMetricDriftItem `json:"items"`
}

type CostMetricDriftItem struct {
	Resource            model.ResourceRef `json:"resource"`
	SourceSystem        string            `json:"source_system"`
	ConnectorID         string            `json:"connector_id"`
	MeasurementSource   string            `json:"measurement_source"`
	BaselineAt          time.Time         `json:"baseline_at"`
	BaselineSeries      int64             `json:"baseline_series"`
	CurrentSeries       int64             `json:"current_series"`
	SeriesIncrease      int64             `json:"series_increase"`
	GrowthPercent       float64           `json:"growth_percent"`
	Currency            string            `json:"currency,omitempty"`
	MonthlyCostIncrease *float64          `json:"monthly_cost_increase,omitempty"`
}

type CostMetricSeriesBaseline struct {
	CostMetricSeriesSnapshot
	SnapshotAt time.Time
}

func NormalizeCostMetricDriftConfig(config CostMetricDriftConfig) CostMetricDriftConfig {
	if config.Lookback <= 0 {
		config.Lookback = DefaultCostMetricDriftLookback
	}
	if config.GrowthRatioThreshold < 0 || math.IsNaN(config.GrowthRatioThreshold) || math.IsInf(config.GrowthRatioThreshold, 0) {
		config.GrowthRatioThreshold = DefaultCostMetricGrowthRatioThreshold
	}
	if config.GrowthMinimum <= 0 {
		config.GrowthMinimum = DefaultCostMetricGrowthMinimum
	}
	return config
}

func BuildCostMetricSeriesSnapshot(ctx context.Context, store *storage.Store, filter storage.ResourceFilter) ([]CostMetricSeriesSnapshot, error) {
	filter.Type = model.ResourceTypeMetric
	resources, err := store.Resources.List(ctx, filter)
	if err != nil {
		return nil, err
	}
	items := make([]CostMetricSeriesSnapshot, 0, len(resources))
	for _, resource := range resources {
		if resource.Status != model.ResourceStatusActive {
			continue
		}
		series, measured := positiveStringInt64(resource.Metadata[model.MetadataSeriesCount])
		if !measured {
			continue
		}
		connectorID := strings.TrimSpace(resource.Metadata[model.MetadataConnectorID])
		measurementSource := strings.TrimSpace(resource.Metadata[model.MetadataSeriesCountSource])
		if connectorID == "" || measurementSource == "" {
			continue
		}
		items = append(items, CostMetricSeriesSnapshot{
			Resource:          model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
			SourceSystem:      strings.TrimSpace(resource.Source.System),
			ConnectorID:       connectorID,
			MeasurementSource: measurementSource,
			MeasuredAt:        resource.UpdatedAt,
			Series:            series,
		})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Series != items[j].Series {
			return items[i].Series > items[j].Series
		}
		return items[i].Resource.ID < items[j].Resource.ID
	})
	return items, nil
}

func LatestCostMetricSeriesBaselines(ctx context.Context, repository storage.ReportExportRepository, since time.Time) (map[string]CostMetricSeriesBaseline, time.Time, error) {
	exports, err := repository.List(ctx)
	if err != nil {
		return nil, time.Time{}, err
	}
	sort.Slice(exports, func(i, j int) bool { return exports[i].CreatedAt.After(exports[j].CreatedAt) })
	baselines := map[string]CostMetricSeriesBaseline{}
	var latestAt time.Time
	for _, export := range exports {
		if export.Type != "cost" || export.Format != "json" || export.CreatedAt.Before(since) {
			continue
		}
		var payload struct {
			Metrics []CostMetricSeriesSnapshot `json:"cost_metric_series"`
		}
		if err := json.Unmarshal([]byte(export.Content), &payload); err != nil {
			continue
		}
		for _, item := range payload.Metrics {
			id := strings.TrimSpace(item.Resource.ID)
			if id == "" || item.Resource.Type != model.ResourceTypeMetric || item.Series <= 0 ||
				strings.TrimSpace(item.ConnectorID) == "" || strings.TrimSpace(item.MeasurementSource) == "" {
				continue
			}
			if _, alreadySelected := baselines[id]; alreadySelected {
				continue
			}
			baselines[id] = CostMetricSeriesBaseline{
				CostMetricSeriesSnapshot: item,
				SnapshotAt:               export.CreatedAt,
			}
			if latestAt.IsZero() || export.CreatedAt.After(latestAt) {
				latestAt = export.CreatedAt
			}
		}
	}
	return baselines, latestAt, nil
}

func BuildCostMetricDriftSummary(ctx context.Context, store *storage.Store, filter storage.ResourceFilter, pricing CostPricing, config CostMetricDriftConfig) (CostMetricDriftSummary, error) {
	pricing = NormalizeCostPricing(pricing)
	config = NormalizeCostMetricDriftConfig(config)
	summary := CostMetricDriftSummary{
		LookbackSeconds:      int64(config.Lookback.Seconds()),
		GrowthRatioThreshold: config.GrowthRatioThreshold,
		GrowthMinimum:        config.GrowthMinimum,
		PricingConfigured:    pricing.MonthlyPerMillionActiveSeries > 0,
		Currency:             pricing.Currency,
		Basis:                "saved_cost_snapshot_same_metric_connector_measurement_source",
		Caveats: []string{
			"Drift requires a saved Cost JSON snapshot and a newer connector measurement.",
			"Only exact Metric resource, Connector, and measurement-source matches are compared.",
			"Cost deltas are governance estimates, not invoice or forecast changes.",
		},
		Items: []CostMetricDriftItem{},
	}
	current, err := BuildCostMetricSeriesSnapshot(ctx, store, filter)
	if err != nil {
		return CostMetricDriftSummary{}, err
	}
	summary.CurrentQuantifiedCount = len(current)
	if store.ReportExports == nil {
		return summary, nil
	}
	baseline, baselineAt, err := LatestCostMetricSeriesBaselines(ctx, store.ReportExports, time.Now().UTC().Add(-config.Lookback))
	if err != nil || len(baseline) == 0 {
		return summary, err
	}
	summary.BaselineFound = true
	summary.BaselineAt = &baselineAt
	var monthlyIncrease float64
	for _, item := range current {
		previous, found := baseline[item.Resource.ID]
		if !found || previous.ConnectorID != item.ConnectorID ||
			previous.MeasurementSource != item.MeasurementSource ||
			!item.MeasuredAt.After(previous.SnapshotAt) {
			continue
		}
		summary.ComparedMetricCount++
		if item.Series <= previous.Series {
			continue
		}
		increase := item.Series - previous.Series
		ratio := float64(increase) / float64(previous.Series)
		if increase < config.GrowthMinimum || ratio < config.GrowthRatioThreshold {
			continue
		}
		drift := CostMetricDriftItem{
			Resource:          item.Resource,
			SourceSystem:      item.SourceSystem,
			ConnectorID:       item.ConnectorID,
			MeasurementSource: item.MeasurementSource,
			BaselineAt:        previous.SnapshotAt,
			BaselineSeries:    previous.Series,
			CurrentSeries:     item.Series,
			SeriesIncrease:    increase,
			GrowthPercent:     roundMoney(ratio * 100),
		}
		if summary.PricingConfigured {
			value := roundMoney(float64(increase) / 1_000_000 * pricing.MonthlyPerMillionActiveSeries)
			drift.Currency = pricing.Currency
			drift.MonthlyCostIncrease = &value
			monthlyIncrease += value
		}
		summary.DriftMetricCount++
		summary.SeriesIncrease += increase
		summary.Items = append(summary.Items, drift)
	}
	if summary.PricingConfigured {
		value := roundMoney(monthlyIncrease)
		summary.MonthlyCostIncrease = &value
	}
	sort.Slice(summary.Items, func(i, j int) bool {
		if summary.Items[i].SeriesIncrease != summary.Items[j].SeriesIncrease {
			return summary.Items[i].SeriesIncrease > summary.Items[j].SeriesIncrease
		}
		return summary.Items[i].Resource.Name < summary.Items[j].Resource.Name
	})
	return summary, nil
}
