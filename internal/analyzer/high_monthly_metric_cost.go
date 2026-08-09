package analyzer

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const HighMonthlyMetricCostAnalyzerID = "builtin.high_monthly_metric_cost"

type HighMonthlyMetricCostAnalyzer struct{}

func NewHighMonthlyMetricCostAnalyzer() *HighMonthlyMetricCostAnalyzer {
	return &HighMonthlyMetricCostAnalyzer{}
}

func (a *HighMonthlyMetricCostAnalyzer) ID() string {
	return HighMonthlyMetricCostAnalyzerID
}

func (a *HighMonthlyMetricCostAnalyzer) Name() string {
	return "High Monthly Metric Cost"
}

func (a *HighMonthlyMetricCostAnalyzer) Version() string {
	return "0.1.0"
}

func (a *HighMonthlyMetricCostAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeMetric}
}

func (a *HighMonthlyMetricCostAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	price := floatConfig(analysis.Config, "cost_monthly_price_per_million_series", 0)
	guardrail := floatConfig(analysis.Config, "cost_metric_monthly_guardrail", 0)
	if price <= 0 || guardrail <= 0 {
		return []model.Finding{}, nil
	}
	currency := strings.ToUpper(strings.TrimSpace(monthlyMetricCostStringConfig(analysis.Config, "cost_currency", "USD")))
	if len(currency) != 3 {
		currency = "USD"
	}
	metrics, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeMetric})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, metric := range metrics {
		if !isActiveMetric(metric) {
			continue
		}
		series, measured := metricSeriesCount(metric)
		if !measured || series <= 0 {
			continue
		}
		monthly := math.Round(float64(series)/1_000_000*price*100) / 100
		if monthly <= guardrail {
			continue
		}
		findings = append(findings, model.Finding{
			ID:             model.StableID(a.ID(), metric.ID),
			Type:           "HighMonthlyMetricCost",
			Severity:       model.SeverityWarning,
			Resource:       model.ResourceRef{ID: metric.ID, Type: metric.Type, Name: metric.Name},
			Evidence:       []string{fmt.Sprintf("metric %q has %d measured series with an estimated monthly cost of %.2f %s, above the %.2f %s guardrail", metric.Name, series, monthly, currency, guardrail, currency)},
			Recommendation: "确认该指标的业务价值和查询依赖；优先删除未使用 series、限制高基数标签，或在采集侧减少不必要的数据量。",
			Metadata: map[string]string{
				"analyzer_id":            a.ID(),
				"series_count":           strconv.Itoa(series),
				"series_count_source":    metricSeriesCountSource(metric),
				"estimated_monthly_cost": strconv.FormatFloat(monthly, 'f', 2, 64),
				"monthly_cost_guardrail": strconv.FormatFloat(guardrail, 'f', 2, 64),
				"currency":               currency,
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func monthlyMetricCostStringConfig(config map[string]any, key string, fallback string) string {
	value, ok := config[key]
	if !ok {
		return fallback
	}
	typed, ok := value.(string)
	if !ok || strings.TrimSpace(typed) == "" {
		return fallback
	}
	return typed
}
