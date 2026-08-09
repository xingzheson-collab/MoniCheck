package report

import (
	"context"
	"math"
	"sort"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	CostBudgetStateUnpriced      = "UNPRICED"
	CostBudgetStateNotConfigured = "NOT_CONFIGURED"
	CostBudgetStateOnTrack       = "ON_TRACK"
	CostBudgetStateExceeded      = "EXCEEDED"

	CostMetricGuardrailStateWithin   = "WITHIN_GUARDRAIL"
	CostMetricGuardrailStateExceeded = "EXCEEDED"
)

type CostGuardrailConfig struct {
	MonthlyBudget          float64 `json:"monthly_budget"`
	MetricMonthlyGuardrail float64 `json:"metric_monthly_guardrail"`
}

type CostGuardrailSummary struct {
	MetricCount               int                   `json:"metric_count"`
	QuantifiedMetricCount     int                   `json:"quantified_metric_count"`
	MeasuredSeries            int64                 `json:"measured_series"`
	PricingConfigured         bool                  `json:"pricing_configured"`
	BudgetConfigured          bool                  `json:"budget_configured"`
	MetricGuardrailConfigured bool                  `json:"metric_guardrail_configured"`
	Currency                  string                `json:"currency"`
	MonthlyBudget             float64               `json:"monthly_budget"`
	MetricMonthlyGuardrail    float64               `json:"metric_monthly_guardrail"`
	MeasuredMonthlyCost       *float64              `json:"measured_monthly_cost,omitempty"`
	BudgetVariance            *float64              `json:"budget_variance,omitempty"`
	BudgetUtilizationPercent  *float64              `json:"budget_utilization_percent,omitempty"`
	BudgetState               string                `json:"budget_state"`
	ExceededMetricCount       int                   `json:"exceeded_metric_count"`
	Basis                     string                `json:"basis"`
	Caveats                   []string              `json:"caveats"`
	Items                     []CostMetricGuardrail `json:"items"`
}

type CostMetricGuardrail struct {
	Resource       model.ResourceRef `json:"resource"`
	SourceSystem   string            `json:"source_system"`
	ConnectorID    string            `json:"connector_id,omitempty"`
	Series         int64             `json:"series"`
	MonthlyCost    float64           `json:"monthly_cost"`
	GuardrailState string            `json:"guardrail_state"`
}

func NormalizeCostGuardrailConfig(config CostGuardrailConfig) CostGuardrailConfig {
	if config.MonthlyBudget < 0 || math.IsNaN(config.MonthlyBudget) || math.IsInf(config.MonthlyBudget, 0) {
		config.MonthlyBudget = 0
	}
	if config.MetricMonthlyGuardrail < 0 || math.IsNaN(config.MetricMonthlyGuardrail) || math.IsInf(config.MetricMonthlyGuardrail, 0) {
		config.MetricMonthlyGuardrail = 0
	}
	return config
}

func BuildCostGuardrailSummary(ctx context.Context, store *storage.Store, filter storage.ResourceFilter, pricing CostPricing, config CostGuardrailConfig) (CostGuardrailSummary, error) {
	pricing = NormalizeCostPricing(pricing)
	config = NormalizeCostGuardrailConfig(config)
	filter.Type = model.ResourceTypeMetric
	resources, err := store.Resources.List(ctx, filter)
	if err != nil {
		return CostGuardrailSummary{}, err
	}
	summary := CostGuardrailSummary{
		PricingConfigured:         pricing.MonthlyPerMillionActiveSeries > 0,
		BudgetConfigured:          config.MonthlyBudget > 0,
		MetricGuardrailConfigured: config.MetricMonthlyGuardrail > 0,
		Currency:                  pricing.Currency,
		MonthlyBudget:             config.MonthlyBudget,
		MetricMonthlyGuardrail:    config.MetricMonthlyGuardrail,
		BudgetState:               CostBudgetStateUnpriced,
		Basis:                     "connector_metric_active_series",
		Caveats: []string{
			"Measured cost uses connector-provided active series and the configured transparent unit price.",
			"Budget status is a governance estimate, not an invoice, forecast, or chargeback record.",
			"Metrics without a positive series count are excluded from measured cost and guardrail evaluation.",
		},
		Items: []CostMetricGuardrail{},
	}
	for _, resource := range resources {
		if resource.Status != model.ResourceStatusActive {
			continue
		}
		summary.MetricCount++
		series, measured := positiveStringInt64(resource.Metadata[model.MetadataSeriesCount])
		if !measured {
			continue
		}
		summary.QuantifiedMetricCount++
		summary.MeasuredSeries += series
		if !summary.PricingConfigured {
			continue
		}
		monthly := roundMoney(float64(series) / 1_000_000 * pricing.MonthlyPerMillionActiveSeries)
		state := CostMetricGuardrailStateWithin
		if summary.MetricGuardrailConfigured && monthly > config.MetricMonthlyGuardrail {
			state = CostMetricGuardrailStateExceeded
			summary.ExceededMetricCount++
		}
		summary.Items = append(summary.Items, CostMetricGuardrail{
			Resource:       model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
			SourceSystem:   resource.Source.System,
			ConnectorID:    resource.Metadata[model.MetadataConnectorID],
			Series:         series,
			MonthlyCost:    monthly,
			GuardrailState: state,
		})
	}
	if summary.PricingConfigured {
		monthlyTotal := roundMoney(float64(summary.MeasuredSeries) / 1_000_000 * pricing.MonthlyPerMillionActiveSeries)
		summary.MeasuredMonthlyCost = &monthlyTotal
		summary.BudgetState = CostBudgetStateNotConfigured
		if summary.BudgetConfigured {
			variance := roundMoney(monthlyTotal - config.MonthlyBudget)
			utilization := roundMoney(monthlyTotal / config.MonthlyBudget * 100)
			summary.BudgetVariance = &variance
			summary.BudgetUtilizationPercent = &utilization
			summary.BudgetState = CostBudgetStateOnTrack
			if variance > 0 {
				summary.BudgetState = CostBudgetStateExceeded
			}
		}
	}
	sort.Slice(summary.Items, func(i, j int) bool {
		if summary.Items[i].MonthlyCost != summary.Items[j].MonthlyCost {
			return summary.Items[i].MonthlyCost > summary.Items[j].MonthlyCost
		}
		return summary.Items[i].Resource.Name < summary.Items[j].Resource.Name
	})
	return summary, nil
}
