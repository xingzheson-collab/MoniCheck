package report

import (
	"context"
	"sort"

	"monicheck/internal/costattribution"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	CostAllocationStateAllocated   = costattribution.StateAllocated
	CostAllocationStateUnallocated = costattribution.StateUnallocated
	CostAllocationStateAmbiguous   = costattribution.StateAmbiguous
)

type CostAllocationSummary struct {
	MetricCount            int                       `json:"metric_count"`
	QuantifiedMetricCount  int                       `json:"quantified_metric_count"`
	MeasuredSeries         int64                     `json:"measured_series"`
	PricingConfigured      bool                      `json:"pricing_configured"`
	Currency               string                    `json:"currency"`
	MonthlyPricePerMillion float64                   `json:"monthly_price_per_million_active_series"`
	MeasuredMonthlyCost    *float64                  `json:"measured_monthly_cost,omitempty"`
	Basis                  string                    `json:"basis"`
	Caveats                []string                  `json:"caveats"`
	Dimensions             []CostAllocationDimension `json:"dimensions"`
}

type CostAllocationDimension struct {
	Name              string               `json:"name"`
	AllocatedSeries   int64                `json:"allocated_series"`
	UnallocatedSeries int64                `json:"unallocated_series"`
	AmbiguousSeries   int64                `json:"ambiguous_series"`
	CoveragePercent   float64              `json:"coverage_percent"`
	Items             []CostAllocationItem `json:"items"`
}

type CostAllocationItem struct {
	Key          string   `json:"key"`
	State        string   `json:"state"`
	MetricCount  int      `json:"metric_count"`
	Series       int64    `json:"series"`
	SharePercent float64  `json:"share_percent"`
	Currency     string   `json:"currency,omitempty"`
	MonthlyCost  *float64 `json:"monthly_cost,omitempty"`
}

type costAllocationBucket struct {
	key         string
	state       string
	metricCount int
	series      int64
}

func BuildCostAllocationSummary(ctx context.Context, store *storage.Store, filter storage.ResourceFilter, pricing CostPricing) (CostAllocationSummary, error) {
	pricing = NormalizeCostPricing(pricing)
	filter.Type = model.ResourceTypeMetric
	resources, err := store.Resources.List(ctx, filter)
	if err != nil {
		return CostAllocationSummary{}, err
	}
	summary := CostAllocationSummary{
		PricingConfigured:      pricing.MonthlyPerMillionActiveSeries > 0,
		Currency:               pricing.Currency,
		MonthlyPricePerMillion: pricing.MonthlyPerMillionActiveSeries,
		Basis:                  "connector_metric_active_series",
		Caveats: []string{
			"Allocation covers only active Metric resources with a connector-provided series count.",
			"Each dimension is an independent showback view and must not be summed across dimensions.",
			"Values are governance estimates, not vendor invoice or chargeback records.",
		},
		Dimensions: make([]CostAllocationDimension, 0, len(costattribution.Dimensions())),
	}
	quantified := make([]model.Resource, 0, len(resources))
	for _, resource := range resources {
		if resource.Status != model.ResourceStatusActive {
			continue
		}
		summary.MetricCount++
		if series, ok := positiveStringInt64(resource.Metadata[model.MetadataSeriesCount]); ok {
			summary.QuantifiedMetricCount++
			summary.MeasuredSeries += series
			quantified = append(quantified, resource)
		}
	}
	if summary.PricingConfigured {
		value := roundMoney(float64(summary.MeasuredSeries) / 1_000_000 * pricing.MonthlyPerMillionActiveSeries)
		summary.MeasuredMonthlyCost = &value
	}
	for _, definition := range costattribution.Dimensions() {
		dimension := buildCostAllocationDimension(quantified, definition.Name, summary.MeasuredSeries, pricing)
		summary.Dimensions = append(summary.Dimensions, dimension)
	}
	return summary, nil
}

func buildCostAllocationDimension(resources []model.Resource, name string, totalSeries int64, pricing CostPricing) CostAllocationDimension {
	buckets := map[string]*costAllocationBucket{}
	for _, resource := range resources {
		series, _ := positiveStringInt64(resource.Metadata[model.MetadataSeriesCount])
		state, key, _ := costattribution.Resolve(resource, name)
		switch state {
		case CostAllocationStateUnallocated:
			key = "Unallocated"
		case CostAllocationStateAmbiguous:
			key = "Ambiguous"
		}
		bucketKey := state + "\x00" + key
		bucket := buckets[bucketKey]
		if bucket == nil {
			bucket = &costAllocationBucket{key: key, state: state}
			buckets[bucketKey] = bucket
		}
		bucket.metricCount++
		bucket.series += series
	}
	dimension := CostAllocationDimension{Name: name, Items: make([]CostAllocationItem, 0, len(buckets))}
	for _, bucket := range buckets {
		item := CostAllocationItem{
			Key:          bucket.key,
			State:        bucket.state,
			MetricCount:  bucket.metricCount,
			Series:       bucket.series,
			SharePercent: costAllocationPercent(bucket.series, totalSeries),
		}
		switch bucket.state {
		case CostAllocationStateAllocated:
			dimension.AllocatedSeries += bucket.series
		case CostAllocationStateAmbiguous:
			dimension.AmbiguousSeries += bucket.series
		default:
			dimension.UnallocatedSeries += bucket.series
		}
		if pricing.MonthlyPerMillionActiveSeries > 0 {
			value := roundMoney(float64(bucket.series) / 1_000_000 * pricing.MonthlyPerMillionActiveSeries)
			item.Currency = pricing.Currency
			item.MonthlyCost = &value
		}
		dimension.Items = append(dimension.Items, item)
	}
	dimension.CoveragePercent = costAllocationPercent(dimension.AllocatedSeries, totalSeries)
	sort.Slice(dimension.Items, func(i, j int) bool {
		if dimension.Items[i].Series != dimension.Items[j].Series {
			return dimension.Items[i].Series > dimension.Items[j].Series
		}
		if dimension.Items[i].State != dimension.Items[j].State {
			return dimension.Items[i].State < dimension.Items[j].State
		}
		return dimension.Items[i].Key < dimension.Items[j].Key
	})
	return dimension
}

func costAllocationPercent(value int64, total int64) float64 {
	if value <= 0 || total <= 0 {
		return 0
	}
	return roundMoney(float64(value) / float64(total) * 100)
}
