package report

import (
	"context"
	"math"
	"sort"
	"strconv"
	"strings"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	CostOpportunityStatePotential = "POTENTIAL"
	CostOpportunityUnitSeries     = "active_series"
)

type CostPricing struct {
	Currency                      string  `json:"currency"`
	MonthlyPerMillionActiveSeries float64 `json:"monthly_per_million_active_series"`
}

type CostOpportunitySummary struct {
	OpportunityCount         int               `json:"opportunity_count"`
	QuantifiedCount          int               `json:"quantified_count"`
	CurrentSeries            int64             `json:"current_series"`
	PotentialSeriesReduction int64             `json:"potential_series_reduction"`
	PricingConfigured        bool              `json:"pricing_configured"`
	Currency                 string            `json:"currency"`
	MonthlyPricePerMillion   float64           `json:"monthly_price_per_million_active_series"`
	PotentialMonthlySavings  *float64          `json:"potential_monthly_savings,omitempty"`
	Items                    []CostOpportunity `json:"items"`
}

type CostOpportunity struct {
	ID                       string            `json:"id"`
	FindingID                string            `json:"finding_id"`
	FindingType              string            `json:"finding_type"`
	Severity                 model.Severity    `json:"severity"`
	Resource                 model.ResourceRef `json:"resource"`
	SourceSystem             string            `json:"source_system"`
	ConnectorID              string            `json:"connector_id,omitempty"`
	OpportunityType          string            `json:"opportunity_type"`
	SavingsState             string            `json:"savings_state"`
	Unit                     string            `json:"unit"`
	CurrentSeries            int64             `json:"current_series"`
	PotentialSeriesReduction int64             `json:"potential_series_reduction"`
	MeasurementSource        string            `json:"measurement_source"`
	Confidence               string            `json:"confidence"`
	Basis                    string            `json:"basis"`
	Caveats                  []string          `json:"caveats"`
	Currency                 string            `json:"currency,omitempty"`
	PotentialMonthlySavings  *float64          `json:"potential_monthly_savings,omitempty"`
}

func NormalizeCostPricing(pricing CostPricing) CostPricing {
	pricing.Currency = strings.ToUpper(strings.TrimSpace(pricing.Currency))
	if pricing.Currency == "" {
		pricing.Currency = "USD"
	}
	if pricing.MonthlyPerMillionActiveSeries < 0 ||
		math.IsNaN(pricing.MonthlyPerMillionActiveSeries) ||
		math.IsInf(pricing.MonthlyPerMillionActiveSeries, 0) {
		pricing.MonthlyPerMillionActiveSeries = 0
	}
	return pricing
}

func BuildCostOpportunitySummary(ctx context.Context, store *storage.Store, filter storage.ResourceFilter, pricing CostPricing) (CostOpportunitySummary, error) {
	pricing = NormalizeCostPricing(pricing)
	resources, err := store.Resources.List(ctx, filter)
	if err != nil {
		return CostOpportunitySummary{}, err
	}
	findings, err := store.Findings.List(ctx, storage.FindingFilter{})
	if err != nil {
		return CostOpportunitySummary{}, err
	}

	resourcesByID := make(map[string]model.Resource, len(resources))
	for _, resource := range resources {
		resourcesByID[resource.ID] = resource
	}

	// One resource can trigger both opportunities. Removing an unused metric
	// subsumes reducing its cardinality, so keep only the stronger estimate.
	byResource := make(map[string]CostOpportunity)
	for _, finding := range findings {
		if !costOpportunityFindingActive(finding.Status) {
			continue
		}
		resource, ok := resourcesByID[finding.Resource.ID]
		if !ok || resource.Status != model.ResourceStatusActive ||
			resource.Type != model.ResourceTypeMetric {
			continue
		}
		opportunity, ok := costOpportunityForFinding(finding, resource, pricing)
		if !ok {
			continue
		}
		existing, exists := byResource[resource.ID]
		if !exists || costOpportunityPriority(opportunity.OpportunityType) > costOpportunityPriority(existing.OpportunityType) {
			byResource[resource.ID] = opportunity
		}
	}

	summary := CostOpportunitySummary{
		PricingConfigured:      pricing.MonthlyPerMillionActiveSeries > 0,
		Currency:               pricing.Currency,
		MonthlyPricePerMillion: pricing.MonthlyPerMillionActiveSeries,
		Items:                  make([]CostOpportunity, 0, len(byResource)),
	}
	var monthly float64
	for _, opportunity := range byResource {
		summary.OpportunityCount++
		summary.QuantifiedCount++
		summary.CurrentSeries += opportunity.CurrentSeries
		summary.PotentialSeriesReduction += opportunity.PotentialSeriesReduction
		if opportunity.PotentialMonthlySavings != nil {
			monthly += *opportunity.PotentialMonthlySavings
		}
		summary.Items = append(summary.Items, opportunity)
	}
	sort.Slice(summary.Items, func(i, j int) bool {
		if summary.Items[i].PotentialSeriesReduction != summary.Items[j].PotentialSeriesReduction {
			return summary.Items[i].PotentialSeriesReduction > summary.Items[j].PotentialSeriesReduction
		}
		return summary.Items[i].Resource.Name < summary.Items[j].Resource.Name
	})
	if summary.PricingConfigured {
		value := roundMoney(monthly)
		summary.PotentialMonthlySavings = &value
	}
	return summary, nil
}

func costOpportunityForFinding(finding model.Finding, resource model.Resource, pricing CostPricing) (CostOpportunity, bool) {
	current, ok := positiveStringInt64(resource.Metadata[model.MetadataSeriesCount])
	if !ok {
		return CostOpportunity{}, false
	}
	source := strings.TrimSpace(resource.Metadata[model.MetadataSeriesCountSource])
	if source == "" {
		source = "unknown"
	}
	opportunity := CostOpportunity{
		ID:                model.StableID("cost_opportunity", finding.ID),
		FindingID:         finding.ID,
		FindingType:       finding.Type,
		Severity:          finding.Severity,
		Resource:          finding.Resource,
		SourceSystem:      strings.TrimSpace(resource.Source.System),
		ConnectorID:       strings.TrimSpace(resource.Metadata[model.MetadataConnectorID]),
		SavingsState:      CostOpportunityStatePotential,
		Unit:              CostOpportunityUnitSeries,
		CurrentSeries:     current,
		MeasurementSource: source,
		Confidence:        costOpportunityConfidence(source),
		Caveats:           []string{},
	}
	switch finding.Type {
	case "UnusedMetric":
		opportunity.OpportunityType = "REMOVE_UNUSED_METRIC"
		opportunity.PotentialSeriesReduction = current
		opportunity.Basis = "No active Dashboard, Alert, or Recording Rule relationship references this metric."
		opportunity.Caveats = []string{
			"Queries outside connected systems may still use this metric.",
			"Validate with an observation window before stopping collection.",
		}
	case "HighCardinalityMetric":
		threshold, ok := positiveStringInt64(finding.Metadata["threshold"])
		if !ok || current <= threshold {
			return CostOpportunity{}, false
		}
		opportunity.OpportunityType = "REDUCE_HIGH_CARDINALITY"
		opportunity.PotentialSeriesReduction = current - threshold
		opportunity.Basis = "Series above the configured cardinality policy threshold."
		opportunity.Caveats = []string{
			"The policy threshold is a governance target, not a guaranteed removable-series count.",
			"Validate label changes against query and alert dependencies.",
		}
	default:
		return CostOpportunity{}, false
	}
	if pricing.MonthlyPerMillionActiveSeries > 0 {
		value := roundMoney(float64(opportunity.PotentialSeriesReduction) / 1_000_000 * pricing.MonthlyPerMillionActiveSeries)
		opportunity.Currency = pricing.Currency
		opportunity.PotentialMonthlySavings = &value
	}
	return opportunity, true
}

func positiveStringInt64(value string) (int64, bool) {
	parsed, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	return parsed, err == nil && parsed > 0
}

func costOpportunityFindingActive(status model.FindingStatus) bool {
	switch status {
	case model.FindingStatusOpen, model.FindingStatusAcked, model.FindingStatusApproved:
		return true
	default:
		return false
	}
}

func costOpportunityPriority(opportunityType string) int {
	if opportunityType == "REMOVE_UNUSED_METRIC" {
		return 2
	}
	return 1
}

func costOpportunityConfidence(source string) string {
	switch source {
	case "tsdb_head":
		return "MEDIUM"
	case "recent_1h":
		return "LOW"
	default:
		return "LOW"
	}
}

func roundMoney(value float64) float64 {
	return math.Round(value*100) / 100
}
