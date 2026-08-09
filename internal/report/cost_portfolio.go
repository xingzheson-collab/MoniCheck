package report

import (
	"context"
	"sort"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const DefaultCostVerificationSLA = 24 * time.Hour

type CostPortfolioSummary struct {
	PortfolioCount           int                 `json:"portfolio_count"`
	PotentialCount           int                 `json:"potential_count"`
	BaselinedCount           int                 `json:"baselined_count"`
	PendingCount             int                 `json:"pending_count"`
	OverdueCount             int                 `json:"overdue_count"`
	VerifiedCount            int                 `json:"verified_count"`
	ApprovedCount            int                 `json:"approved_count"`
	RealizedCount            int                 `json:"realized_count"`
	NoReductionCount         int                 `json:"no_reduction_count"`
	UnverifiableCount        int                 `json:"unverifiable_count"`
	PotentialSeriesReduction int64               `json:"potential_series_reduction"`
	VerifiedSeriesReduction  int64               `json:"verified_series_reduction"`
	ApprovedSeriesReduction  int64               `json:"approved_series_reduction"`
	RealizedSeriesReduction  int64               `json:"realized_series_reduction"`
	RealizationPercent       float64             `json:"realization_percent"`
	VerificationSLASeconds   int64               `json:"verification_sla_seconds"`
	PricingConfigured        bool                `json:"pricing_configured"`
	Currency                 string              `json:"currency"`
	PotentialMonthlySavings  *float64            `json:"potential_monthly_savings,omitempty"`
	VerifiedMonthlySavings   *float64            `json:"verified_monthly_savings,omitempty"`
	RealizedMonthlySavings   *float64            `json:"realized_monthly_savings,omitempty"`
	Items                    []CostPortfolioItem `json:"items"`
}

type CostPortfolioItem struct {
	FindingID                string            `json:"finding_id"`
	FindingType              string            `json:"finding_type"`
	Resource                 model.ResourceRef `json:"resource"`
	OpportunityType          string            `json:"opportunity_type"`
	State                    string            `json:"state"`
	PotentialSeriesReduction int64             `json:"potential_series_reduction"`
	VerifiedSeriesReduction  int64             `json:"verified_series_reduction"`
	ApprovedSeriesReduction  int64             `json:"approved_series_reduction"`
	RealizedSeriesReduction  int64             `json:"realized_series_reduction"`
	CommitmentID             string            `json:"commitment_id,omitempty"`
	Owner                    string            `json:"owner,omitempty"`
	DueAt                    *time.Time        `json:"due_at,omitempty"`
	RealizedAt               *time.Time        `json:"realized_at,omitempty"`
	BaselineCapturedAt       *time.Time        `json:"baseline_captured_at,omitempty"`
	BaselineAgeSeconds       int64             `json:"baseline_age_seconds"`
	Overdue                  bool              `json:"overdue"`
	MeasurementSource        string            `json:"measurement_source,omitempty"`
	ConnectorID              string            `json:"connector_id,omitempty"`
	Currency                 string            `json:"currency,omitempty"`
	PotentialMonthlySavings  *float64          `json:"potential_monthly_savings,omitempty"`
	VerifiedMonthlySavings   *float64          `json:"verified_monthly_savings,omitempty"`
}

func BuildCostPortfolioSummary(ctx context.Context, store *storage.Store, filter storage.ResourceFilter, pricing CostPricing, verificationSLA time.Duration) (CostPortfolioSummary, error) {
	return BuildCostPortfolioSummaryAt(ctx, store, filter, pricing, verificationSLA, time.Now().UTC())
}

func BuildCostPortfolioSummaryAt(ctx context.Context, store *storage.Store, filter storage.ResourceFilter, pricing CostPricing, verificationSLA time.Duration, now time.Time) (CostPortfolioSummary, error) {
	pricing = NormalizeCostPricing(pricing)
	if verificationSLA <= 0 {
		verificationSLA = DefaultCostVerificationSLA
	}
	opportunities, err := BuildCostOpportunitySummary(ctx, store, filter, pricing)
	if err != nil {
		return CostPortfolioSummary{}, err
	}
	verification, err := BuildCostVerificationSummary(ctx, store, filter, pricing)
	if err != nil {
		return CostPortfolioSummary{}, err
	}
	outcomes, err := BuildCostOutcomeSummaryAt(ctx, store, filter, pricing, now)
	if err != nil {
		return CostPortfolioSummary{}, err
	}

	byFinding := make(map[string]CostPortfolioItem, len(opportunities.Items)+len(verification.Items))
	for _, opportunity := range opportunities.Items {
		byFinding[opportunity.FindingID] = CostPortfolioItem{
			FindingID:                opportunity.FindingID,
			FindingType:              opportunity.FindingType,
			Resource:                 opportunity.Resource,
			OpportunityType:          opportunity.OpportunityType,
			State:                    CostOpportunityStatePotential,
			PotentialSeriesReduction: opportunity.PotentialSeriesReduction,
			MeasurementSource:        opportunity.MeasurementSource,
			ConnectorID:              opportunity.ConnectorID,
			Currency:                 opportunity.Currency,
			PotentialMonthlySavings:  opportunity.PotentialMonthlySavings,
		}
	}
	for _, item := range verification.Items {
		baselineAt := item.BaselineCapturedAt
		age := now.Sub(baselineAt)
		if age < 0 {
			age = 0
		}
		potential := item.PotentialSeriesReduction
		existing, found := byFinding[item.FindingID]
		if potential == 0 && found {
			potential = existing.PotentialSeriesReduction
		}
		potentialSavings := existing.PotentialMonthlySavings
		if pricing.MonthlyPerMillionActiveSeries > 0 && potential > 0 {
			value := roundMoney(float64(potential) / 1_000_000 * pricing.MonthlyPerMillionActiveSeries)
			potentialSavings = &value
		}
		byFinding[item.FindingID] = CostPortfolioItem{
			FindingID:                item.FindingID,
			FindingType:              item.FindingType,
			Resource:                 item.Resource,
			OpportunityType:          item.OpportunityType,
			State:                    item.State,
			PotentialSeriesReduction: potential,
			VerifiedSeriesReduction:  item.VerifiedSeriesReduction,
			BaselineCapturedAt:       &baselineAt,
			BaselineAgeSeconds:       int64(age.Seconds()),
			Overdue:                  CostVerificationNeedsAttention(item.State) && age > verificationSLA,
			MeasurementSource:        item.MeasurementSource,
			ConnectorID:              item.ConnectorID,
			Currency:                 pricing.Currency,
			PotentialMonthlySavings:  potentialSavings,
			VerifiedMonthlySavings:   item.VerifiedMonthlySavings,
		}
	}
	for _, outcome := range outcomes.Items {
		item, found := byFinding[outcome.FindingID]
		if !found {
			item = CostPortfolioItem{
				FindingID: outcome.FindingID, FindingType: outcome.FindingType, Resource: outcome.Resource,
				OpportunityType: outcome.OpportunityType, PotentialSeriesReduction: outcome.PotentialSeriesReduction,
			}
		}
		if outcome.CommitmentID != "" {
			item.State = outcome.State
			item.CommitmentID = outcome.CommitmentID
			item.Owner = outcome.Owner
			item.DueAt = outcome.DueAt
			item.Overdue = outcome.Overdue
			item.ApprovedSeriesReduction = outcome.ApprovedSeriesReduction
			item.RealizedSeriesReduction = outcome.RealizedSeriesReduction
			item.RealizedAt = outcome.RealizedAt
		}
		byFinding[outcome.FindingID] = item
	}

	summary := CostPortfolioSummary{
		VerificationSLASeconds: int64(verificationSLA.Seconds()),
		PricingConfigured:      pricing.MonthlyPerMillionActiveSeries > 0,
		Currency:               pricing.Currency,
		Items:                  make([]CostPortfolioItem, 0, len(byFinding)),
	}
	var potentialMonthly float64
	var verifiedMonthly float64
	var realizedMonthly float64
	for _, item := range byFinding {
		summary.PortfolioCount++
		summary.PotentialSeriesReduction += item.PotentialSeriesReduction
		summary.VerifiedSeriesReduction += item.VerifiedSeriesReduction
		summary.ApprovedSeriesReduction += item.ApprovedSeriesReduction
		summary.RealizedSeriesReduction += item.RealizedSeriesReduction
		if item.BaselineCapturedAt != nil {
			summary.BaselinedCount++
		}
		if item.CommitmentID != "" && item.State != CostOutcomeStateRealized {
			summary.ApprovedCount++
		}
		if item.Overdue {
			summary.OverdueCount++
		}
		switch item.State {
		case CostOpportunityStatePotential:
			summary.PotentialCount++
		case CostVerificationPending:
			summary.PendingCount++
		case CostVerificationVerified:
			summary.VerifiedCount++
		case CostOutcomeStateApproved:
			summary.PendingCount++
		case CostOutcomeStateRealized:
			summary.RealizedCount++
		case CostVerificationNoReduction:
			summary.NoReductionCount++
		default:
			summary.UnverifiableCount++
		}
		if item.PotentialMonthlySavings != nil {
			potentialMonthly += *item.PotentialMonthlySavings
		}
		if item.VerifiedMonthlySavings != nil {
			verifiedMonthly += *item.VerifiedMonthlySavings
		}
		summary.Items = append(summary.Items, item)
	}
	if summary.PotentialSeriesReduction > 0 {
		summary.RealizationPercent = roundPercent(float64(summary.VerifiedSeriesReduction) / float64(summary.PotentialSeriesReduction) * 100)
	}
	if summary.PricingConfigured {
		potential := roundMoney(potentialMonthly)
		verified := roundMoney(verifiedMonthly)
		for _, receipt := range outcomes.Receipts {
			if receipt.RealizedMonthlySavings != nil {
				realizedMonthly += *receipt.RealizedMonthlySavings
			}
		}
		realized := roundMoney(realizedMonthly)
		summary.PotentialMonthlySavings = &potential
		summary.VerifiedMonthlySavings = &verified
		summary.RealizedMonthlySavings = &realized
	}
	sort.Slice(summary.Items, func(i, j int) bool {
		if summary.Items[i].Overdue != summary.Items[j].Overdue {
			return summary.Items[i].Overdue
		}
		if portfolioStatePriority(summary.Items[i].State) != portfolioStatePriority(summary.Items[j].State) {
			return portfolioStatePriority(summary.Items[i].State) < portfolioStatePriority(summary.Items[j].State)
		}
		if summary.Items[i].PotentialSeriesReduction != summary.Items[j].PotentialSeriesReduction {
			return summary.Items[i].PotentialSeriesReduction > summary.Items[j].PotentialSeriesReduction
		}
		return summary.Items[i].Resource.Name < summary.Items[j].Resource.Name
	})
	return summary, nil
}

func CostVerificationNeedsAttention(state string) bool {
	return state == CostVerificationPending || state == CostVerificationUnverifiable
}

func portfolioStatePriority(state string) int {
	switch state {
	case CostOpportunityStatePotential:
		return 0
	case CostVerificationPending:
		return 1
	case CostOutcomeStateApproved:
		return 1
	case CostVerificationUnverifiable:
		return 2
	case CostVerificationNoReduction:
		return 3
	case CostVerificationVerified:
		return 4
	case CostOutcomeStateRealized:
		return 5
	default:
		return 5
	}
}

func roundPercent(value float64) float64 {
	return float64(int64(value*100+0.5)) / 100
}
