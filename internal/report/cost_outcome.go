package report

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	CostOptimizationApprovedAction  = "cost_optimization_approved"
	CostOptimizationCancelledAction = "cost_optimization_cancelled"
	CostOutcomeRealizedAction       = "cost_outcome_realized"

	CostOutcomeStateApproved = "APPROVED"
	CostOutcomeStateRealized = "REALIZED"
)

type CostOutcomeSummary struct {
	OpportunityCount          int                  `json:"opportunity_count"`
	ApprovedCount             int                  `json:"approved_count"`
	VerifiedCount             int                  `json:"verified_count"`
	RealizedCount             int                  `json:"realized_count"`
	OverdueCommitmentCount    int                  `json:"overdue_commitment_count"`
	PotentialSeriesReduction  int64                `json:"potential_series_reduction"`
	ApprovedSeriesReduction   int64                `json:"approved_series_reduction"`
	VerifiedSeriesReduction   int64                `json:"verified_series_reduction"`
	RealizedSeriesReduction   int64                `json:"realized_series_reduction"`
	RealizedPercentOfApproved float64              `json:"realized_percent_of_approved"`
	PricingConfigured         bool                 `json:"pricing_configured"`
	Currency                  string               `json:"currency"`
	ApprovedMonthlySavings    *float64             `json:"approved_monthly_savings,omitempty"`
	VerifiedMonthlySavings    *float64             `json:"verified_monthly_savings,omitempty"`
	RealizedMonthlySavings    *float64             `json:"realized_monthly_savings,omitempty"`
	Items                     []CostOutcomeItem    `json:"items"`
	Receipts                  []CostOutcomeReceipt `json:"receipts"`
}

type CostOutcomeItem struct {
	FindingID                string            `json:"finding_id"`
	FindingType              string            `json:"finding_type"`
	Resource                 model.ResourceRef `json:"resource"`
	OpportunityType          string            `json:"opportunity_type"`
	State                    string            `json:"state"`
	CommitmentID             string            `json:"commitment_id,omitempty"`
	Owner                    string            `json:"owner,omitempty"`
	Reason                   string            `json:"reason,omitempty"`
	ApprovedAt               *time.Time        `json:"approved_at,omitempty"`
	DueAt                    *time.Time        `json:"due_at,omitempty"`
	Overdue                  bool              `json:"overdue"`
	PotentialSeriesReduction int64             `json:"potential_series_reduction"`
	ApprovedSeriesReduction  int64             `json:"approved_series_reduction"`
	VerifiedSeriesReduction  int64             `json:"verified_series_reduction"`
	RealizedSeriesReduction  int64             `json:"realized_series_reduction"`
	VerificationState        string            `json:"verification_state,omitempty"`
	VerificationMethod       string            `json:"verification_method,omitempty"`
	MeasurementSource        string            `json:"measurement_source,omitempty"`
	ConnectorID              string            `json:"connector_id,omitempty"`
	Currency                 string            `json:"currency,omitempty"`
	ApprovedMonthlySavings   *float64          `json:"approved_monthly_savings,omitempty"`
	VerifiedMonthlySavings   *float64          `json:"verified_monthly_savings,omitempty"`
	RealizedMonthlySavings   *float64          `json:"realized_monthly_savings,omitempty"`
	RealizedAt               *time.Time        `json:"realized_at,omitempty"`
	AcceptedBy               string            `json:"accepted_by,omitempty"`
}

type CostOutcomeReceipt struct {
	ID                      string            `json:"id"`
	CommitmentID            string            `json:"commitment_id"`
	FindingID               string            `json:"finding_id"`
	FindingType             string            `json:"finding_type"`
	Resource                model.ResourceRef `json:"resource"`
	OpportunityType         string            `json:"opportunity_type"`
	Owner                   string            `json:"owner"`
	AcceptedBy              string            `json:"accepted_by"`
	AcceptanceNote          string            `json:"acceptance_note,omitempty"`
	ApprovedSeriesReduction int64             `json:"approved_series_reduction"`
	BaselineSeries          int64             `json:"baseline_series"`
	CurrentSeries           int64             `json:"current_series"`
	RealizedSeriesReduction int64             `json:"realized_series_reduction"`
	VerificationMethod      string            `json:"verification_method"`
	MeasurementSource       string            `json:"measurement_source"`
	ConnectorID             string            `json:"connector_id,omitempty"`
	EvidenceSnapshotID      string            `json:"evidence_snapshot_id,omitempty"`
	MeasurementAt           time.Time         `json:"measurement_at,omitempty"`
	Currency                string            `json:"currency,omitempty"`
	RealizedMonthlySavings  *float64          `json:"realized_monthly_savings,omitempty"`
	RealizedAt              time.Time         `json:"realized_at"`
}

func BuildCostOutcomeSummary(ctx context.Context, store *storage.Store, filter storage.ResourceFilter, pricing CostPricing) (CostOutcomeSummary, error) {
	return BuildCostOutcomeSummaryAt(ctx, store, filter, pricing, time.Now().UTC())
}

func BuildCostOutcomeSummaryAt(ctx context.Context, store *storage.Store, filter storage.ResourceFilter, pricing CostPricing, now time.Time) (CostOutcomeSummary, error) {
	pricing = NormalizeCostPricing(pricing)
	opportunities, err := BuildCostOpportunitySummary(ctx, store, filter, pricing)
	if err != nil {
		return CostOutcomeSummary{}, err
	}
	verification, err := BuildCostVerificationSummary(ctx, store, filter, pricing)
	if err != nil {
		return CostOutcomeSummary{}, err
	}
	summary := CostOutcomeSummary{
		PricingConfigured: pricing.MonthlyPerMillionActiveSeries > 0,
		Currency:          pricing.Currency,
		Items:             []CostOutcomeItem{},
		Receipts:          []CostOutcomeReceipt{},
	}
	byFinding := make(map[string]CostOutcomeItem, len(opportunities.Items)+len(verification.Items))
	for _, opportunity := range opportunities.Items {
		byFinding[opportunity.FindingID] = CostOutcomeItem{
			FindingID:                opportunity.FindingID,
			FindingType:              opportunity.FindingType,
			Resource:                 opportunity.Resource,
			OpportunityType:          opportunity.OpportunityType,
			State:                    CostOpportunityStatePotential,
			PotentialSeriesReduction: opportunity.PotentialSeriesReduction,
			MeasurementSource:        opportunity.MeasurementSource,
			ConnectorID:              opportunity.ConnectorID,
			Currency:                 opportunity.Currency,
		}
	}
	verificationByFinding := make(map[string]CostVerification, len(verification.Items))
	for _, item := range verification.Items {
		verificationByFinding[item.FindingID] = item
		existing := byFinding[item.FindingID]
		existing.FindingID = item.FindingID
		existing.FindingType = item.FindingType
		existing.Resource = item.Resource
		existing.OpportunityType = item.OpportunityType
		existing.State = item.State
		existing.VerificationState = item.State
		existing.VerifiedSeriesReduction = item.VerifiedSeriesReduction
		existing.VerificationMethod = item.VerificationMethod
		existing.MeasurementSource = item.MeasurementSource
		existing.ConnectorID = item.ConnectorID
		existing.Currency = item.Currency
		existing.VerifiedMonthlySavings = item.VerifiedMonthlySavings
		if existing.PotentialSeriesReduction == 0 {
			existing.PotentialSeriesReduction = item.PotentialSeriesReduction
		}
		byFinding[item.FindingID] = existing
	}

	events := []model.FindingWorkflowEvent{}
	if store.FindingWorkflow != nil {
		events, err = store.FindingWorkflow.List(ctx, "")
		if err != nil {
			return CostOutcomeSummary{}, err
		}
	}
	var allowedResources map[string]bool
	if resourceFilterConfigured(filter) {
		resources, listErr := store.Resources.List(ctx, filter)
		if listErr != nil {
			return CostOutcomeSummary{}, listErr
		}
		allowedResources = make(map[string]bool, len(resources))
		for _, resource := range resources {
			allowedResources[resource.ID] = true
		}
	}
	cancelled := map[string]bool{}
	realized := map[string]CostOutcomeReceipt{}
	approvals := map[string]model.FindingWorkflowEvent{}
	for _, event := range events {
		if allowedResources != nil && !allowedResources[event.Metadata["resource_id"]] {
			continue
		}
		commitmentID := strings.TrimSpace(event.Metadata["commitment_id"])
		switch event.Action {
		case CostOptimizationCancelledAction:
			if commitmentID != "" {
				cancelled[commitmentID] = true
			}
		case CostOutcomeRealizedAction:
			receipt := costOutcomeReceiptFromEvent(event)
			if receipt.CommitmentID != "" {
				if current, found := realized[receipt.CommitmentID]; !found || receipt.RealizedAt.After(current.RealizedAt) {
					realized[receipt.CommitmentID] = receipt
				}
			}
		case CostOptimizationApprovedAction:
			approvals[event.ID] = event
		}
	}
	for _, receipt := range realized {
		summary.Receipts = append(summary.Receipts, receipt)
	}
	sort.Slice(summary.Receipts, func(i, j int) bool {
		return summary.Receipts[i].RealizedAt.After(summary.Receipts[j].RealizedAt)
	})

	latestApprovalByFinding := map[string]model.FindingWorkflowEvent{}
	for id, event := range approvals {
		if cancelled[id] {
			continue
		}
		current, found := latestApprovalByFinding[event.FindingID]
		if !found || event.CreatedAt.After(current.CreatedAt) {
			latestApprovalByFinding[event.FindingID] = event
		}
	}
	for findingID, approval := range latestApprovalByFinding {
		item := byFinding[findingID]
		item = applyCostApproval(item, approval, now)
		if receipt, found := realized[approval.ID]; found {
			item.State = CostOutcomeStateRealized
			item.RealizedSeriesReduction = receipt.RealizedSeriesReduction
			item.RealizedMonthlySavings = receipt.RealizedMonthlySavings
			item.RealizedAt = &receipt.RealizedAt
			item.AcceptedBy = receipt.AcceptedBy
			item.Overdue = false
		} else if verificationItem, found := verificationByFinding[findingID]; found {
			item.VerificationState = verificationItem.State
			item.VerifiedSeriesReduction = verificationItem.VerifiedSeriesReduction
			item.VerifiedMonthlySavings = verificationItem.VerifiedMonthlySavings
			item.VerificationMethod = verificationItem.VerificationMethod
			if verificationItem.State == CostVerificationVerified {
				item.State = CostVerificationVerified
			}
		}
		byFinding[findingID] = item
	}

	var approvedMonthly, verifiedMonthly, realizedMonthly float64
	for commitmentID, approval := range approvals {
		if cancelled[commitmentID] {
			continue
		}
		summary.ApprovedCount++
		summary.ApprovedSeriesReduction += positiveStringInt64OrZero(approval.Metadata["approved_series_reduction"])
		if value, ok := positiveStringFloat64(approval.Metadata["approved_monthly_savings"]); ok {
			approvedMonthly += value
		}
	}
	for _, item := range byFinding {
		summary.OpportunityCount++
		summary.PotentialSeriesReduction += item.PotentialSeriesReduction
		if item.CommitmentID != "" && item.State != CostOutcomeStateRealized {
			if item.Overdue {
				summary.OverdueCommitmentCount++
			}
		}
		if item.VerificationState == CostVerificationVerified {
			summary.VerifiedCount++
			summary.VerifiedSeriesReduction += item.VerifiedSeriesReduction
			if item.VerifiedMonthlySavings != nil {
				verifiedMonthly += *item.VerifiedMonthlySavings
			}
		}
		summary.Items = append(summary.Items, item)
	}
	for _, receipt := range summary.Receipts {
		summary.RealizedCount++
		summary.RealizedSeriesReduction += receipt.RealizedSeriesReduction
		if receipt.RealizedMonthlySavings != nil {
			realizedMonthly += *receipt.RealizedMonthlySavings
		}
	}
	if summary.ApprovedSeriesReduction > 0 {
		summary.RealizedPercentOfApproved = roundPercent(float64(summary.RealizedSeriesReduction) / float64(summary.ApprovedSeriesReduction) * 100)
	}
	if summary.PricingConfigured {
		approved, verified, realizedValue := roundMoney(approvedMonthly), roundMoney(verifiedMonthly), roundMoney(realizedMonthly)
		summary.ApprovedMonthlySavings = &approved
		summary.VerifiedMonthlySavings = &verified
		summary.RealizedMonthlySavings = &realizedValue
	}
	sort.Slice(summary.Items, func(i, j int) bool {
		if summary.Items[i].Overdue != summary.Items[j].Overdue {
			return summary.Items[i].Overdue
		}
		if costOutcomeStatePriority(summary.Items[i].State) != costOutcomeStatePriority(summary.Items[j].State) {
			return costOutcomeStatePriority(summary.Items[i].State) < costOutcomeStatePriority(summary.Items[j].State)
		}
		return summary.Items[i].PotentialSeriesReduction > summary.Items[j].PotentialSeriesReduction
	})
	return summary, nil
}

func resourceFilterConfigured(filter storage.ResourceFilter) bool {
	return filter.Type != "" || strings.TrimSpace(filter.Team) != "" || strings.TrimSpace(filter.Project) != "" ||
		strings.TrimSpace(filter.Namespace) != "" || strings.TrimSpace(filter.Cluster) != ""
}

func ActiveCostCommitment(summary CostOutcomeSummary, findingID string) (CostOutcomeItem, bool) {
	for _, item := range summary.Items {
		if item.FindingID == findingID && item.CommitmentID != "" && item.State != CostOutcomeStateRealized {
			return item, true
		}
	}
	return CostOutcomeItem{}, false
}

func applyCostApproval(item CostOutcomeItem, event model.FindingWorkflowEvent, now time.Time) CostOutcomeItem {
	item.FindingID = event.FindingID
	item.FindingType = firstNonEmpty(item.FindingType, event.Metadata["finding_type"])
	if item.Resource.ID == "" {
		item.Resource = model.ResourceRef{
			ID: event.Metadata["resource_id"], Type: model.ResourceType(event.Metadata["resource_type"]), Name: event.Metadata["resource_name"],
		}
	}
	item.OpportunityType = firstNonEmpty(item.OpportunityType, event.Metadata["opportunity_type"])
	item.State = CostOutcomeStateApproved
	item.CommitmentID = event.ID
	item.Owner = event.Metadata["owner"]
	item.Reason = event.Note
	approvedAt := event.CreatedAt
	item.ApprovedAt = &approvedAt
	if dueAt, ok := parseRFC3339(event.Metadata["due_at"]); ok {
		item.DueAt = &dueAt
		item.Overdue = now.After(dueAt)
	}
	item.ApprovedSeriesReduction = positiveStringInt64OrZero(event.Metadata["approved_series_reduction"])
	if item.PotentialSeriesReduction == 0 {
		item.PotentialSeriesReduction = positiveStringInt64OrZero(event.Metadata["potential_series_reduction"])
	}
	if value, ok := positiveStringFloat64(event.Metadata["approved_monthly_savings"]); ok {
		rounded := roundMoney(value)
		item.ApprovedMonthlySavings = &rounded
	}
	item.MeasurementSource = firstNonEmpty(item.MeasurementSource, event.Metadata["measurement_source"])
	item.ConnectorID = firstNonEmpty(item.ConnectorID, event.Metadata["connector_id"])
	item.Currency = firstNonEmpty(item.Currency, event.Metadata["currency"])
	return item
}

func costOutcomeReceiptFromEvent(event model.FindingWorkflowEvent) CostOutcomeReceipt {
	receipt := CostOutcomeReceipt{
		ID:                      event.ID,
		CommitmentID:            event.Metadata["commitment_id"],
		FindingID:               event.FindingID,
		FindingType:             event.Metadata["finding_type"],
		Resource:                model.ResourceRef{ID: event.Metadata["resource_id"], Type: model.ResourceType(event.Metadata["resource_type"]), Name: event.Metadata["resource_name"]},
		OpportunityType:         event.Metadata["opportunity_type"],
		Owner:                   event.Metadata["owner"],
		AcceptedBy:              event.Actor,
		AcceptanceNote:          event.Note,
		ApprovedSeriesReduction: positiveStringInt64OrZero(event.Metadata["approved_series_reduction"]),
		BaselineSeries:          positiveStringInt64OrZero(event.Metadata["baseline_series"]),
		CurrentSeries:           nonNegativeStringInt64OrZero(event.Metadata["current_series"]),
		RealizedSeriesReduction: positiveStringInt64OrZero(event.Metadata["realized_series_reduction"]),
		VerificationMethod:      event.Metadata["verification_method"],
		MeasurementSource:       event.Metadata["measurement_source"],
		ConnectorID:             event.Metadata["connector_id"],
		EvidenceSnapshotID:      event.Metadata["evidence_snapshot_id"],
		RealizedAt:              event.CreatedAt,
		Currency:                event.Metadata["currency"],
	}
	if measuredAt, ok := parseRFC3339(event.Metadata["measurement_at"]); ok {
		receipt.MeasurementAt = measuredAt
	}
	if value, ok := positiveStringFloat64(event.Metadata["realized_monthly_savings"]); ok {
		rounded := roundMoney(value)
		receipt.RealizedMonthlySavings = &rounded
	}
	return receipt
}

func nonNegativeStringInt64OrZero(value string) int64 {
	parsed, ok := nonNegativeStringInt64(value)
	if !ok {
		return 0
	}
	return parsed
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func costOutcomeStatePriority(state string) int {
	switch state {
	case CostOutcomeStateApproved:
		return 0
	case CostVerificationPending, CostVerificationUnverifiable:
		return 1
	case CostVerificationVerified:
		return 2
	case CostOutcomeStateRealized:
		return 3
	default:
		return 4
	}
}

func CostApprovalMetadata(opportunity CostOpportunity, readiness CostReadinessItem, pricing CostPricing, owner string, dueAt time.Time, approvedReduction int64, override bool) map[string]string {
	metadata := CostBaselineMetadata(opportunity, pricing)
	for key, value := range CostReadinessBaselineMetadata(readiness, override) {
		metadata[key] = value
	}
	metadata["owner"] = strings.TrimSpace(owner)
	metadata["due_at"] = dueAt.UTC().Format(time.RFC3339Nano)
	metadata["approved_series_reduction"] = strconv.FormatInt(approvedReduction, 10)
	pricing = NormalizeCostPricing(pricing)
	if pricing.MonthlyPerMillionActiveSeries > 0 {
		metadata["currency"] = pricing.Currency
		metadata["approved_monthly_savings"] = strconv.FormatFloat(roundMoney(float64(approvedReduction)/1_000_000*pricing.MonthlyPerMillionActiveSeries), 'f', 2, 64)
	}
	return metadata
}
