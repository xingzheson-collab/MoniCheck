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
	CostBaselineCapturedAction = "cost_baseline_captured"

	CostVerificationPending      = "PENDING"
	CostVerificationVerified     = "VERIFIED"
	CostVerificationNoReduction  = "NO_REDUCTION"
	CostVerificationUnverifiable = "UNVERIFIABLE"

	CostVerificationMethodMeasurement = "SAME_SOURCE_MEASUREMENT"
	CostVerificationMethodTombstone   = "COMPLETE_SNAPSHOT_TOMBSTONE"
)

type CostVerificationSummary struct {
	BaselineCount           int                `json:"baseline_count"`
	PendingCount            int                `json:"pending_count"`
	VerifiedCount           int                `json:"verified_count"`
	NoReductionCount        int                `json:"no_reduction_count"`
	UnverifiableCount       int                `json:"unverifiable_count"`
	VerifiedSeriesReduction int64              `json:"verified_series_reduction"`
	PricingConfigured       bool               `json:"pricing_configured"`
	Currency                string             `json:"currency"`
	VerifiedMonthlySavings  *float64           `json:"verified_monthly_savings,omitempty"`
	Items                   []CostVerification `json:"items"`
}

type CostVerification struct {
	FindingID                        string            `json:"finding_id"`
	FindingType                      string            `json:"finding_type"`
	Resource                         model.ResourceRef `json:"resource"`
	OpportunityType                  string            `json:"opportunity_type"`
	State                            string            `json:"state"`
	BaselineCapturedAt               time.Time         `json:"baseline_captured_at"`
	MeasurementAt                    time.Time         `json:"measurement_at,omitempty"`
	MeasurementSource                string            `json:"measurement_source"`
	VerificationMethod               string            `json:"verification_method,omitempty"`
	EvidenceSnapshotID               string            `json:"evidence_snapshot_id,omitempty"`
	ConnectorID                      string            `json:"connector_id,omitempty"`
	BaselineSeries                   int64             `json:"baseline_series"`
	CurrentSeries                    int64             `json:"current_series"`
	PotentialSeriesReduction         int64             `json:"potential_series_reduction"`
	VerifiedSeriesReduction          int64             `json:"verified_series_reduction"`
	Currency                         string            `json:"currency,omitempty"`
	PotentialMonthlySavingsAtCapture *float64          `json:"potential_monthly_savings_at_capture,omitempty"`
	VerifiedMonthlySavings           *float64          `json:"verified_monthly_savings,omitempty"`
	Detail                           string            `json:"detail"`
}

func BuildCostVerificationSummary(ctx context.Context, store *storage.Store, filter storage.ResourceFilter, pricing CostPricing) (CostVerificationSummary, error) {
	pricing = NormalizeCostPricing(pricing)
	if store.FindingWorkflow == nil {
		return CostVerificationSummary{
			PricingConfigured: pricing.MonthlyPerMillionActiveSeries > 0,
			Currency:          pricing.Currency,
			Items:             []CostVerification{},
		}, nil
	}
	resources, err := store.Resources.List(ctx, filter)
	if err != nil {
		return CostVerificationSummary{}, err
	}
	findings, err := store.Findings.List(ctx, storage.FindingFilter{})
	if err != nil {
		return CostVerificationSummary{}, err
	}
	resourcesByID := make(map[string]model.Resource, len(resources))
	for _, resource := range resources {
		resourcesByID[resource.ID] = resource
	}
	events, err := store.FindingWorkflow.List(ctx, "")
	if err != nil {
		return CostVerificationSummary{}, err
	}
	cancelledCommitments := map[string]bool{}
	for _, event := range events {
		if event.Action == CostOptimizationCancelledAction {
			cancelledCommitments[strings.TrimSpace(event.Metadata["commitment_id"])] = true
		}
	}
	baselinesByFinding := make(map[string]model.FindingWorkflowEvent)
	for _, event := range events {
		if event.Action != CostBaselineCapturedAction && event.Action != CostOptimizationApprovedAction {
			continue
		}
		if event.Action == CostOptimizationApprovedAction && cancelledCommitments[event.ID] {
			continue
		}
		current, found := baselinesByFinding[event.FindingID]
		if !found || event.CreatedAt.After(current.CreatedAt) {
			baselinesByFinding[event.FindingID] = event
		}
	}

	summary := CostVerificationSummary{
		PricingConfigured: pricing.MonthlyPerMillionActiveSeries > 0,
		Currency:          pricing.Currency,
		Items:             []CostVerification{},
	}
	var monthly float64
	findingsByID := make(map[string]model.Finding, len(findings))
	for _, finding := range findings {
		findingsByID[finding.ID] = finding
	}
	for findingID, baseline := range baselinesByFinding {
		finding, findingFound := findingsByID[findingID]
		findingType := finding.Type
		resourceRef := finding.Resource
		if !findingFound {
			findingType = strings.TrimSpace(baseline.Metadata["finding_type"])
			resourceRef = model.ResourceRef{
				ID:   strings.TrimSpace(baseline.Metadata["resource_id"]),
				Type: model.ResourceType(strings.TrimSpace(baseline.Metadata["resource_type"])),
				Name: strings.TrimSpace(baseline.Metadata["resource_name"]),
			}
			finding = model.Finding{ID: findingID, Type: findingType, Resource: resourceRef}
		}
		resource, ok := resourcesByID[resourceRef.ID]
		if !ok || resource.Type != model.ResourceTypeMetric || !costOpportunityFindingType(findingType) {
			continue
		}
		item := buildCostVerification(finding, resource, baseline, pricing)
		summary.BaselineCount++
		switch item.State {
		case CostVerificationPending:
			summary.PendingCount++
		case CostVerificationVerified:
			summary.VerifiedCount++
		case CostVerificationNoReduction:
			summary.NoReductionCount++
		default:
			summary.UnverifiableCount++
		}
		summary.VerifiedSeriesReduction += item.VerifiedSeriesReduction
		if item.VerifiedMonthlySavings != nil {
			monthly += *item.VerifiedMonthlySavings
		}
		summary.Items = append(summary.Items, item)
	}
	sort.Slice(summary.Items, func(i, j int) bool {
		if summary.Items[i].VerifiedSeriesReduction != summary.Items[j].VerifiedSeriesReduction {
			return summary.Items[i].VerifiedSeriesReduction > summary.Items[j].VerifiedSeriesReduction
		}
		return summary.Items[i].BaselineCapturedAt.After(summary.Items[j].BaselineCapturedAt)
	})
	if summary.PricingConfigured {
		value := roundMoney(monthly)
		summary.VerifiedMonthlySavings = &value
	}
	return summary, nil
}

func buildCostVerification(finding model.Finding, resource model.Resource, baseline model.FindingWorkflowEvent, pricing CostPricing) CostVerification {
	baselineSeries, baselineOK := positiveStringInt64(baseline.Metadata["baseline_series"])
	baselineSource := strings.TrimSpace(baseline.Metadata["measurement_source"])
	baselineConnectorID := strings.TrimSpace(baseline.Metadata["connector_id"])
	currentSeries, currentOK := nonNegativeStringInt64(resource.Metadata[model.MetadataSeriesCount])
	currentSource := strings.TrimSpace(resource.Metadata[model.MetadataSeriesCountSource])
	currentConnectorID := strings.TrimSpace(resource.Metadata[model.MetadataConnectorID])
	item := CostVerification{
		FindingID:                finding.ID,
		FindingType:              finding.Type,
		Resource:                 finding.Resource,
		OpportunityType:          strings.TrimSpace(baseline.Metadata["opportunity_type"]),
		State:                    CostVerificationUnverifiable,
		BaselineCapturedAt:       baseline.CreatedAt,
		MeasurementAt:            resource.UpdatedAt,
		MeasurementSource:        currentSource,
		ConnectorID:              currentConnectorID,
		BaselineSeries:           baselineSeries,
		CurrentSeries:            currentSeries,
		PotentialSeriesReduction: positiveStringInt64OrZero(baseline.Metadata["potential_series_reduction"]),
		Detail:                   "The current measurement cannot be compared with the captured baseline.",
	}
	if capturedPrice, ok := positiveStringFloat64(baseline.Metadata["monthly_price_per_million"]); ok &&
		item.PotentialSeriesReduction > 0 {
		value := roundMoney(float64(item.PotentialSeriesReduction) / 1_000_000 * capturedPrice)
		item.PotentialMonthlySavingsAtCapture = &value
	}
	if !baselineOK {
		return item
	}
	if resource.Status == model.ResourceStatusOrphan {
		return buildTombstoneCostVerification(item, resource, baseline, baselineConnectorID, baselineSource, pricing)
	}
	if !currentOK || resource.Status != model.ResourceStatusActive {
		return item
	}
	if baselineConnectorID != "" && baselineConnectorID != currentConnectorID {
		item.Detail = "The current resource is owned by a different connector than the captured baseline."
		return item
	}
	if baselineSource == "" || currentSource == "" || baselineSource != currentSource {
		item.Detail = "The baseline and current series use different or unknown measurement sources."
		return item
	}
	if !resource.UpdatedAt.After(baseline.CreatedAt) {
		item.State = CostVerificationPending
		item.Detail = "Waiting for a connector measurement newer than the baseline."
		return item
	}
	reduction := baselineSeries - currentSeries
	if reduction <= 0 {
		item.State = CostVerificationNoReduction
		item.Detail = "The latest comparable measurement does not show a series reduction."
		return item
	}
	item.State = CostVerificationVerified
	item.VerificationMethod = CostVerificationMethodMeasurement
	item.VerifiedSeriesReduction = reduction
	item.Detail = "A newer measurement from the same source is below the captured baseline."
	if pricing.MonthlyPerMillionActiveSeries > 0 {
		value := roundMoney(float64(reduction) / 1_000_000 * pricing.MonthlyPerMillionActiveSeries)
		item.Currency = pricing.Currency
		item.VerifiedMonthlySavings = &value
	}
	return item
}

func buildTombstoneCostVerification(item CostVerification, resource model.Resource, baseline model.FindingWorkflowEvent, baselineConnectorID string, baselineSource string, pricing CostPricing) CostVerification {
	tombstoneConnectorID := strings.TrimSpace(resource.Metadata[model.MetadataConnectorID])
	tombstoneSnapshotID := strings.TrimSpace(resource.Metadata[model.MetadataConnectorOrphanedSnapshotID])
	tombstoneComplete := strings.EqualFold(strings.TrimSpace(resource.Metadata[model.MetadataConnectorOrphanedSnapshotComplete]), "true")
	tombstoneAt, timestampOK := parseRFC3339(resource.Metadata[model.MetadataConnectorOrphanedAt])
	item.ConnectorID = tombstoneConnectorID
	item.EvidenceSnapshotID = tombstoneSnapshotID
	item.MeasurementSource = baselineSource
	if baselineConnectorID == "" || tombstoneConnectorID == "" || baselineConnectorID != tombstoneConnectorID {
		item.Detail = "The tombstone connector cannot be matched to the captured baseline."
		return item
	}
	if !tombstoneComplete || tombstoneSnapshotID == "" || !timestampOK {
		item.Detail = "The resource is absent, but no complete connector snapshot proves its removal."
		return item
	}
	item.MeasurementAt = tombstoneAt
	if !tombstoneAt.After(baseline.CreatedAt) {
		item.State = CostVerificationPending
		item.Detail = "Waiting for a complete connector snapshot newer than the baseline."
		return item
	}
	item.State = CostVerificationVerified
	item.VerificationMethod = CostVerificationMethodTombstone
	item.CurrentSeries = 0
	item.VerifiedSeriesReduction = item.BaselineSeries
	item.Detail = "A newer complete snapshot from the baseline connector no longer contains this metric."
	if pricing.MonthlyPerMillionActiveSeries > 0 {
		value := roundMoney(float64(item.VerifiedSeriesReduction) / 1_000_000 * pricing.MonthlyPerMillionActiveSeries)
		item.Currency = pricing.Currency
		item.VerifiedMonthlySavings = &value
	}
	return item
}

func parseRFC3339(value string) (time.Time, bool) {
	parsed, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(value))
	return parsed, err == nil
}

func nonNegativeStringInt64(value string) (int64, bool) {
	parsed, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	return parsed, err == nil && parsed >= 0
}

func positiveStringInt64OrZero(value string) int64 {
	parsed, ok := positiveStringInt64(value)
	if !ok {
		return 0
	}
	return parsed
}

func positiveStringFloat64(value string) (float64, bool) {
	parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	return parsed, err == nil && parsed > 0
}

func costOpportunityFindingType(findingType string) bool {
	return findingType == "UnusedMetric" || findingType == "HighCardinalityMetric"
}

func CostBaselineMetadata(opportunity CostOpportunity, pricing CostPricing) map[string]string {
	pricing = NormalizeCostPricing(pricing)
	return map[string]string{
		"baseline_series":            strconv.FormatInt(opportunity.CurrentSeries, 10),
		"measurement_source":         opportunity.MeasurementSource,
		"connector_id":               opportunity.ConnectorID,
		"opportunity_type":           opportunity.OpportunityType,
		"finding_type":               opportunity.FindingType,
		"resource_id":                opportunity.Resource.ID,
		"resource_type":              string(opportunity.Resource.Type),
		"resource_name":              opportunity.Resource.Name,
		"source_system":              opportunity.SourceSystem,
		"potential_series_reduction": strconv.FormatInt(opportunity.PotentialSeriesReduction, 10),
		"currency":                   pricing.Currency,
		"monthly_price_per_million":  strconv.FormatFloat(pricing.MonthlyPerMillionActiveSeries, 'f', -1, 64),
	}
}
