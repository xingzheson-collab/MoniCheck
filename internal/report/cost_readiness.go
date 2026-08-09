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
	DefaultCostOptimizationObservationWindow = 7 * 24 * time.Hour

	CostReadinessReady               = "READY_FOR_REVIEW"
	CostReadinessIncompleteInventory = "INCOMPLETE_INVENTORY"
	CostReadinessIncompleteCoverage  = "INCOMPLETE_USAGE_COVERAGE"
	CostReadinessNeedsObservation    = "NEEDS_OBSERVATION"

	CostEvidenceDashboard = "dashboard"
	CostEvidenceRule      = "rule"
)

var DefaultCostOptimizationRequiredEvidence = []string{CostEvidenceDashboard, CostEvidenceRule}

type CostReadinessConfig struct {
	ObservationWindow       time.Duration
	RequiredEvidenceDomains []string
}

type CostReadinessSummary struct {
	OpportunityCount                int                 `json:"opportunity_count"`
	ReadyCount                      int                 `json:"ready_count"`
	BlockedCount                    int                 `json:"blocked_count"`
	IncompleteInventoryCount        int                 `json:"incomplete_inventory_count"`
	IncompleteCoverageCount         int                 `json:"incomplete_coverage_count"`
	NeedsObservationCount           int                 `json:"needs_observation_count"`
	ReadyPotentialSeriesReduction   int64               `json:"ready_potential_series_reduction"`
	BlockedPotentialSeriesReduction int64               `json:"blocked_potential_series_reduction"`
	ObservationWindowSeconds        int64               `json:"observation_window_seconds"`
	RequiredEvidenceDomains         []string            `json:"required_evidence_domains"`
	EvidenceAvailability            map[string]bool     `json:"evidence_availability"`
	PricingConfigured               bool                `json:"pricing_configured"`
	Currency                        string              `json:"currency"`
	ReadyPotentialMonthlySavings    *float64            `json:"ready_potential_monthly_savings,omitempty"`
	Items                           []CostReadinessItem `json:"items"`
}

type CostReadinessItem struct {
	FindingID                string               `json:"finding_id"`
	FindingType              string               `json:"finding_type"`
	Resource                 model.ResourceRef    `json:"resource"`
	OpportunityType          string               `json:"opportunity_type"`
	ReadinessState           string               `json:"readiness_state"`
	Ready                    bool                 `json:"ready"`
	InventoryComplete        bool                 `json:"inventory_complete"`
	ObservationAgeSeconds    int64                `json:"observation_age_seconds"`
	ObservationWindowSeconds int64                `json:"observation_window_seconds"`
	ConsumerCount            int                  `json:"consumer_count"`
	ConsumersByType          map[string]int       `json:"consumers_by_type"`
	EvidenceDomains          []CostEvidenceDomain `json:"evidence_domains"`
	BlockingReasons          []string             `json:"blocking_reasons"`
	PotentialSeriesReduction int64                `json:"potential_series_reduction"`
	Currency                 string               `json:"currency,omitempty"`
	PotentialMonthlySavings  *float64             `json:"potential_monthly_savings,omitempty"`
}

type CostEvidenceDomain struct {
	Name      string `json:"name"`
	Required  bool   `json:"required"`
	Available bool   `json:"available"`
}

func NormalizeCostReadinessConfig(config CostReadinessConfig) CostReadinessConfig {
	if config.ObservationWindow < 0 {
		config.ObservationWindow = DefaultCostOptimizationObservationWindow
	}
	config.RequiredEvidenceDomains = NormalizeCostEvidenceDomains(config.RequiredEvidenceDomains)
	if len(config.RequiredEvidenceDomains) == 0 {
		config.RequiredEvidenceDomains = append([]string(nil), DefaultCostOptimizationRequiredEvidence...)
	}
	return config
}

func NormalizeCostEvidenceDomains(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value != CostEvidenceDashboard && value != CostEvidenceRule || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func BuildCostReadinessSummary(ctx context.Context, store *storage.Store, filter storage.ResourceFilter, pricing CostPricing, config CostReadinessConfig) (CostReadinessSummary, error) {
	return BuildCostReadinessSummaryAt(ctx, store, filter, pricing, config, time.Now().UTC())
}

func BuildCostReadinessSummaryAt(ctx context.Context, store *storage.Store, filter storage.ResourceFilter, pricing CostPricing, config CostReadinessConfig, now time.Time) (CostReadinessSummary, error) {
	pricing = NormalizeCostPricing(pricing)
	config = NormalizeCostReadinessConfig(config)
	opportunities, err := BuildCostOpportunitySummary(ctx, store, filter, pricing)
	if err != nil {
		return CostReadinessSummary{}, err
	}
	resources, err := store.Resources.List(ctx, storage.ResourceFilter{})
	if err != nil {
		return CostReadinessSummary{}, err
	}
	relationships, err := store.Relationships.List(ctx)
	if err != nil {
		return CostReadinessSummary{}, err
	}
	resourcesByID := make(map[string]model.Resource, len(resources))
	for _, resource := range resources {
		resourcesByID[resource.ID] = resource
	}
	availability := costEvidenceAvailability(resources)
	required := make(map[string]bool, len(config.RequiredEvidenceDomains))
	for _, domain := range config.RequiredEvidenceDomains {
		required[domain] = true
	}
	evidenceDomains := []CostEvidenceDomain{
		{Name: CostEvidenceDashboard, Required: required[CostEvidenceDashboard], Available: availability[CostEvidenceDashboard]},
		{Name: CostEvidenceRule, Required: required[CostEvidenceRule], Available: availability[CostEvidenceRule]},
	}
	summary := CostReadinessSummary{
		ObservationWindowSeconds: int64(config.ObservationWindow.Seconds()),
		RequiredEvidenceDomains:  append([]string(nil), config.RequiredEvidenceDomains...),
		EvidenceAvailability:     availability,
		PricingConfigured:        pricing.MonthlyPerMillionActiveSeries > 0,
		Currency:                 pricing.Currency,
		Items:                    make([]CostReadinessItem, 0, len(opportunities.Items)),
	}
	var readyMonthly float64
	for _, opportunity := range opportunities.Items {
		resource := resourcesByID[opportunity.Resource.ID]
		item := buildCostReadinessItem(opportunity, resource, relationships, resourcesByID, evidenceDomains, config, now)
		summary.OpportunityCount++
		if item.Ready {
			summary.ReadyCount++
			summary.ReadyPotentialSeriesReduction += item.PotentialSeriesReduction
			if item.PotentialMonthlySavings != nil {
				readyMonthly += *item.PotentialMonthlySavings
			}
		} else {
			summary.BlockedCount++
			summary.BlockedPotentialSeriesReduction += item.PotentialSeriesReduction
			switch item.ReadinessState {
			case CostReadinessIncompleteInventory:
				summary.IncompleteInventoryCount++
			case CostReadinessIncompleteCoverage:
				summary.IncompleteCoverageCount++
			case CostReadinessNeedsObservation:
				summary.NeedsObservationCount++
			}
		}
		summary.Items = append(summary.Items, item)
	}
	if summary.PricingConfigured {
		value := roundMoney(readyMonthly)
		summary.ReadyPotentialMonthlySavings = &value
	}
	sort.Slice(summary.Items, func(i, j int) bool {
		if summary.Items[i].Ready != summary.Items[j].Ready {
			return !summary.Items[i].Ready
		}
		if summary.Items[i].PotentialSeriesReduction != summary.Items[j].PotentialSeriesReduction {
			return summary.Items[i].PotentialSeriesReduction > summary.Items[j].PotentialSeriesReduction
		}
		return summary.Items[i].Resource.Name < summary.Items[j].Resource.Name
	})
	return summary, nil
}

func buildCostReadinessItem(opportunity CostOpportunity, resource model.Resource, relationships []model.Relationship, resourcesByID map[string]model.Resource, domains []CostEvidenceDomain, config CostReadinessConfig, now time.Time) CostReadinessItem {
	age := time.Duration(0)
	if !resource.CreatedAt.IsZero() && now.After(resource.CreatedAt) {
		age = now.Sub(resource.CreatedAt)
	}
	consumersByType := make(map[string]int)
	seenConsumers := map[string]bool{}
	for _, relationship := range relationships {
		if relationship.ToID != resource.ID || !costConsumerRelationship(relationship.Type) || seenConsumers[relationship.FromID] {
			continue
		}
		consumer, ok := resourcesByID[relationship.FromID]
		if !ok || consumer.Status != model.ResourceStatusActive || !costConsumerResource(consumer.Type) {
			continue
		}
		seenConsumers[consumer.ID] = true
		consumersByType[string(consumer.Type)]++
	}
	item := CostReadinessItem{
		FindingID:                opportunity.FindingID,
		FindingType:              opportunity.FindingType,
		Resource:                 opportunity.Resource,
		OpportunityType:          opportunity.OpportunityType,
		ReadinessState:           CostReadinessReady,
		Ready:                    true,
		InventoryComplete:        strings.EqualFold(strings.TrimSpace(resource.Metadata[model.MetadataConnectorSnapshotCompleteness]), "complete"),
		ObservationAgeSeconds:    int64(age.Seconds()),
		ObservationWindowSeconds: int64(config.ObservationWindow.Seconds()),
		ConsumerCount:            len(seenConsumers),
		ConsumersByType:          consumersByType,
		EvidenceDomains:          append([]CostEvidenceDomain(nil), domains...),
		BlockingReasons:          []string{},
		PotentialSeriesReduction: opportunity.PotentialSeriesReduction,
		Currency:                 opportunity.Currency,
		PotentialMonthlySavings:  opportunity.PotentialMonthlySavings,
	}
	if !item.InventoryComplete {
		item.BlockingReasons = append(item.BlockingReasons, "metric_inventory_incomplete")
	}
	for _, domain := range domains {
		if domain.Required && !domain.Available {
			item.BlockingReasons = append(item.BlockingReasons, domain.Name+"_evidence_unavailable")
		}
	}
	if age < config.ObservationWindow {
		item.BlockingReasons = append(item.BlockingReasons, "observation_window_incomplete")
	}
	switch {
	case !item.InventoryComplete:
		item.ReadinessState = CostReadinessIncompleteInventory
		item.Ready = false
	case requiredEvidenceUnavailable(domains):
		item.ReadinessState = CostReadinessIncompleteCoverage
		item.Ready = false
	case age < config.ObservationWindow:
		item.ReadinessState = CostReadinessNeedsObservation
		item.Ready = false
	}
	return item
}

func costEvidenceAvailability(resources []model.Resource) map[string]bool {
	availability := map[string]bool{
		CostEvidenceDashboard: false,
		CostEvidenceRule:      false,
	}
	for _, resource := range resources {
		if resource.Status != model.ResourceStatusActive ||
			!strings.EqualFold(strings.TrimSpace(resource.Metadata[model.MetadataConnectorSnapshotCompleteness]), "complete") {
			continue
		}
		switch resource.Type {
		case model.ResourceTypeDashboard, model.ResourceTypePanel:
			availability[CostEvidenceDashboard] = true
		case model.ResourceTypeAlertRule, model.ResourceTypeRecordingRule:
			availability[CostEvidenceRule] = true
		}
	}
	return availability
}

func requiredEvidenceUnavailable(domains []CostEvidenceDomain) bool {
	for _, domain := range domains {
		if domain.Required && !domain.Available {
			return true
		}
	}
	return false
}

func costConsumerRelationship(relationshipType model.RelationshipType) bool {
	switch relationshipType {
	case model.RelationshipUses, model.RelationshipReferences, model.RelationshipDependsOn:
		return true
	default:
		return false
	}
}

func costConsumerResource(resourceType model.ResourceType) bool {
	switch resourceType {
	case model.ResourceTypeDashboard, model.ResourceTypePanel, model.ResourceTypeAlertRule, model.ResourceTypeRecordingRule:
		return true
	default:
		return false
	}
}

func CostReadinessBaselineMetadata(item CostReadinessItem, overridden bool) map[string]string {
	return map[string]string{
		"readiness_state":                      item.ReadinessState,
		"readiness_ready":                      strconv.FormatBool(item.Ready),
		"readiness_override":                   strconv.FormatBool(overridden),
		"readiness_blocking_reasons":           strings.Join(item.BlockingReasons, ","),
		"readiness_observation_age_seconds":    strconv.FormatInt(item.ObservationAgeSeconds, 10),
		"readiness_observation_window_seconds": strconv.FormatInt(item.ObservationWindowSeconds, 10),
	}
}
