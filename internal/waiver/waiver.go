package waiver

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"monicheck/internal/model"
)

const (
	MetadataID        = "waiver.id"
	MetadataScope     = "waiver.scope"
	MetadataExpiresAt = "waiver.expires_at"
)

func Validate(candidate model.Waiver, now time.Time) error {
	switch candidate.Scope {
	case model.WaiverScopeFinding, model.WaiverScopeResource, model.WaiverScopeAnalyzer, model.WaiverScopeFindingType:
	default:
		return fmt.Errorf("scope must be FINDING, RESOURCE, ANALYZER, or FINDING_TYPE")
	}
	if strings.TrimSpace(candidate.ScopeValue) == "" {
		return fmt.Errorf("scope_value is required")
	}
	if strings.TrimSpace(candidate.Owner) == "" {
		return fmt.Errorf("owner is required")
	}
	if strings.TrimSpace(candidate.Reason) == "" {
		return fmt.Errorf("reason is required")
	}
	if candidate.ExpiresAt.IsZero() || !candidate.ExpiresAt.After(now) {
		return fmt.Errorf("expires_at must be in the future")
	}
	return nil
}

func Apply(findings []model.Finding, waivers []model.Waiver, now time.Time) []model.Finding {
	result := make([]model.Finding, len(findings))
	for index, finding := range findings {
		result[index] = ApplyToFinding(finding, waivers, now)
	}
	return result
}

func ApplyToFinding(finding model.Finding, waivers []model.Waiver, now time.Time) model.Finding {
	finding.Metadata = cloneMetadata(finding.Metadata)
	active := matchingActiveWaivers(finding, waivers, now)
	if len(active) == 0 {
		if finding.Status == model.FindingStatusWaived {
			finding.Status = model.FindingStatusOpen
		}
		clearMetadata(&finding)
		return finding
	}
	if finding.Status != model.FindingStatusOpen && finding.Status != model.FindingStatusWaived {
		clearMetadata(&finding)
		return finding
	}
	selected := active[0]
	finding.Status = model.FindingStatusWaived
	if finding.Metadata == nil {
		finding.Metadata = map[string]string{}
	}
	finding.Metadata[MetadataID] = selected.ID
	finding.Metadata[MetadataScope] = string(selected.Scope)
	finding.Metadata[MetadataExpiresAt] = selected.ExpiresAt.UTC().Format(time.RFC3339)
	return finding
}

func cloneMetadata(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func Matches(finding model.Finding, candidate model.Waiver) bool {
	switch candidate.Scope {
	case model.WaiverScopeFinding:
		return finding.ID == candidate.ScopeValue
	case model.WaiverScopeResource:
		return finding.Resource.ID == candidate.ScopeValue
	case model.WaiverScopeAnalyzer:
		return strings.TrimSpace(finding.Metadata["analyzer_id"]) == candidate.ScopeValue
	case model.WaiverScopeFindingType:
		return finding.Type == candidate.ScopeValue
	default:
		return false
	}
}

func matchingActiveWaivers(finding model.Finding, waivers []model.Waiver, now time.Time) []model.Waiver {
	result := make([]model.Waiver, 0)
	for _, candidate := range waivers {
		if candidate.State(now) == model.WaiverStateActive && Matches(finding, candidate) {
			result = append(result, candidate)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		leftPriority := scopePriority(result[i].Scope)
		rightPriority := scopePriority(result[j].Scope)
		if leftPriority != rightPriority {
			return leftPriority < rightPriority
		}
		if !result[i].CreatedAt.Equal(result[j].CreatedAt) {
			return result[i].CreatedAt.After(result[j].CreatedAt)
		}
		return result[i].ID < result[j].ID
	})
	return result
}

func scopePriority(scope model.WaiverScope) int {
	switch scope {
	case model.WaiverScopeFinding:
		return 0
	case model.WaiverScopeResource:
		return 1
	case model.WaiverScopeAnalyzer:
		return 2
	case model.WaiverScopeFindingType:
		return 3
	default:
		return 4
	}
}

func clearMetadata(finding *model.Finding) {
	if finding.Metadata == nil {
		return
	}
	delete(finding.Metadata, MetadataID)
	delete(finding.Metadata, MetadataScope)
	delete(finding.Metadata, MetadataExpiresAt)
}
