package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const MissingOwnerAnalyzerID = "builtin.missing_owner"

var defaultOwnerKeys = []string{
	model.MetadataOwner,
	"team",
	"squad",
	"maintainer",
	"responsible",
}

type MissingOwnerAnalyzer struct{}

func NewMissingOwnerAnalyzer() *MissingOwnerAnalyzer {
	return &MissingOwnerAnalyzer{}
}

func (a *MissingOwnerAnalyzer) ID() string {
	return MissingOwnerAnalyzerID
}

func (a *MissingOwnerAnalyzer) Name() string {
	return "Missing Owner"
}

func (a *MissingOwnerAnalyzer) Version() string {
	return "0.1.0"
}

func (a *MissingOwnerAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{
		model.ResourceTypeMetric,
		model.ResourceTypeService,
		model.ResourceTypeDashboard,
		model.ResourceTypeAlertRule,
		model.ResourceTypeRecordingRule,
		model.ResourceTypeDatasource,
	}
}

func (a *MissingOwnerAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := ownedResourceCandidates(ctx, analysis.Resources)
	if err != nil {
		return nil, err
	}

	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	ownerKeys := stringSliceConfig(analysis.Config, "owner_keys", defaultOwnerKeys)
	for _, resource := range resources {
		if !isOwnedResourceCandidate(resource) {
			continue
		}
		if hasOwner(resource, ownerKeys) {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), resource.ID),
			Type:     "MissingOwner",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   resource.ID,
				Type: resource.Type,
				Name: resource.Name,
			},
			Evidence: []string{
				fmt.Sprintf("%s %q has no owner metadata or label", resource.Type, resource.Name),
			},
			Recommendation: "Add an owner label or metadata value so findings can be routed, lifecycle decisions can be assigned, and accountability remains traceable.",
			Metadata: map[string]string{
				"analyzer_id": a.ID(),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func ownedResourceCandidates(ctx context.Context, resources storage.ResourceRepository) ([]model.Resource, error) {
	candidates := make([]model.Resource, 0)
	for _, resourceType := range []model.ResourceType{
		model.ResourceTypeMetric,
		model.ResourceTypeService,
		model.ResourceTypeDashboard,
		model.ResourceTypeAlertRule,
		model.ResourceTypeRecordingRule,
		model.ResourceTypeDatasource,
	} {
		items, err := resources.List(ctx, storage.ResourceFilter{Type: resourceType})
		if err != nil {
			return nil, err
		}
		candidates = append(candidates, items...)
	}
	return candidates, nil
}

func isOwnedResourceCandidate(resource model.Resource) bool {
	if resource.Status != model.ResourceStatusActive {
		return false
	}
	if resource.Type == model.ResourceTypeAlertRule && isDisabledAlert(resource) {
		return false
	}
	return true
}

func hasOwner(resource model.Resource, ownerKeys []string) bool {
	for _, key := range ownerKeys {
		if strings.TrimSpace(resource.Metadata[key]) != "" || strings.TrimSpace(resource.Labels[key]) != "" {
			return true
		}
	}
	return false
}
