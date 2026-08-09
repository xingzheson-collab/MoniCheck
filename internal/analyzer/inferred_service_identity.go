package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const InferredServiceIdentityAnalyzerID = "builtin.inferred_service_identity"

type InferredServiceIdentityAnalyzer struct{}

func NewInferredServiceIdentityAnalyzer() *InferredServiceIdentityAnalyzer {
	return &InferredServiceIdentityAnalyzer{}
}

func (a *InferredServiceIdentityAnalyzer) ID() string      { return InferredServiceIdentityAnalyzerID }
func (a *InferredServiceIdentityAnalyzer) Name() string    { return "Inferred Service Identity" }
func (a *InferredServiceIdentityAnalyzer) Version() string { return "0.1.0" }
func (a *InferredServiceIdentityAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeService}
}

func (a *InferredServiceIdentityAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	services, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeService})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, service := range services {
		if service.Status != model.ResourceStatusActive || strings.ToUpper(strings.TrimSpace(service.Metadata[model.MetadataServiceIdentityConfidence])) != "INFERRED" {
			continue
		}
		source := strings.TrimSpace(service.Metadata[model.MetadataServiceIdentitySource])
		if source == "" {
			source = "source metadata"
		}
		findings = append(findings, model.Finding{
			ID:             model.StableID(a.ID(), service.ID),
			Type:           "InferredServiceIdentity",
			Severity:       model.SeverityInfo,
			Category:       model.FindingCategoryQuality,
			Resource:       model.ResourceRef{ID: service.ID, Type: service.Type, Name: service.Name},
			Evidence:       []string{fmt.Sprintf("service %q identity is inferred from %s", service.Name, source)},
			Recommendation: "Add an explicit service label or source mapping when this job represents a business service; otherwise exclude the infrastructure job from the service inventory.",
			Metadata:       map[string]string{"analyzer_id": a.ID(), "service_identity_source": source},
			Status:         model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now,
		})
	}
	return findings, nil
}
