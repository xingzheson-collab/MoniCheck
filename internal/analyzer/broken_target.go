package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const BrokenTargetAnalyzerID = "builtin.broken_target"

type BrokenTargetAnalyzer struct{}

func NewBrokenTargetAnalyzer() *BrokenTargetAnalyzer {
	return &BrokenTargetAnalyzer{}
}

func (a *BrokenTargetAnalyzer) ID() string {
	return BrokenTargetAnalyzerID
}

func (a *BrokenTargetAnalyzer) Name() string {
	return "Broken Target"
}

func (a *BrokenTargetAnalyzer) Version() string {
	return "0.1.0"
}

func (a *BrokenTargetAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTarget}
}

func (a *BrokenTargetAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	targets, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTarget})
	if err != nil {
		return nil, err
	}

	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, target := range targets {
		if !isTargetEligibleForHealthDetection(target) {
			continue
		}
		evidence := targetEvidence(target)
		if len(evidence) == 0 {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), target.ID),
			Type:     "BrokenTarget",
			Severity: model.SeverityCritical,
			Resource: model.ResourceRef{
				ID:   target.ID,
				Type: target.Type,
				Name: target.Name,
			},
			Evidence:       evidence,
			Recommendation: "检查 exporter 是否存活、网络是否可达、Prometheus scrape 配置是否正确。",
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

func targetEvidence(target model.Resource) []string {
	health := strings.TrimSpace(target.Metadata[model.MetadataHealth])
	lastError := strings.TrimSpace(target.Metadata[model.MetadataLastError])

	evidence := make([]string, 0, 2)
	if health != "" && !strings.EqualFold(health, "up") {
		evidence = append(evidence, fmt.Sprintf("target health is %q", health))
	}
	if lastError != "" {
		evidence = append(evidence, "last scrape error: "+lastError)
	}
	if target.Status == model.ResourceStatusBroken && len(evidence) == 0 {
		evidence = append(evidence, "target status is BROKEN")
	}
	return evidence
}

func isTargetEligibleForHealthDetection(target model.Resource) bool {
	return target.Type == model.ResourceTypeTarget &&
		target.Status != model.ResourceStatusDeprecated &&
		target.Status != model.ResourceStatusDeleted
}
