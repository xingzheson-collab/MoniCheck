package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const EditableDashboardAnalyzerID = "builtin.editable_dashboard"

type EditableDashboardAnalyzer struct{}

func NewEditableDashboardAnalyzer() *EditableDashboardAnalyzer {
	return &EditableDashboardAnalyzer{}
}

func (a *EditableDashboardAnalyzer) ID() string {
	return EditableDashboardAnalyzerID
}

func (a *EditableDashboardAnalyzer) Name() string {
	return "Editable Dashboard"
}

func (a *EditableDashboardAnalyzer) Version() string {
	return "0.1.0"
}

func (a *EditableDashboardAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeDashboard}
}

func (a *EditableDashboardAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	dashboards, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeDashboard})
	if err != nil {
		return nil, err
	}

	allowed := resourceIdentitySet(stringSliceConfig(analysis.Config, "allowed_editable_dashboards", nil))
	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, dashboard := range dashboards {
		if !isActiveDashboard(dashboard) || dashboard.Source.System != "grafana" || !isTruthy(dashboard.Metadata[model.MetadataDashboardEditable]) {
			continue
		}
		if allowedResource(dashboard, allowed, model.MetadataDashboardUID) {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), dashboard.ID),
			Type:     "EditableDashboard",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   dashboard.ID,
				Type: dashboard.Type,
				Name: dashboard.Name,
			},
			Evidence: []string{
				fmt.Sprintf("grafana dashboard %q is editable in the UI", dashboard.Name),
			},
			Recommendation: "生产 Dashboard 建议通过 JSON/provisioning/IaC 管理并关闭 UI 直接编辑，减少看板漂移；如确认为受控例外，请加入 allowed_editable_dashboards。",
			Metadata: map[string]string{
				"analyzer_id": a.ID(),
				"editable":    strings.TrimSpace(dashboard.Metadata[model.MetadataDashboardEditable]),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func resourceIdentitySet(values []string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value != "" {
			result[value] = true
		}
	}
	return result
}

func allowedResource(resource model.Resource, allowed map[string]bool, metadataKeys ...string) bool {
	if len(allowed) == 0 {
		return false
	}
	identities := []string{resource.ID, resource.Name, resource.UID}
	for _, key := range metadataKeys {
		identities = append(identities, resource.Metadata[key])
	}
	for _, identity := range identities {
		identity = strings.ToLower(strings.TrimSpace(identity))
		if identity != "" && allowed[identity] {
			return true
		}
	}
	return false
}
