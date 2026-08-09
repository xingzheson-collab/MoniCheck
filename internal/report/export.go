package report

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"monicheck/internal/contract"
	coveragepkg "monicheck/internal/coverage"
	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func BuildExport(ctx context.Context, store *storage.Store, rawType string, rawFormat string) (model.ReportExport, error) {
	return BuildExportWithFilter(ctx, store, rawType, rawFormat, storage.ResourceFilter{})
}

func BuildExportWithFilter(ctx context.Context, store *storage.Store, rawType string, rawFormat string, filter storage.ResourceFilter) (model.ReportExport, error) {
	return BuildExportWithFilterAndCostPricing(ctx, store, rawType, rawFormat, filter, CostPricing{})
}

func BuildExportWithFilterAndCostPricing(ctx context.Context, store *storage.Store, rawType string, rawFormat string, filter storage.ResourceFilter, pricing CostPricing) (model.ReportExport, error) {
	return BuildExportWithFilterAndCostConfig(ctx, store, rawType, rawFormat, filter, pricing, CostGuardrailConfig{})
}

func BuildExportWithFilterAndCostConfig(ctx context.Context, store *storage.Store, rawType string, rawFormat string, filter storage.ResourceFilter, pricing CostPricing, guardrailConfig CostGuardrailConfig) (model.ReportExport, error) {
	return BuildExportWithFilterAndCostControls(ctx, store, rawType, rawFormat, filter, pricing, guardrailConfig, CostMetricDriftConfig{})
}

func BuildExportWithFilterAndCostControls(ctx context.Context, store *storage.Store, rawType string, rawFormat string, filter storage.ResourceFilter, pricing CostPricing, guardrailConfig CostGuardrailConfig, driftConfig CostMetricDriftConfig) (model.ReportExport, error) {
	return BuildExportWithFilterAndCostGovernance(ctx, store, rawType, rawFormat, filter, pricing, guardrailConfig, driftConfig, DefaultCostVerificationSLA)
}

func BuildExportWithFilterAndCostGovernance(ctx context.Context, store *storage.Store, rawType string, rawFormat string, filter storage.ResourceFilter, pricing CostPricing, guardrailConfig CostGuardrailConfig, driftConfig CostMetricDriftConfig, verificationSLA time.Duration) (model.ReportExport, error) {
	return BuildExportWithFilterAndCostOptimization(ctx, store, rawType, rawFormat, filter, pricing, guardrailConfig, driftConfig, verificationSLA, CostReadinessConfig{})
}

func BuildExportWithFilterAndCostOptimization(ctx context.Context, store *storage.Store, rawType string, rawFormat string, filter storage.ResourceFilter, pricing CostPricing, guardrailConfig CostGuardrailConfig, driftConfig CostMetricDriftConfig, verificationSLA time.Duration, readinessConfig CostReadinessConfig) (model.ReportExport, error) {
	reportType := strings.TrimSpace(rawType)
	if reportType == "" {
		reportType = "governance"
	}
	format := strings.TrimSpace(rawFormat)
	if format == "" {
		format = "json"
	}
	payload, rows, err := exportPayload(ctx, store, reportType, filter, pricing, guardrailConfig, driftConfig, verificationSLA, readinessConfig)
	if err != nil {
		return model.ReportExport{}, err
	}
	now := time.Now().UTC()
	export := model.ReportExport{
		ID:        model.StableID("report_export", reportType, format, now.Format(time.RFC3339Nano)),
		Type:      reportType,
		Format:    format,
		Filename:  "monicheck-" + reportType + "-report." + format,
		CreatedAt: now,
	}
	switch format {
	case "json":
		data, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			return model.ReportExport{}, err
		}
		export.ContentType = "application/json"
		export.Content = string(append(data, '\n'))
	case "csv":
		var builder strings.Builder
		writer := csv.NewWriter(&builder)
		if err := writer.Write([]string{"section", "key", "value"}); err != nil {
			return model.ReportExport{}, err
		}
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return model.ReportExport{}, err
			}
		}
		writer.Flush()
		if err := writer.Error(); err != nil {
			return model.ReportExport{}, err
		}
		export.ContentType = "text/csv"
		export.Content = builder.String()
	default:
		return model.ReportExport{}, fmt.Errorf("format must be json or csv")
	}
	return export, nil
}

func exportPayload(ctx context.Context, store *storage.Store, reportType string, filter storage.ResourceFilter, pricing CostPricing, guardrailConfig CostGuardrailConfig, driftConfig CostMetricDriftConfig, verificationSLA time.Duration, readinessConfig CostReadinessConfig) (map[string]any, [][]string, error) {
	switch reportType {
	case "governance":
		resources, err := store.Resources.List(ctx, filter)
		if err != nil {
			return nil, nil, err
		}
		findings, err := store.Findings.List(ctx, storage.FindingFilter{})
		if err != nil {
			return nil, nil, err
		}
		allResourcesByID, err := resourcesByID(ctx, store)
		if err != nil {
			return nil, nil, err
		}
		findings = filterFindingsByTenant(findings, allResourcesByID, filter)
		relationships, err := store.Relationships.List(ctx)
		if err != nil {
			return nil, nil, err
		}
		expectations, err := store.CoverageExpectations.List(ctx)
		if err != nil {
			return nil, nil, err
		}
		exceptions, err := store.CoverageExceptions.List(ctx)
		if err != nil {
			return nil, nil, err
		}
		coverage := coveragepkg.Assess(resources, graph.NewBounded(resources, relationships), expectations, exceptions, time.Now().UTC())
		resourcesByType := make(map[string]int)
		resourcesBySource := make(map[string]int)
		findingsBySeverity := make(map[string]int)
		findingsByCategory := make(map[string]int)
		findingsBySource := make(map[string]int)
		resourcesByTeam := make(map[string]int)
		resourcesByProject := make(map[string]int)
		resourcesByNamespace := make(map[string]int)
		resourcesByCluster := make(map[string]int)
		findingsByTeam := make(map[string]int)
		findingsByProject := make(map[string]int)
		findingsByNamespace := make(map[string]int)
		findingsByCluster := make(map[string]int)
		openFindings := 0
		for _, resource := range resources {
			resourcesByType[string(resource.Type)]++
			resourcesBySource[resourceSourceValue(resource)]++
			resourcesByTeam[resourceTenantValue(resource, "team")]++
			resourcesByProject[resourceTenantValue(resource, "project")]++
			resourcesByNamespace[resourceTenantValue(resource, "namespace")]++
			resourcesByCluster[resourceTenantValue(resource, "cluster")]++
		}
		for _, finding := range findings {
			findingsBySeverity[string(finding.Severity)]++
			findingsByCategory[string(finding.Category)]++
			resource := allResourcesByID[finding.Resource.ID]
			findingsBySource[findingSourceValue(finding, resource)]++
			findingsByTeam[findingTenantValue(finding, resource, "team")]++
			findingsByProject[findingTenantValue(finding, resource, "project")]++
			findingsByNamespace[findingTenantValue(finding, resource, "namespace")]++
			findingsByCluster[findingTenantValue(finding, resource, "cluster")]++
			if finding.Status == model.FindingStatusOpen {
				openFindings++
			}
		}
		priorityFindings := governancePriorityFindings(findings, 20)
		payload := map[string]any{
			"contract_version":                       "governance-report.v2",
			"generated_at":                           time.Now().UTC(),
			"resource_count":                         len(resources),
			"finding_count":                          len(findings),
			"open_finding_count":                     openFindings,
			"critical_count":                         findingsBySeverity[string(model.SeverityCritical)],
			"warning_count":                          findingsBySeverity[string(model.SeverityWarning)],
			"info_count":                             findingsBySeverity[string(model.SeverityInfo)],
			"resources_by_type":                      resourcesByType,
			"resources_by_source":                    resourcesBySource,
			"findings_by_severity":                   findingsBySeverity,
			"findings_by_category":                   findingsByCategory,
			"findings_by_source":                     findingsBySource,
			"resources_by_team":                      resourcesByTeam,
			"resources_by_project":                   resourcesByProject,
			"resources_by_namespace":                 resourcesByNamespace,
			"resources_by_cluster":                   resourcesByCluster,
			"findings_by_team":                       findingsByTeam,
			"findings_by_project":                    findingsByProject,
			"findings_by_namespace":                  findingsByNamespace,
			"findings_by_cluster":                    findingsByCluster,
			"coverage_service_count":                 coverage.ServiceCount,
			"coverage_percent":                       roundedPercent(coverage.CoveragePercent),
			"coverage_missing_signals":               coverage.MissingSignals,
			"coverage_unknown_signals":               coverage.UnknownSignals,
			"coverage_evaluable_signals":             coverage.EvaluableSignals,
			"coverage_evidence_state":                string(coverage.EvidenceState),
			"coverage_evidence_completeness_percent": roundedPercent(coverage.EvidenceCompleteness),
			"coverage":                               coverage,
			"priority_findings":                      priorityFindings,
		}
		rows := [][]string{
			{"summary", "contract_version", "governance-report.v2"},
			{"summary", "resource_count", strconv.Itoa(len(resources))},
			{"summary", "finding_count", strconv.Itoa(len(findings))},
			{"summary", "open_finding_count", strconv.Itoa(openFindings)},
			{"summary", "critical_count", strconv.Itoa(findingsBySeverity[string(model.SeverityCritical)])},
			{"summary", "warning_count", strconv.Itoa(findingsBySeverity[string(model.SeverityWarning)])},
			{"summary", "info_count", strconv.Itoa(findingsBySeverity[string(model.SeverityInfo)])},
			{"coverage", "service_count", strconv.Itoa(coverage.ServiceCount)},
			{"coverage", "coverage_percent", strconv.Itoa(roundedPercent(coverage.CoveragePercent))},
			{"coverage", "missing_signals", strconv.Itoa(coverage.MissingSignals)},
			{"coverage", "unknown_signals", strconv.Itoa(coverage.UnknownSignals)},
			{"coverage", "evaluable_signals", strconv.Itoa(coverage.EvaluableSignals)},
			{"coverage", "evidence_state", string(coverage.EvidenceState)},
			{"coverage", "evidence_completeness_percent", strconv.Itoa(roundedPercent(coverage.EvidenceCompleteness))},
		}
		for index, item := range priorityFindings {
			prefix := fmt.Sprintf("%d.%s", index, item.ID)
			rows = append(rows,
				[]string{"priority_finding", prefix + ".type", item.Type},
				[]string{"priority_finding", prefix + ".severity", string(item.Severity)},
				[]string{"priority_finding", prefix + ".risk_score", strconv.Itoa(item.RiskScore)},
				[]string{"priority_finding", prefix + ".resource", item.Resource.Name},
				[]string{"priority_finding", prefix + ".evidence", strings.Join(item.Evidence, " | ")},
				[]string{"priority_finding", prefix + ".recommendation", item.Recommendation},
			)
		}
		rows = appendMapRows(rows, "resources_by_type", resourcesByType)
		rows = appendMapRows(rows, "resources_by_source", resourcesBySource)
		rows = appendMapRows(rows, "findings_by_severity", findingsBySeverity)
		rows = appendMapRows(rows, "findings_by_category", findingsByCategory)
		rows = appendMapRows(rows, "findings_by_source", findingsBySource)
		rows = appendMapRows(rows, "resources_by_team", resourcesByTeam)
		rows = appendMapRows(rows, "resources_by_project", resourcesByProject)
		rows = appendMapRows(rows, "resources_by_namespace", resourcesByNamespace)
		rows = appendMapRows(rows, "resources_by_cluster", resourcesByCluster)
		rows = appendMapRows(rows, "findings_by_team", findingsByTeam)
		rows = appendMapRows(rows, "findings_by_project", findingsByProject)
		rows = appendMapRows(rows, "findings_by_namespace", findingsByNamespace)
		rows = appendMapRows(rows, "findings_by_cluster", findingsByCluster)
		return payload, rows, nil
	case "quality":
		return categoryExportPayload(ctx, store, reportType, model.FindingCategoryQuality, filter, pricing, guardrailConfig, driftConfig, verificationSLA, readinessConfig)
	case "cost":
		return categoryExportPayload(ctx, store, reportType, model.FindingCategoryCost, filter, pricing, guardrailConfig, driftConfig, verificationSLA, readinessConfig)
	case "lifecycle":
		return categoryExportPayload(ctx, store, reportType, model.FindingCategoryLifecycle, filter, pricing, guardrailConfig, driftConfig, verificationSLA, readinessConfig)
	case "reliability":
		return categoryExportPayload(ctx, store, reportType, model.FindingCategoryReliability, filter, pricing, guardrailConfig, driftConfig, verificationSLA, readinessConfig)
	case "configuration":
		return categoryExportPayload(ctx, store, reportType, model.FindingCategoryConfiguration, filter, pricing, guardrailConfig, driftConfig, verificationSLA, readinessConfig)
	case "security":
		return categoryExportPayload(ctx, store, reportType, model.FindingCategorySecurity, filter, pricing, guardrailConfig, driftConfig, verificationSLA, readinessConfig)
	case "ownership":
		resources, err := store.Resources.List(ctx, storage.ResourceFilter{})
		if err != nil {
			return nil, nil, err
		}
		resourcesByOwner := make(map[string]int)
		unowned := 0
		for _, resource := range resources {
			owner := resourceOwner(resource)
			if owner == "" {
				unowned++
				owner = "unowned"
			}
			resourcesByOwner[owner]++
		}
		payload := map[string]any{
			"generated_at":           time.Now().UTC(),
			"resource_count":         len(resources),
			"owned_resource_count":   len(resources) - unowned,
			"unowned_resource_count": unowned,
			"resources_by_owner":     resourcesByOwner,
		}
		rows := [][]string{
			{"summary", "resource_count", strconv.Itoa(len(resources))},
			{"summary", "owned_resource_count", strconv.Itoa(len(resources) - unowned)},
			{"summary", "unowned_resource_count", strconv.Itoa(unowned)},
		}
		rows = appendMapRows(rows, "resources_by_owner", resourcesByOwner)
		return payload, rows, nil
	case "services":
		resources, err := store.Resources.List(ctx, storage.ResourceFilter{})
		if err != nil {
			return nil, nil, err
		}
		relationships, err := store.Relationships.List(ctx)
		if err != nil {
			return nil, nil, err
		}
		findings, err := store.Findings.List(ctx, storage.FindingFilter{})
		if err != nil {
			return nil, nil, err
		}
		items := serviceExportItems(resources, relationships, findings)
		totalResources := 0
		totalFindings := 0
		for _, item := range items {
			totalResources += item.ResourceCount
			totalFindings += item.FindingCount
		}
		payload := map[string]any{
			"generated_at":              time.Now().UTC(),
			"service_count":             len(items),
			"attributed_resource_count": totalResources,
			"attributed_finding_count":  totalFindings,
			"services":                  items,
		}
		rows := [][]string{
			{"summary", "service_count", strconv.Itoa(len(items))},
			{"summary", "attributed_resource_count", strconv.Itoa(totalResources)},
			{"summary", "attributed_finding_count", strconv.Itoa(totalFindings)},
		}
		for _, item := range items {
			rows = append(rows, []string{"services", item.Name, fmt.Sprintf("resources=%d findings=%d owner=%s", item.ResourceCount, item.FindingCount, item.Owner)})
		}
		return payload, rows, nil
	default:
		return nil, nil, fmt.Errorf("type must be governance, quality, cost, lifecycle, reliability, configuration, security, ownership, or services")
	}
}

type governancePriorityFinding struct {
	ID             string                `json:"id"`
	Type           string                `json:"type"`
	Severity       model.Severity        `json:"severity"`
	Category       model.FindingCategory `json:"category"`
	RiskScore      int                   `json:"risk_score"`
	RiskLevel      string                `json:"risk_level,omitempty"`
	RiskConfidence int                   `json:"risk_confidence,omitempty"`
	Resource       model.ResourceRef     `json:"resource"`
	Evidence       []string              `json:"evidence"`
	Recommendation string                `json:"recommendation"`
	UpdatedAt      time.Time             `json:"updated_at"`
}

func governancePriorityFindings(findings []model.Finding, limit int) []governancePriorityFinding {
	open := make([]model.Finding, 0, len(findings))
	for _, finding := range findings {
		if finding.Status == model.FindingStatusOpen {
			open = append(open, finding)
		}
	}
	sort.SliceStable(open, func(i, j int) bool {
		leftSeverity := governanceSeverityRank(open[i].Severity)
		rightSeverity := governanceSeverityRank(open[j].Severity)
		if leftSeverity != rightSeverity {
			return leftSeverity < rightSeverity
		}
		leftRisk, rightRisk := findingRiskScore(open[i]), findingRiskScore(open[j])
		if leftRisk != rightRisk {
			return leftRisk > rightRisk
		}
		return open[i].UpdatedAt.After(open[j].UpdatedAt)
	})
	if limit <= 0 || limit > len(open) {
		limit = len(open)
	}
	result := make([]governancePriorityFinding, 0, limit)
	for _, finding := range open[:limit] {
		item := governancePriorityFinding{
			ID: finding.ID, Type: finding.Type, Severity: finding.Severity, Category: finding.Category,
			RiskScore: findingRiskScore(finding), Resource: finding.Resource,
			Evidence: contract.PresentationEvidence(finding), Recommendation: contract.PresentationRecommendation(finding),
			UpdatedAt: finding.UpdatedAt,
		}
		if finding.RiskScore != nil {
			item.RiskLevel = finding.RiskScore.Level
			item.RiskConfidence = finding.RiskScore.Confidence
		}
		result = append(result, item)
	}
	return result
}

func findingRiskScore(finding model.Finding) int {
	if finding.RiskScore == nil {
		return 0
	}
	return finding.RiskScore.Score
}

func governanceSeverityRank(severity model.Severity) int {
	switch severity {
	case model.SeverityCritical:
		return 0
	case model.SeverityWarning:
		return 1
	case model.SeverityInfo:
		return 2
	default:
		return 3
	}
}

func roundedPercent(value *float64) int {
	if value == nil {
		return 0
	}
	return int(*value + 0.5)
}

type serviceExportItem struct {
	ID                       string         `json:"id"`
	Name                     string         `json:"name"`
	Owner                    string         `json:"owner,omitempty"`
	ResourceCount            int            `json:"resource_count"`
	FindingCount             int            `json:"finding_count"`
	ImpactResourceCount      int            `json:"impact_resource_count"`
	ImpactFindingCount       int            `json:"impact_finding_count"`
	ResourcesByType          map[string]int `json:"resources_by_type"`
	ResourcesBySource        map[string]int `json:"resources_by_source"`
	FindingsBySeverity       map[string]int `json:"findings_by_severity"`
	FindingsBySource         map[string]int `json:"findings_by_source"`
	ImpactResourcesByType    map[string]int `json:"impact_resources_by_type"`
	ImpactResourcesBySource  map[string]int `json:"impact_resources_by_source"`
	ImpactFindingsBySeverity map[string]int `json:"impact_findings_by_severity"`
	ImpactFindingsBySource   map[string]int `json:"impact_findings_by_source"`
}

func serviceExportItems(resources []model.Resource, relationships []model.Relationship, findings []model.Finding) []serviceExportItem {
	resourcesByID := make(map[string]model.Resource, len(resources))
	serviceByID := make(map[string]model.Resource)
	for _, resource := range resources {
		resourcesByID[resource.ID] = resource
		if resource.Type == model.ResourceTypeService {
			serviceByID[resource.ID] = resource
		}
	}
	serviceResources := make(map[string]map[string]model.Resource)
	resourceServices := make(map[string][]string)
	for _, relationship := range relationships {
		if relationship.Type != model.RelationshipBelongsTo {
			continue
		}
		service, ok := serviceByID[relationship.ToID]
		if !ok {
			continue
		}
		resource, ok := resourcesByID[relationship.FromID]
		if !ok || resource.ID == service.ID {
			continue
		}
		if serviceResources[service.ID] == nil {
			serviceResources[service.ID] = map[string]model.Resource{}
		}
		serviceResources[service.ID][resource.ID] = resource
		resourceServices[resource.ID] = append(resourceServices[resource.ID], service.ID)
	}
	items := make([]serviceExportItem, 0, len(serviceByID))
	for serviceID, service := range serviceByID {
		item := serviceExportItem{
			ID:                       service.ID,
			Name:                     service.Name,
			Owner:                    resourceOwner(service),
			ResourcesByType:          map[string]int{},
			ResourcesBySource:        map[string]int{},
			FindingsBySeverity:       map[string]int{},
			FindingsBySource:         map[string]int{},
			ImpactResourcesByType:    map[string]int{},
			ImpactResourcesBySource:  map[string]int{},
			ImpactFindingsBySeverity: map[string]int{},
			ImpactFindingsBySource:   map[string]int{},
		}
		for _, resource := range serviceResources[serviceID] {
			item.ResourceCount++
			item.ResourcesByType[string(resource.Type)]++
			item.ResourcesBySource[resourceSourceValue(resource)]++
		}
		impactResources := serviceImpactResources(serviceID, serviceResources, resourcesByID, relationships)
		for _, resource := range impactResources {
			item.ImpactResourceCount++
			item.ImpactResourcesByType[string(resource.Type)]++
			item.ImpactResourcesBySource[resourceSourceValue(resource)]++
		}
		for _, finding := range findings {
			if _, ok := impactResources[finding.Resource.ID]; ok {
				item.ImpactFindingCount++
				item.ImpactFindingsBySeverity[string(finding.Severity)]++
				item.ImpactFindingsBySource[findingSourceValue(finding, resourcesByID[finding.Resource.ID])]++
			}
			if finding.Resource.ID == serviceID {
				item.FindingCount++
				item.FindingsBySeverity[string(finding.Severity)]++
				item.FindingsBySource[resourceSourceValue(service)]++
				continue
			}
			for _, itemServiceID := range resourceServices[finding.Resource.ID] {
				if itemServiceID == serviceID {
					item.FindingCount++
					item.FindingsBySeverity[string(finding.Severity)]++
					item.FindingsBySource[findingSourceValue(finding, resourcesByID[finding.Resource.ID])]++
					break
				}
			}
		}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].FindingCount != items[j].FindingCount {
			return items[i].FindingCount > items[j].FindingCount
		}
		if items[i].ResourceCount != items[j].ResourceCount {
			return items[i].ResourceCount > items[j].ResourceCount
		}
		return items[i].Name < items[j].Name
	})
	return items
}

func serviceImpactResources(serviceID string, serviceResources map[string]map[string]model.Resource, resourcesByID map[string]model.Resource, relationships []model.Relationship) map[string]model.Resource {
	impactResources := make(map[string]model.Resource)
	queue := make([]string, 0)
	for resourceID, resource := range serviceResources[serviceID] {
		impactResources[resourceID] = resource
		queue = append(queue, resourceID)
	}
	for len(queue) > 0 {
		resourceID := queue[0]
		queue = queue[1:]
		for _, relationship := range relationships {
			var nextID string
			switch {
			case relationship.FromID == resourceID && relationship.Type == model.RelationshipProduces:
				nextID = relationship.ToID
			case relationship.ToID == resourceID && (relationship.Type == model.RelationshipUses || relationship.Type == model.RelationshipProduces):
				nextID = relationship.FromID
			default:
				continue
			}
			if _, seen := impactResources[nextID]; seen {
				continue
			}
			resource, ok := resourcesByID[nextID]
			if !ok || resource.Type == model.ResourceTypeService {
				continue
			}
			impactResources[nextID] = resource
			queue = append(queue, nextID)
		}
	}
	return impactResources
}

func categoryExportPayload(ctx context.Context, store *storage.Store, reportType string, category model.FindingCategory, filter storage.ResourceFilter, pricing CostPricing, guardrailConfig CostGuardrailConfig, driftConfig CostMetricDriftConfig, verificationSLA time.Duration, readinessConfig CostReadinessConfig) (map[string]any, [][]string, error) {
	findings, err := store.Findings.List(ctx, storage.FindingFilter{Category: category})
	if err != nil {
		return nil, nil, err
	}
	allResourcesByID, err := resourcesByID(ctx, store)
	if err != nil {
		return nil, nil, err
	}
	findings = filterFindingsByTenant(findings, allResourcesByID, filter)
	byType := make(map[string]int)
	byResourceType := make(map[string]int)
	byQueryLanguage := make(map[string]int)
	byTeam := make(map[string]int)
	byProject := make(map[string]int)
	byNamespace := make(map[string]int)
	byCluster := make(map[string]int)
	for _, finding := range findings {
		byType[finding.Type]++
		byResourceType[string(finding.Resource.Type)]++
		resource := allResourcesByID[finding.Resource.ID]
		byTeam[findingTenantValue(finding, resource, "team")]++
		byProject[findingTenantValue(finding, resource, "project")]++
		byNamespace[findingTenantValue(finding, resource, "namespace")]++
		byCluster[findingTenantValue(finding, resource, "cluster")]++
		if queryLanguage := strings.TrimSpace(finding.Metadata["query_language"]); queryLanguage != "" {
			byQueryLanguage[queryLanguage]++
		}
	}
	payload := map[string]any{
		"generated_at":               time.Now().UTC(),
		"category":                   string(category),
		"finding_count":              len(findings),
		"findings_by_type":           byType,
		"by_resource_type":           byResourceType,
		"findings_by_query_language": byQueryLanguage,
		"findings_by_team":           byTeam,
		"findings_by_project":        byProject,
		"findings_by_namespace":      byNamespace,
		"findings_by_cluster":        byCluster,
		"top_findings":               findings,
		"report_type":                reportType,
	}
	rows := [][]string{
		{"summary", "category", string(category)},
		{"summary", "finding_count", strconv.Itoa(len(findings))},
	}
	rows = appendMapRows(rows, "findings_by_type", byType)
	rows = appendMapRows(rows, "by_resource_type", byResourceType)
	rows = appendMapRows(rows, "findings_by_query_language", byQueryLanguage)
	rows = appendMapRows(rows, "findings_by_team", byTeam)
	rows = appendMapRows(rows, "findings_by_project", byProject)
	rows = appendMapRows(rows, "findings_by_namespace", byNamespace)
	rows = appendMapRows(rows, "findings_by_cluster", byCluster)
	if category == model.FindingCategoryCost {
		tsdbCost, err := BuildTSDBCostSummary(ctx, store, filter)
		if err != nil {
			return nil, nil, err
		}
		payload["tsdb_count"] = tsdbCost.TSDBCount
		payload["tsdb_head_series"] = tsdbCost.HeadSeries
		payload["tsdb_head_chunks"] = tsdbCost.HeadChunks
		payload["tsdb_label_value_count"] = tsdbCost.LabelValueCount
		payload["tsdb_label_memory_bytes"] = tsdbCost.LabelMemoryBytes
		payload["tsdb_instances"] = tsdbCost.Instances
		rows = append(rows,
			[]string{"tsdb", "tsdb_count", strconv.Itoa(tsdbCost.TSDBCount)},
			[]string{"tsdb", "tsdb_head_series", strconv.FormatInt(tsdbCost.HeadSeries, 10)},
			[]string{"tsdb", "tsdb_head_chunks", strconv.FormatInt(tsdbCost.HeadChunks, 10)},
			[]string{"tsdb", "tsdb_label_value_count", strconv.FormatInt(tsdbCost.LabelValueCount, 10)},
			[]string{"tsdb", "tsdb_label_memory_bytes", strconv.FormatInt(tsdbCost.LabelMemoryBytes, 10)},
		)
		metricSeries, err := BuildCostMetricSeriesSnapshot(ctx, store, filter)
		if err != nil {
			return nil, nil, err
		}
		payload["cost_metric_series"] = metricSeries
		for _, item := range metricSeries {
			prefix := item.Resource.ID
			rows = append(rows,
				[]string{"cost_metric_series", prefix + ".resource", item.Resource.Name},
				[]string{"cost_metric_series", prefix + ".source_system", item.SourceSystem},
				[]string{"cost_metric_series", prefix + ".connector_id", item.ConnectorID},
				[]string{"cost_metric_series", prefix + ".measurement_source", item.MeasurementSource},
				[]string{"cost_metric_series", prefix + ".measured_at", item.MeasuredAt.Format(time.RFC3339Nano)},
				[]string{"cost_metric_series", prefix + ".series", strconv.FormatInt(item.Series, 10)},
			)
		}
		opportunities, err := BuildCostOpportunitySummary(ctx, store, filter, pricing)
		if err != nil {
			return nil, nil, err
		}
		payload["cost_opportunities"] = opportunities
		rows = append(rows,
			[]string{"cost_opportunity_summary", "opportunity_count", strconv.Itoa(opportunities.OpportunityCount)},
			[]string{"cost_opportunity_summary", "quantified_count", strconv.Itoa(opportunities.QuantifiedCount)},
			[]string{"cost_opportunity_summary", "current_series", strconv.FormatInt(opportunities.CurrentSeries, 10)},
			[]string{"cost_opportunity_summary", "potential_series_reduction", strconv.FormatInt(opportunities.PotentialSeriesReduction, 10)},
			[]string{"cost_opportunity_summary", "pricing_configured", strconv.FormatBool(opportunities.PricingConfigured)},
			[]string{"cost_opportunity_summary", "currency", opportunities.Currency},
			[]string{"cost_opportunity_summary", "monthly_price_per_million_active_series", strconv.FormatFloat(opportunities.MonthlyPricePerMillion, 'f', -1, 64)},
		)
		if opportunities.PotentialMonthlySavings != nil {
			rows = append(rows, []string{"cost_opportunity_summary", "potential_monthly_savings", strconv.FormatFloat(*opportunities.PotentialMonthlySavings, 'f', 2, 64)})
		}
		for _, opportunity := range opportunities.Items {
			rows = append(rows,
				[]string{"cost_opportunity", opportunity.ID + ".finding_id", opportunity.FindingID},
				[]string{"cost_opportunity", opportunity.ID + ".type", opportunity.OpportunityType},
				[]string{"cost_opportunity", opportunity.ID + ".resource", opportunity.Resource.Name},
				[]string{"cost_opportunity", opportunity.ID + ".potential_series_reduction", strconv.FormatInt(opportunity.PotentialSeriesReduction, 10)},
			)
		}
		verification, err := BuildCostVerificationSummary(ctx, store, filter, pricing)
		if err != nil {
			return nil, nil, err
		}
		payload["cost_verification"] = verification
		rows = append(rows,
			[]string{"cost_verification_summary", "baseline_count", strconv.Itoa(verification.BaselineCount)},
			[]string{"cost_verification_summary", "pending_count", strconv.Itoa(verification.PendingCount)},
			[]string{"cost_verification_summary", "verified_count", strconv.Itoa(verification.VerifiedCount)},
			[]string{"cost_verification_summary", "no_reduction_count", strconv.Itoa(verification.NoReductionCount)},
			[]string{"cost_verification_summary", "unverifiable_count", strconv.Itoa(verification.UnverifiableCount)},
			[]string{"cost_verification_summary", "verified_series_reduction", strconv.FormatInt(verification.VerifiedSeriesReduction, 10)},
		)
		if verification.VerifiedMonthlySavings != nil {
			rows = append(rows, []string{"cost_verification_summary", "verified_monthly_savings", strconv.FormatFloat(*verification.VerifiedMonthlySavings, 'f', 2, 64)})
		}
		for _, item := range verification.Items {
			prefix := item.FindingID
			rows = append(rows,
				[]string{"cost_verification", prefix + ".state", item.State},
				[]string{"cost_verification", prefix + ".resource", item.Resource.Name},
				[]string{"cost_verification", prefix + ".verification_method", item.VerificationMethod},
				[]string{"cost_verification", prefix + ".connector_id", item.ConnectorID},
				[]string{"cost_verification", prefix + ".evidence_snapshot_id", item.EvidenceSnapshotID},
				[]string{"cost_verification", prefix + ".baseline_series", strconv.FormatInt(item.BaselineSeries, 10)},
				[]string{"cost_verification", prefix + ".current_series", strconv.FormatInt(item.CurrentSeries, 10)},
				[]string{"cost_verification", prefix + ".verified_series_reduction", strconv.FormatInt(item.VerifiedSeriesReduction, 10)},
			)
		}
		outcomes, err := BuildCostOutcomeSummary(ctx, store, filter, pricing)
		if err != nil {
			return nil, nil, err
		}
		payload["cost_outcomes"] = outcomes
		rows = append(rows,
			[]string{"cost_outcome_summary", "opportunity_count", strconv.Itoa(outcomes.OpportunityCount)},
			[]string{"cost_outcome_summary", "approved_count", strconv.Itoa(outcomes.ApprovedCount)},
			[]string{"cost_outcome_summary", "verified_count", strconv.Itoa(outcomes.VerifiedCount)},
			[]string{"cost_outcome_summary", "realized_count", strconv.Itoa(outcomes.RealizedCount)},
			[]string{"cost_outcome_summary", "overdue_commitment_count", strconv.Itoa(outcomes.OverdueCommitmentCount)},
			[]string{"cost_outcome_summary", "approved_series_reduction", strconv.FormatInt(outcomes.ApprovedSeriesReduction, 10)},
			[]string{"cost_outcome_summary", "verified_series_reduction", strconv.FormatInt(outcomes.VerifiedSeriesReduction, 10)},
			[]string{"cost_outcome_summary", "realized_series_reduction", strconv.FormatInt(outcomes.RealizedSeriesReduction, 10)},
			[]string{"cost_outcome_summary", "realized_percent_of_approved", strconv.FormatFloat(outcomes.RealizedPercentOfApproved, 'f', 2, 64)},
		)
		for _, receipt := range outcomes.Receipts {
			rows = append(rows,
				[]string{"cost_outcome_receipt", receipt.ID + ".commitment_id", receipt.CommitmentID},
				[]string{"cost_outcome_receipt", receipt.ID + ".resource", receipt.Resource.Name},
				[]string{"cost_outcome_receipt", receipt.ID + ".owner", receipt.Owner},
				[]string{"cost_outcome_receipt", receipt.ID + ".accepted_by", receipt.AcceptedBy},
				[]string{"cost_outcome_receipt", receipt.ID + ".realized_series_reduction", strconv.FormatInt(receipt.RealizedSeriesReduction, 10)},
				[]string{"cost_outcome_receipt", receipt.ID + ".verification_method", receipt.VerificationMethod},
				[]string{"cost_outcome_receipt", receipt.ID + ".realized_at", receipt.RealizedAt.Format(time.RFC3339Nano)},
			)
		}
		portfolio, err := BuildCostPortfolioSummary(ctx, store, filter, pricing, verificationSLA)
		if err != nil {
			return nil, nil, err
		}
		payload["cost_portfolio"] = portfolio
		rows = append(rows,
			[]string{"cost_portfolio_summary", "portfolio_count", strconv.Itoa(portfolio.PortfolioCount)},
			[]string{"cost_portfolio_summary", "potential_count", strconv.Itoa(portfolio.PotentialCount)},
			[]string{"cost_portfolio_summary", "baselined_count", strconv.Itoa(portfolio.BaselinedCount)},
			[]string{"cost_portfolio_summary", "overdue_count", strconv.Itoa(portfolio.OverdueCount)},
			[]string{"cost_portfolio_summary", "verified_count", strconv.Itoa(portfolio.VerifiedCount)},
			[]string{"cost_portfolio_summary", "potential_series_reduction", strconv.FormatInt(portfolio.PotentialSeriesReduction, 10)},
			[]string{"cost_portfolio_summary", "verified_series_reduction", strconv.FormatInt(portfolio.VerifiedSeriesReduction, 10)},
			[]string{"cost_portfolio_summary", "realization_percent", strconv.FormatFloat(portfolio.RealizationPercent, 'f', 2, 64)},
			[]string{"cost_portfolio_summary", "verification_sla_seconds", strconv.FormatInt(portfolio.VerificationSLASeconds, 10)},
		)
		for _, item := range portfolio.Items {
			prefix := item.FindingID
			rows = append(rows,
				[]string{"cost_portfolio", prefix + ".state", item.State},
				[]string{"cost_portfolio", prefix + ".resource", item.Resource.Name},
				[]string{"cost_portfolio", prefix + ".potential_series_reduction", strconv.FormatInt(item.PotentialSeriesReduction, 10)},
				[]string{"cost_portfolio", prefix + ".verified_series_reduction", strconv.FormatInt(item.VerifiedSeriesReduction, 10)},
				[]string{"cost_portfolio", prefix + ".overdue", strconv.FormatBool(item.Overdue)},
			)
		}
		readiness, err := BuildCostReadinessSummary(ctx, store, filter, pricing, readinessConfig)
		if err != nil {
			return nil, nil, err
		}
		payload["cost_readiness"] = readiness
		rows = append(rows,
			[]string{"cost_readiness_summary", "opportunity_count", strconv.Itoa(readiness.OpportunityCount)},
			[]string{"cost_readiness_summary", "ready_count", strconv.Itoa(readiness.ReadyCount)},
			[]string{"cost_readiness_summary", "blocked_count", strconv.Itoa(readiness.BlockedCount)},
			[]string{"cost_readiness_summary", "ready_potential_series_reduction", strconv.FormatInt(readiness.ReadyPotentialSeriesReduction, 10)},
			[]string{"cost_readiness_summary", "blocked_potential_series_reduction", strconv.FormatInt(readiness.BlockedPotentialSeriesReduction, 10)},
			[]string{"cost_readiness_summary", "observation_window_seconds", strconv.FormatInt(readiness.ObservationWindowSeconds, 10)},
			[]string{"cost_readiness_summary", "required_evidence_domains", strings.Join(readiness.RequiredEvidenceDomains, ",")},
		)
		for _, item := range readiness.Items {
			prefix := item.FindingID
			rows = append(rows,
				[]string{"cost_readiness", prefix + ".state", item.ReadinessState},
				[]string{"cost_readiness", prefix + ".resource", item.Resource.Name},
				[]string{"cost_readiness", prefix + ".inventory_complete", strconv.FormatBool(item.InventoryComplete)},
				[]string{"cost_readiness", prefix + ".observation_age_seconds", strconv.FormatInt(item.ObservationAgeSeconds, 10)},
				[]string{"cost_readiness", prefix + ".consumer_count", strconv.Itoa(item.ConsumerCount)},
				[]string{"cost_readiness", prefix + ".blocking_reasons", strings.Join(item.BlockingReasons, ",")},
			)
		}
		allocation, err := BuildCostAllocationSummary(ctx, store, filter, pricing)
		if err != nil {
			return nil, nil, err
		}
		payload["cost_allocation"] = allocation
		rows = append(rows,
			[]string{"cost_allocation_summary", "metric_count", strconv.Itoa(allocation.MetricCount)},
			[]string{"cost_allocation_summary", "quantified_metric_count", strconv.Itoa(allocation.QuantifiedMetricCount)},
			[]string{"cost_allocation_summary", "measured_series", strconv.FormatInt(allocation.MeasuredSeries, 10)},
			[]string{"cost_allocation_summary", "pricing_configured", strconv.FormatBool(allocation.PricingConfigured)},
			[]string{"cost_allocation_summary", "currency", allocation.Currency},
		)
		if allocation.MeasuredMonthlyCost != nil {
			rows = append(rows, []string{"cost_allocation_summary", "measured_monthly_cost", strconv.FormatFloat(*allocation.MeasuredMonthlyCost, 'f', 2, 64)})
		}
		for _, dimension := range allocation.Dimensions {
			prefix := dimension.Name
			rows = append(rows,
				[]string{"cost_allocation_dimension", prefix + ".allocated_series", strconv.FormatInt(dimension.AllocatedSeries, 10)},
				[]string{"cost_allocation_dimension", prefix + ".unallocated_series", strconv.FormatInt(dimension.UnallocatedSeries, 10)},
				[]string{"cost_allocation_dimension", prefix + ".ambiguous_series", strconv.FormatInt(dimension.AmbiguousSeries, 10)},
				[]string{"cost_allocation_dimension", prefix + ".coverage_percent", strconv.FormatFloat(dimension.CoveragePercent, 'f', 2, 64)},
			)
			for _, item := range dimension.Items {
				itemPrefix := prefix + "." + item.State + "." + item.Key
				rows = append(rows,
					[]string{"cost_allocation", itemPrefix + ".metric_count", strconv.Itoa(item.MetricCount)},
					[]string{"cost_allocation", itemPrefix + ".series", strconv.FormatInt(item.Series, 10)},
					[]string{"cost_allocation", itemPrefix + ".share_percent", strconv.FormatFloat(item.SharePercent, 'f', 2, 64)},
				)
			}
		}
		guardrails, err := BuildCostGuardrailSummary(ctx, store, filter, pricing, guardrailConfig)
		if err != nil {
			return nil, nil, err
		}
		payload["cost_guardrails"] = guardrails
		rows = append(rows,
			[]string{"cost_guardrail_summary", "budget_state", guardrails.BudgetState},
			[]string{"cost_guardrail_summary", "measured_series", strconv.FormatInt(guardrails.MeasuredSeries, 10)},
			[]string{"cost_guardrail_summary", "monthly_budget", strconv.FormatFloat(guardrails.MonthlyBudget, 'f', 2, 64)},
			[]string{"cost_guardrail_summary", "metric_monthly_guardrail", strconv.FormatFloat(guardrails.MetricMonthlyGuardrail, 'f', 2, 64)},
			[]string{"cost_guardrail_summary", "exceeded_metric_count", strconv.Itoa(guardrails.ExceededMetricCount)},
		)
		if guardrails.MeasuredMonthlyCost != nil {
			rows = append(rows, []string{"cost_guardrail_summary", "measured_monthly_cost", strconv.FormatFloat(*guardrails.MeasuredMonthlyCost, 'f', 2, 64)})
		}
		if guardrails.BudgetVariance != nil {
			rows = append(rows, []string{"cost_guardrail_summary", "budget_variance", strconv.FormatFloat(*guardrails.BudgetVariance, 'f', 2, 64)})
		}
		for _, item := range guardrails.Items {
			prefix := item.Resource.ID
			rows = append(rows,
				[]string{"cost_metric_guardrail", prefix + ".resource", item.Resource.Name},
				[]string{"cost_metric_guardrail", prefix + ".series", strconv.FormatInt(item.Series, 10)},
				[]string{"cost_metric_guardrail", prefix + ".monthly_cost", strconv.FormatFloat(item.MonthlyCost, 'f', 2, 64)},
				[]string{"cost_metric_guardrail", prefix + ".state", item.GuardrailState},
			)
		}
		drift, err := BuildCostMetricDriftSummary(ctx, store, filter, pricing, driftConfig)
		if err != nil {
			return nil, nil, err
		}
		payload["cost_metric_drift"] = drift
		rows = append(rows,
			[]string{"cost_metric_drift_summary", "baseline_found", strconv.FormatBool(drift.BaselineFound)},
			[]string{"cost_metric_drift_summary", "lookback_seconds", strconv.FormatInt(drift.LookbackSeconds, 10)},
			[]string{"cost_metric_drift_summary", "compared_metric_count", strconv.Itoa(drift.ComparedMetricCount)},
			[]string{"cost_metric_drift_summary", "drift_metric_count", strconv.Itoa(drift.DriftMetricCount)},
			[]string{"cost_metric_drift_summary", "series_increase", strconv.FormatInt(drift.SeriesIncrease, 10)},
		)
		if drift.BaselineAt != nil {
			rows = append(rows, []string{"cost_metric_drift_summary", "baseline_at", drift.BaselineAt.Format(time.RFC3339Nano)})
		}
		if drift.MonthlyCostIncrease != nil {
			rows = append(rows, []string{"cost_metric_drift_summary", "monthly_cost_increase", strconv.FormatFloat(*drift.MonthlyCostIncrease, 'f', 2, 64)})
		}
		for _, item := range drift.Items {
			prefix := item.Resource.ID
			rows = append(rows,
				[]string{"cost_metric_drift", prefix + ".resource", item.Resource.Name},
				[]string{"cost_metric_drift", prefix + ".baseline_at", item.BaselineAt.Format(time.RFC3339Nano)},
				[]string{"cost_metric_drift", prefix + ".baseline_series", strconv.FormatInt(item.BaselineSeries, 10)},
				[]string{"cost_metric_drift", prefix + ".current_series", strconv.FormatInt(item.CurrentSeries, 10)},
				[]string{"cost_metric_drift", prefix + ".series_increase", strconv.FormatInt(item.SeriesIncrease, 10)},
				[]string{"cost_metric_drift", prefix + ".growth_percent", strconv.FormatFloat(item.GrowthPercent, 'f', 2, 64)},
			)
		}
	}
	rows = appendFindingRows(rows, findings)
	return payload, rows, nil
}

func resourcesByID(ctx context.Context, store *storage.Store) (map[string]model.Resource, error) {
	resources, err := store.Resources.List(ctx, storage.ResourceFilter{})
	if err != nil {
		return nil, err
	}
	byID := make(map[string]model.Resource, len(resources))
	for _, resource := range resources {
		byID[resource.ID] = resource
	}
	return byID, nil
}

func filterFindingsByTenant(findings []model.Finding, resourcesByID map[string]model.Resource, filter storage.ResourceFilter) []model.Finding {
	if filter.Team == "" && filter.Project == "" && filter.Namespace == "" && filter.Cluster == "" {
		return findings
	}
	filtered := make([]model.Finding, 0, len(findings))
	for _, finding := range findings {
		resource, ok := resourcesByID[finding.Resource.ID]
		if ok && resourceMatchesTenantFilter(resource, filter) {
			filtered = append(filtered, finding)
			continue
		}
		if findingMatchesTenantFilter(finding, filter) {
			filtered = append(filtered, finding)
		}
	}
	return filtered
}

func findingMatchesTenantFilter(finding model.Finding, filter storage.ResourceFilter) bool {
	if filter.Team != "" && !tenantMetadataValueMatches(finding.Metadata, "team", filter.Team) {
		return false
	}
	if filter.Project != "" && !tenantMetadataValueMatches(finding.Metadata, "project", filter.Project) {
		return false
	}
	if filter.Namespace != "" && !tenantMetadataValueMatches(finding.Metadata, "namespace", filter.Namespace) {
		return false
	}
	if filter.Cluster != "" && !tenantMetadataValueMatches(finding.Metadata, "cluster", filter.Cluster) {
		return false
	}
	return true
}

func resourceMatchesTenantFilter(resource model.Resource, filter storage.ResourceFilter) bool {
	if filter.Team != "" && !resourceTenantValueMatches(resource, "team", filter.Team) {
		return false
	}
	if filter.Project != "" && !resourceTenantValueMatches(resource, "project", filter.Project) {
		return false
	}
	if filter.Namespace != "" && !resourceTenantValueMatches(resource, "namespace", filter.Namespace) {
		return false
	}
	if filter.Cluster != "" && !resourceTenantValueMatches(resource, "cluster", filter.Cluster) {
		return false
	}
	return true
}

func tenantMetadataValueMatches(metadata map[string]string, dimension string, expected string) bool {
	for _, key := range tenantDimensionKeys(dimension) {
		if strings.EqualFold(strings.TrimSpace(metadata[key]), strings.TrimSpace(expected)) {
			return true
		}
	}
	return false
}

func resourceTenantValueMatches(resource model.Resource, dimension string, expected string) bool {
	expected = strings.TrimSpace(expected)
	if expected == "" {
		return true
	}
	for _, value := range resourceTenantValues(resource, dimension) {
		if strings.EqualFold(value, expected) {
			return true
		}
	}
	return false
}

func resourceTenantValues(resource model.Resource, dimension string) []string {
	keys := tenantDimensionKeys(dimension)
	values := make([]string, 0, len(keys)+1)
	for _, key := range keys {
		if value := strings.TrimSpace(resource.Labels[key]); value != "" {
			values = append(values, value)
		}
		if value := strings.TrimSpace(resource.Metadata[key]); value != "" {
			values = append(values, value)
		}
	}
	if dimension == "cluster" && strings.TrimSpace(resource.Source.Cluster) != "" {
		values = append(values, resource.Source.Cluster)
	}
	return values
}

func resourceTenantValue(resource model.Resource, dimension string) string {
	values := resourceTenantValues(resource, dimension)
	if len(values) == 0 {
		return "unassigned"
	}
	return values[0]
}

func findingTenantValue(finding model.Finding, resource model.Resource, dimension string) string {
	if resource.ID != "" {
		if value := resourceTenantValue(resource, dimension); value != "unassigned" {
			return value
		}
	}
	for _, key := range tenantDimensionKeys(dimension) {
		if value := strings.TrimSpace(finding.Metadata[key]); value != "" {
			return value
		}
	}
	return "unassigned"
}

func resourceSourceValue(resource model.Resource) string {
	if value := strings.TrimSpace(resource.Source.System); value != "" {
		return value
	}
	if value := strings.TrimSpace(resource.Metadata["source"]); value != "" {
		return value
	}
	return "unknown"
}

func findingSourceValue(finding model.Finding, resource model.Resource) string {
	if resource.ID != "" {
		return resourceSourceValue(resource)
	}
	for _, key := range []string{"source", "source_system"} {
		if value := strings.TrimSpace(finding.Metadata[key]); value != "" {
			return value
		}
	}
	return "unknown"
}

func tenantDimensionKeys(dimension string) []string {
	switch dimension {
	case "team":
		return []string{"team", "owner_team", "responsible_team"}
	case "project":
		return []string{"project", "project_id", "project_name"}
	case "namespace":
		return []string{"namespace", "kubernetes_namespace", "k8s_namespace"}
	case "cluster":
		return []string{"cluster", "cluster_name"}
	default:
		return []string{dimension}
	}
}

func appendMapRows(rows [][]string, section string, values map[string]int) [][]string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		rows = append(rows, []string{section, key, strconv.Itoa(values[key])})
	}
	return rows
}

func appendFindingRows(rows [][]string, findings []model.Finding) [][]string {
	limit := len(findings)
	if limit > 10 {
		limit = 10
	}
	for index := 0; index < limit; index++ {
		finding := findings[index]
		rows = append(rows, []string{"top_findings", finding.Type, string(finding.Severity) + " " + finding.Resource.Name})
	}
	return rows
}

func resourceOwner(resource model.Resource) string {
	if owner := strings.TrimSpace(resource.Metadata[model.MetadataOwner]); owner != "" {
		return owner
	}
	return strings.TrimSpace(resource.Labels[model.MetadataOwner])
}
