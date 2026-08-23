package agentkit

import (
	"sort"
	"strings"

	"monicheck/internal/model"
)

const maximumActionGroups = 10

type ActionGroup struct {
	ID                string         `json:"id"`
	Family            string         `json:"family"`
	Title             string         `json:"title"`
	Severity          model.Severity `json:"severity"`
	FindingCount      int            `json:"finding_count"`
	ResourceCount     int            `json:"resource_count,omitempty"`
	FindingTypes      []string       `json:"finding_types"`
	AffectedResources []EntityRef    `json:"affected_resources,omitempty"`
	Consequence       string         `json:"consequence"`
	FirstStep         string         `json:"first_step"`
	Verification      string         `json:"verification"`
}

type actionTemplate struct {
	Title        string
	Consequence  string
	FirstStep    string
	Verification string
}

var actionTemplates = map[string]actionTemplate{
	"target-telemetry-loss": {
		Title:        "Restore or intentionally retire broken telemetry targets",
		Consequence:  "Metrics from the affected target path may be unavailable, so dependent dashboards and alerts can become blind.",
		FirstStep:    "Open the collected target inventory, verify the exporter or workload is expected to exist, then choose restore or documented retirement.",
		Verification: "Repeat the scan and require the target finding to clear without reducing expected service coverage.",
	},
	"service-coverage-gap": {
		Title:        "Close or explicitly accept a monitoring coverage gap",
		Consequence:  "The affected Service lacks an evaluable required signal and may fail without the expected detection path.",
		FirstStep:    "Confirm the Service is in scope, inspect its signal matrix, then add the missing collection/dashboard/alert or create a time-bounded exception.",
		Verification: "Repeat coverage assessment and require MISSING to become OBSERVED or an approved EXEMPT state; UNKNOWN is not closure.",
	},
	"dashboard-integrity": {
		Title:        "Repair dashboard datasource or query integrity",
		Consequence:  "Operators may see empty or misleading panels during diagnosis even when telemetry exists.",
		FirstStep:    "Inspect the affected dashboard and datasource binding, then repair only the explicitly attributed query or retire the dashboard with owner confirmation.",
		Verification: "Reload the dashboard against the intended datasource and repeat the scan without broadening datasource attribution.",
	},
	"metric-contract-drift": {
		Title:        "Reconcile inconsistent metric metadata",
		Consequence:  "Different metric type, help, or unit contracts can produce incorrect queries, rates, and aggregations.",
		FirstStep:    "Identify the emitting versions for the affected metric and standardize instrumentation before changing downstream queries.",
		Verification: "Repeat metadata collection and require one consistent metric contract across active emitters.",
	},
	"alert-delivery": {
		Title:        "Restore the alert delivery path",
		Consequence:  "A firing condition may not reach an intended receiver or may route unpredictably.",
		FirstStep:    "Trace the affected rule through notification policy and receiver references, then repair the first undefined or unhealthy hop.",
		Verification: "Run a controlled notification test and repeat the scan until the delivery finding clears.",
	},
	"telemetry-cost": {
		Title:        "Validate and reduce avoidable telemetry volume",
		Consequence:  "High-cardinality or unused telemetry can consume storage and query capacity without proportional operational value.",
		FirstStep:    "Confirm source attribution and usage history, quantify the affected series, then test a recording, relabel, aggregation, or retention change on a bounded scope.",
		Verification: "Compare the next baseline for lower series cost without new coverage gaps or broken queries.",
	},
	"configuration-risk": {
		Title:        "Review the highest-confidence configuration risk",
		Consequence:  "The current configuration can reduce observability reliability, safety, or maintainability.",
		FirstStep:    "Inspect the scoped entity and deterministic recommendation, then validate the change in a non-production or review workflow.",
		Verification: "Repeat the scan and require the finding to clear without introducing a regression.",
	},
}

func actionTemplateFor(family string) actionTemplate {
	if template, ok := actionTemplates[family]; ok {
		return template
	}
	if strings.HasPrefix(family, "hygiene-backlog/") {
		resourceType := strings.TrimPrefix(family, "hygiene-backlog/")
		return actionTemplate{
			Title:        "Review " + resourceType + " hygiene backlog",
			Consequence:  "Accumulated configuration findings can hide higher-value work and make future changes harder to review safely.",
			FirstStep:    "Assign an owner for this resource family, sample the highest-severity findings, then batch only changes that share the same operational consequence.",
			Verification: "Repeat the scan and confirm the resource-family backlog falls without new reliability or coverage regressions.",
		}
	}
	return actionTemplates["configuration-risk"]
}

func actionGroupsFromFindingGroups(findingGroups []FindingGroup) []ActionGroup {
	type groupState struct {
		group ActionGroup
		types map[string]bool
	}
	states := map[string]*groupState{}
	for _, finding := range findingGroups {
		family := actionFamily(finding.Type, finding.Category, finding.ResourceType)
		state := states[family]
		if state == nil {
			template := actionTemplateFor(family)
			state = &groupState{group: ActionGroup{
				ID: model.StableID("agent_action", family), Family: family, Title: template.Title,
				Severity: model.Severity(finding.Severity), Consequence: template.Consequence,
				FirstStep: template.FirstStep, Verification: template.Verification,
			}, types: map[string]bool{}}
			states[family] = state
		}
		state.group.FindingCount += finding.Count
		state.types[finding.Type] = true
		if querySeverityRank(model.Severity(finding.Severity)) > querySeverityRank(state.group.Severity) {
			state.group.Severity = model.Severity(finding.Severity)
		}
	}
	groups := make([]ActionGroup, 0, len(states))
	for _, state := range states {
		state.group.FindingTypes = sortedKeys(state.types)
		groups = append(groups, state.group)
	}
	sortActionGroups(groups)
	if len(groups) > maximumActionGroups {
		groups = groups[:maximumActionGroups]
	}
	return groups
}

func actionGroupsFromQuery(items, disclosedItems []FindingQueryItem) []ActionGroup {
	type groupState struct {
		group     ActionGroup
		types     map[string]bool
		resources map[string]EntityRef
	}
	disclosedResources := map[string]bool{}
	for _, item := range disclosedItems {
		disclosedResources[item.Resource.ID] = true
	}
	states := map[string]*groupState{}
	for _, item := range items {
		family := actionFamily(item.Type, string(item.Category), string(item.Resource.Type))
		state := states[family]
		if state == nil {
			template := actionTemplateFor(family)
			state = &groupState{group: ActionGroup{
				ID: model.StableID("agent_action", family), Family: family, Title: template.Title,
				Severity: item.Severity, Consequence: template.Consequence,
				FirstStep: template.FirstStep, Verification: template.Verification,
			}, types: map[string]bool{}, resources: map[string]EntityRef{}}
			states[family] = state
		}
		state.group.FindingCount++
		state.types[item.Type] = true
		if disclosedResources[item.Resource.ID] {
			state.resources[item.Resource.ID] = item.Resource
		}
		if querySeverityRank(item.Severity) > querySeverityRank(state.group.Severity) {
			state.group.Severity = item.Severity
		}
	}
	groups := make([]ActionGroup, 0, len(states))
	for _, state := range states {
		state.group.FindingTypes = sortedKeys(state.types)
		resourceIDsAll := map[string]bool{}
		for _, item := range items {
			if actionFamily(item.Type, string(item.Category), string(item.Resource.Type)) == state.group.Family {
				resourceIDsAll[item.Resource.ID] = true
			}
		}
		state.group.ResourceCount = len(resourceIDsAll)
		resourceIDs := make([]string, 0, len(state.resources))
		for id := range state.resources {
			resourceIDs = append(resourceIDs, id)
		}
		sort.Strings(resourceIDs)
		for index, id := range resourceIDs {
			if index == 10 {
				break
			}
			state.group.AffectedResources = append(state.group.AffectedResources, state.resources[id])
		}
		groups = append(groups, state.group)
	}
	sortActionGroups(groups)
	if len(groups) > maximumActionGroups {
		groups = groups[:maximumActionGroups]
	}
	return groups
}

func sortActionGroups(groups []ActionGroup) {
	sort.Slice(groups, func(i, j int) bool {
		left, right := querySeverityRank(groups[i].Severity), querySeverityRank(groups[j].Severity)
		if left != right {
			return left > right
		}
		if groups[i].FindingCount != groups[j].FindingCount {
			return groups[i].FindingCount > groups[j].FindingCount
		}
		return groups[i].Family < groups[j].Family
	})
}

func sortedKeys(values map[string]bool) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func actionFamily(findingType, category, resourceType string) string {
	switch findingType {
	case "BrokenTarget", "SlowTargetScrape", "StaleTargetScrape", "TargetScrapeTimeoutRisk":
		return "target-telemetry-loss"
	case "ServiceObservabilityGap", "MissingMonitoringCoverage", "KubernetesServiceWithoutMonitor":
		return "service-coverage-gap"
	case "BrokenDashboard", "InvalidDatasource", "UnusedDatasource":
		return "dashboard-integrity"
	case "InconsistentMetricMetadata":
		return "metric-contract-drift"
	case "UndefinedReceiver", "MissingDefaultReceiver", "NotificationPolicyWithoutReceiver", "HighImpactAlertWithoutReceiver":
		return "alert-delivery"
	}
	if strings.EqualFold(category, string(model.FindingCategoryCost)) || strings.Contains(strings.ToLower(findingType), "cardinality") || strings.Contains(strings.ToLower(findingType), "unusedmetric") {
		return "telemetry-cost"
	}
	resourceType = strings.ToLower(strings.TrimSpace(resourceType))
	if resourceType == "" {
		resourceType = "unclassified"
	}
	return "hygiene-backlog/" + resourceType
}
