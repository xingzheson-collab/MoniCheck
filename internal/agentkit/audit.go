package agentkit

import (
	"context"
	"sort"
	"time"

	"monicheck/internal/localruntime"
	"monicheck/internal/report"
	"monicheck/internal/storage"
	"monicheck/pkg/evidence"
)

const (
	ContractVersion       = "agent-audit.v1"
	maxFindingGroupCount  = 25
	defaultActivationTime = 15 * time.Minute
)

type Gate struct {
	Passed           bool                     `json:"passed"`
	State            string                   `json:"state"`
	SnapshotCount    int                      `json:"snapshot_count"`
	RegressedMetrics []string                 `json:"regressed_metrics"`
	ImprovedMetrics  []string                 `json:"improved_metrics"`
	FindingDiff      *report.LocalFindingDiff `json:"finding_diff,omitempty"`
}

// BuildExisting rebuilds the Agent-facing audit from durable Local state. It
// never contacts providers or runs analyzers.
func BuildExisting(ctx context.Context, runtime *localruntime.Runtime) (Audit, error) {
	regression, err := report.BuildLocalRegression(ctx, runtime.Store)
	if err != nil {
		return Audit{}, err
	}
	bundle, err := runtime.EvidenceBundle(ctx)
	if err != nil {
		return Audit{}, err
	}
	audit := Build(bundle, regression, 0)
	resources, err := runtime.Store.Resources.List(ctx, storage.ResourceFilter{})
	if err != nil {
		return Audit{}, err
	}
	relationships, err := runtime.Store.Relationships.List(ctx)
	if err != nil {
		return Audit{}, err
	}
	audit.InventoryVisibility.ObservedResourceCount = len(resources)
	audit.InventoryVisibility.ObservedRelationshipCount = len(relationships)
	audit.InventoryVisibility.Basis = "Counts are rebuilt from the persisted Local audit. Provider permission, pagination, tenant, and folder completeness remain unverified."
	ownedResources := 0
	for _, resource := range resources {
		if resource.Labels["team"] != "" || resource.Labels["owner"] != "" {
			ownedResources++
		}
	}
	if ownedResources == 0 && len(resources) > 0 {
		audit.InventoryVisibility.OwnershipGuidance = "No team or owner labels were observed. Assign action groups by source and resource family first; add ownership labels before treating team-level counts as authoritative."
	}
	return audit, nil
}

type FindingGroup struct {
	Type             string `json:"type"`
	Category         string `json:"category"`
	Severity         string `json:"severity"`
	Status           string `json:"status"`
	ResourceType     string `json:"resource_type"`
	Count            int    `json:"count"`
	HighestRiskScore *int   `json:"highest_risk_score,omitempty"`
}

type Privacy struct {
	Classification string   `json:"classification"`
	Includes       []string `json:"includes"`
	Excludes       []string `json:"excludes"`
}

type InventoryVisibility struct {
	State                     string   `json:"state"`
	ConnectorCount            int      `json:"connector_count"`
	ObservedResourceCount     int      `json:"observed_resource_count"`
	ObservedRelationshipCount int      `json:"observed_relationship_count"`
	UnverifiedDimensions      []string `json:"unverified_dimensions"`
	Basis                     string   `json:"basis"`
	OwnershipGuidance         string   `json:"ownership_guidance,omitempty"`
}

type Audit struct {
	ContractVersion      string                       `json:"contract_version"`
	GeneratedAt          time.Time                    `json:"generated_at"`
	ScanElapsedMillis    int64                        `json:"scan_elapsed_milliseconds"`
	TargetSeconds        int64                        `json:"target_seconds"`
	WithinTarget         bool                         `json:"within_target"`
	Gate                 Gate                         `json:"gate"`
	Summary              evidence.Summary             `json:"summary"`
	Coverage             evidence.Coverage            `json:"coverage"`
	Cost                 evidence.Cost                `json:"cost"`
	Connectors           []evidence.ConnectorEvidence `json:"connectors"`
	FindingGroups        []FindingGroup               `json:"finding_groups"`
	FindingGroupCount    int                          `json:"finding_group_count"`
	OmittedFindingGroups int                          `json:"omitted_finding_groups"`
	ActionGroups         []ActionGroup                `json:"action_groups"`
	InventoryVisibility  InventoryVisibility          `json:"inventory_visibility"`
	Privacy              Privacy                      `json:"privacy"`
}

func Run(ctx context.Context, options localruntime.Options) (Audit, error) {
	started := time.Now().UTC()
	if options.ActivationStartedAt.IsZero() {
		options.ActivationStartedAt = started
	}
	runtime, err := localruntime.New(ctx, options)
	if err != nil {
		return Audit{}, err
	}
	regression, err := report.BuildLocalRegression(ctx, runtime.Store)
	if err != nil {
		return Audit{}, err
	}
	bundle, err := runtime.EvidenceBundle(ctx)
	if err != nil {
		return Audit{}, err
	}
	return Build(bundle, regression, time.Since(started)), nil
}

func Build(bundle evidence.Bundle, regression report.LocalRegressionReport, elapsed time.Duration) Audit {
	groups := groupFindings(bundle.Findings)
	actionGroups := actionGroupsFromFindingGroups(groups)
	groupCount := len(groups)
	if len(groups) > maxFindingGroupCount {
		groups = groups[:maxFindingGroupCount]
	}
	return Audit{
		ContractVersion:   ContractVersion,
		GeneratedAt:       bundle.GeneratedAt,
		ScanElapsedMillis: elapsed.Milliseconds(),
		TargetSeconds:     int64(defaultActivationTime / time.Second),
		WithinTarget:      elapsed <= defaultActivationTime,
		Gate: Gate{
			Passed:           len(regression.RegressedMetrics) == 0,
			State:            regression.State,
			SnapshotCount:    regression.SnapshotCount,
			RegressedMetrics: append([]string{}, regression.RegressedMetrics...),
			ImprovedMetrics:  append([]string{}, regression.ImprovedMetrics...),
			FindingDiff:      regression.FindingDiff,
		},
		Summary:              bundle.Summary,
		Coverage:             bundle.Coverage,
		Cost:                 bundle.Cost,
		Connectors:           append([]evidence.ConnectorEvidence{}, bundle.Connectors...),
		FindingGroups:        groups,
		FindingGroupCount:    groupCount,
		OmittedFindingGroups: groupCount - len(groups),
		ActionGroups:         actionGroups,
		InventoryVisibility:  inventoryVisibility(bundle.Connectors, bundle.Summary.ResourceCount),
		Privacy: Privacy{
			Classification: "PRIVACY_SAFE_AGENT_SUMMARY",
			Includes:       []string{"aggregate counts", "connector health", "coverage trust", "cost estimates", "finding classifications", "deterministic action templates", "regression movement"},
			Excludes:       []string{"credentials", "endpoint URLs", "resource names", "labels", "queries", "raw evidence", "dashboard JSON", "source configuration", "user identity"},
		},
	}
}

func inventoryVisibility(connectors []evidence.ConnectorEvidence, observedResources int) InventoryVisibility {
	relationships := 0
	for _, connector := range connectors {
		relationships += connector.RelationshipCount
	}
	return InventoryVisibility{
		State: "NOT_PROVEN_COMPLETE", ConnectorCount: len(connectors),
		ObservedResourceCount: observedResources, ObservedRelationshipCount: relationships,
		UnverifiedDimensions: []string{"provider permission role", "Grafana folder reachability", "API pagination beyond observed responses", "tenant and organization scope"},
		Basis:                "MoniCheck can report the inventory it observed, but the current evidence does not independently prove that provider credentials can see the complete estate.",
	}
}

func groupFindings(findings []evidence.FindingEvidence) []FindingGroup {
	byKey := make(map[string]*FindingGroup)
	for _, finding := range findings {
		key := finding.Type + "\x00" + finding.Category + "\x00" + finding.Severity + "\x00" + finding.Status + "\x00" + finding.ResourceType
		group := byKey[key]
		if group == nil {
			group = &FindingGroup{Type: finding.Type, Category: finding.Category, Severity: finding.Severity, Status: finding.Status, ResourceType: finding.ResourceType}
			byKey[key] = group
		}
		group.Count++
		if finding.RiskScore != nil && (group.HighestRiskScore == nil || *finding.RiskScore > *group.HighestRiskScore) {
			score := *finding.RiskScore
			group.HighestRiskScore = &score
		}
	}
	result := make([]FindingGroup, 0, len(byKey))
	for _, group := range byKey {
		result = append(result, *group)
	}
	sort.Slice(result, func(i, j int) bool {
		left, right := severityRank(result[i].Severity), severityRank(result[j].Severity)
		if left != right {
			return left > right
		}
		if result[i].Count != result[j].Count {
			return result[i].Count > result[j].Count
		}
		return result[i].Type < result[j].Type
	})
	return result
}

func severityRank(value string) int {
	switch value {
	case "CRITICAL":
		return 3
	case "WARNING":
		return 2
	case "INFO":
		return 1
	default:
		return 0
	}
}
