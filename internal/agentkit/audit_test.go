package agentkit

import (
	"fmt"
	"testing"
	"time"

	"monicheck/internal/report"
	"monicheck/pkg/evidence"
)

func TestBuildProducesBoundedPrivacySafeAgentSummary(t *testing.T) {
	now := time.Now().UTC()
	bundle := evidence.Bundle{
		GeneratedAt: now,
		Summary:     evidence.Summary{ResourceCount: 42, FindingCount: 30, OpenFindingCount: 29, CriticalCount: 2},
		Coverage:    evidence.Coverage{EvidenceState: "PARTIAL", EvidenceCompletenessPercent: 72},
		Connectors:  []evidence.ConnectorEvidence{{InstanceRef: "connector_anon", Type: "prometheus", Group: "Metrics", Status: "SUCCEEDED"}},
	}
	for index := 0; index < 30; index++ {
		score := index
		bundle.Findings = append(bundle.Findings, evidence.FindingEvidence{
			Ref: fmt.Sprintf("finding_%d", index), Type: fmt.Sprintf("Type%02d", index), Category: "RELIABILITY",
			Severity: "WARNING", Status: "OPEN", RiskScore: &score, ResourceType: "METRIC", ResourceRef: fmt.Sprintf("resource_%d", index),
		})
	}
	regression := report.LocalRegressionReport{State: "REGRESSED", SnapshotCount: 2, RegressedMetrics: []string{"new_open_findings"}}

	got := Build(bundle, regression, 2*time.Second)
	if got.ContractVersion != ContractVersion || got.Gate.Passed || got.Gate.State != "REGRESSED" {
		t.Fatalf("unexpected agent audit gate: %#v", got)
	}
	if len(got.FindingGroups) != maxFindingGroupCount || got.OmittedFindingGroups != 5 {
		t.Fatalf("agent finding groups were not bounded: groups=%d omitted=%d", len(got.FindingGroups), got.OmittedFindingGroups)
	}
	if got.Privacy.Classification != "PRIVACY_SAFE_AGENT_SUMMARY" || len(got.Privacy.Excludes) == 0 {
		t.Fatalf("privacy contract missing: %#v", got.Privacy)
	}
	if got.Connectors[0].InstanceRef != "connector_anon" || got.Summary.ResourceCount != 42 {
		t.Fatalf("evidence summary was not preserved: %#v", got)
	}
}
