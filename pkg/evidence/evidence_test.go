package evidence

import (
	"testing"
	"time"
)

func TestBundleNormalizeAndValidate(t *testing.T) {
	now := time.Now().UTC()
	bundle := Bundle{BundleID: AnonymousID("bundle", "scan-1"), GeneratedAt: now, Execution: Execution{Ref: AnonymousID("execution", "scan-1"), Status: "SUCCEEDED", StartedAt: now.Add(-time.Second), FinishedAt: now}, Summary: Summary{}, Coverage: Coverage{Percent: 100}, Connectors: []ConnectorEvidence{{InstanceRef: AnonymousID("connector", "prometheus:prod"), Type: "prometheus", Group: "Metrics", Status: "SUCCEEDED"}}, Findings: []FindingEvidence{{Ref: AnonymousID("finding", "finding-1"), Type: "UnusedMetric", ResourceRef: AnonymousID("resource", "resource-1"), ResourceType: "Metric"}}}
	bundle.Normalize()
	if err := bundle.Validate(); err != nil {
		t.Fatal(err)
	}
	if bundle.ContractVersion != ContractVersion || bundle.Product.Mode != "LOCAL" {
		t.Fatalf("normalization failed: %#v", bundle)
	}
}

func TestAnonymousIDIsStableAndDoesNotExposeInput(t *testing.T) {
	first := AnonymousID("resource", "prometheus.internal", "customer_metric")
	second := AnonymousID("resource", "prometheus.internal", "customer_metric")
	if first != second {
		t.Fatal("anonymous ID is not stable")
	}
	if first == "" || first == "prometheus.internal" {
		t.Fatalf("unsafe anonymous ID: %q", first)
	}
}
