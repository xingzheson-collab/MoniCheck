package analyzer

import (
	"context"
	"testing"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestSilenceWithoutCommentAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	now := time.Now().UTC()
	missingComment := silenceResource("missing-comment", now, now.Add(time.Hour), "active")
	pendingMissingComment := silenceResource("pending-comment", now.Add(time.Hour), now.Add(2*time.Hour), "pending")
	n9eMissingComment := silenceResource("n9e-missing-comment", now, now.Add(time.Hour), "active")
	n9eMissingComment.Source.System = "n9e"
	withComment := silenceResource("with-comment", now, now.Add(time.Hour), "active")
	withComment.Metadata[model.MetadataSilenceComment] = "deploy maintenance"
	unknownStub := silenceResource("unknown-stub", now, now.Add(time.Hour), "unknown")
	expired := silenceResource("expired", now.Add(-2*time.Hour), now.Add(-time.Hour), "expired")
	for _, resource := range []model.Resource{missingComment, pendingMissingComment, n9eMissingComment, withComment, unknownStub, expired} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert silence: %v", err)
		}
	}
	findings, err := NewSilenceWithoutCommentAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("expected Alertmanager and N9E missing-comment findings, got %#v", findings)
	}
	for _, finding := range findings {
		if finding.Type != "SilenceWithoutComment" || finding.Category != model.FindingCategoryLifecycle || finding.Severity != model.SeverityWarning {
			t.Fatalf("unexpected finding: %#v", finding)
		}
	}
}

func TestBroadSilenceMatcherAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	now := time.Now().UTC()
	noMatchers := silenceResource("no-matchers", now, now.Add(time.Hour), "active")
	wildcard := silenceWithMatcherDetails("wildcard", `[{"name":"alertname","value":"^.*$","is_regex":true,"is_equal":true}]`, "alertname=~^.*$", now)
	onlyNegative := silenceWithMatcherDetails("only-negative", `[{"name":"severity","value":"info","is_regex":false,"is_equal":false}]`, "severity!=info", now)
	n9eWildcard := silenceWithMatcherDetails("n9e-wildcard", `[{"name":"instance","value":".*","is_regex":true,"is_equal":true}]`, "instance =~ .*", now)
	n9eWildcard.Source.System = "n9e"
	scoped := silenceWithMatcherDetails("scoped", `[{"name":"service","value":"payments","is_regex":false,"is_equal":true}]`, "service=payments", now)
	mixed := silenceWithMatcherDetails("mixed", `[{"name":"service","value":"payments","is_regex":false,"is_equal":true},{"name":"severity","value":"info","is_regex":false,"is_equal":false}]`, "service=payments,severity!=info", now)
	for _, resource := range []model.Resource{noMatchers, wildcard, onlyNegative, n9eWildcard, scoped, mixed} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert silence: %v", err)
		}
	}
	findings, err := NewBroadSilenceMatcherAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 4 {
		t.Fatalf("expected broad Alertmanager and N9E matcher findings, got %#v", findings)
	}
	byResource := map[string]model.Finding{}
	for _, finding := range findings {
		byResource[finding.Resource.ID] = finding
	}
	if byResource[noMatchers.ID].Severity != model.SeverityCritical || byResource[wildcard.ID].Severity != model.SeverityWarning || byResource[onlyNegative.ID].Severity != model.SeverityWarning || byResource[n9eWildcard.ID].Severity != model.SeverityWarning {
		t.Fatalf("unexpected broad silence severities: %#v", byResource)
	}
	if byResource[scoped.ID].ID != "" || byResource[mixed.ID].ID != "" {
		t.Fatalf("expected scoped matchers not to produce findings: %#v", byResource)
	}
}

func silenceWithMatcherDetails(id string, details string, display string, now time.Time) model.Resource {
	resource := silenceResource(id, now, now.Add(time.Hour), "active")
	resource.Metadata[model.MetadataSilenceMatcherDetails] = details
	resource.Metadata[model.MetadataSilenceMatchers] = display
	return resource
}
