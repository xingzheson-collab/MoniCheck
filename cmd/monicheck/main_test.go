package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"monicheck/internal/buildinfo"
	"monicheck/internal/execution"
)

func TestVersionSupportsTextAndJSONContracts(t *testing.T) {
	previousVersion, previousCommit, previousDate := buildinfo.Version, buildinfo.Commit, buildinfo.BuildDate
	t.Cleanup(func() {
		buildinfo.Version, buildinfo.Commit, buildinfo.BuildDate = previousVersion, previousCommit, previousDate
	})
	buildinfo.Version, buildinfo.Commit, buildinfo.BuildDate = "v0.6.2", strings.Repeat("a", 40), "2026-08-14T10:00:00Z"

	var stdout, stderr bytes.Buffer
	if code := runVersion(nil, &stdout, &stderr); code != 0 {
		t.Fatalf("text exit code = %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "MoniCheck v0.6.2") {
		t.Fatalf("unexpected text output: %s", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := runVersion([]string{"--format", "json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("json exit code = %d: %s", code, stderr.String())
	}
	var info buildinfo.Info
	if err := json.Unmarshal(stdout.Bytes(), &info); err != nil {
		t.Fatalf("decode version JSON: %v", err)
	}
	if info.ContractVersion != "build-info.v1" || info.Version != "v0.6.2" || info.Commit != strings.Repeat("a", 40) {
		t.Fatalf("unexpected build info: %+v", info)
	}
}

func TestVersionRejectsUnsupportedFormatsAndPositionals(t *testing.T) {
	for _, args := range [][]string{{"--format", "yaml"}, {"extra"}} {
		var stdout, stderr bytes.Buffer
		if code := runVersion(args, &stdout, &stderr); code != 2 {
			t.Fatalf("args %v exit code = %d", args, code)
		}
		if stderr.Len() == 0 {
			t.Fatalf("args %v returned no diagnostic", args)
		}
	}
}

func TestBundleOutRequiresExplicitCheckMode(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runLocal(context.Background(), []string{"--prometheus-url", "http://127.0.0.1:9090", "--bundle-out", "bundle.json"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit code = %d", code)
	}
	if !strings.Contains(stderr.String(), "--bundle-out require --check") {
		t.Fatalf("unexpected error: %s", stderr.String())
	}
}

func TestConnectorListIncludesEvidenceSources(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runConnectors([]string{"list"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code = %d: %s", code, stderr.String())
	}
	for _, typeName := range []string{"prometheus", "otelcol", "datadog", "newrelic"} {
		if !strings.Contains(stdout.String(), typeName) {
			t.Fatalf("missing connector %q", typeName)
		}
	}
}

func TestMCPCommandServesInitializeRequest(t *testing.T) {
	input := strings.NewReader("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-11-25\"}}\n")
	var stdout, stderr bytes.Buffer
	if code := runMCP(context.Background(), nil, input, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code = %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"name":"monicheck-local"`) {
		t.Fatalf("unexpected MCP response: %s", stdout.String())
	}
}

func TestLocalProgressIsStageSpecificAndCredentialSafe(t *testing.T) {
	var output bytes.Buffer
	for _, event := range []execution.ProgressEvent{
		{Stage: execution.ProgressStageSourceCollection, Total: 1},
		{Stage: execution.ProgressStageSnapshotPersistence, ResourceCount: 3316, RelationshipCount: 38847},
		{Stage: execution.ProgressStageInventoryReconciliation},
		{Stage: execution.ProgressStageAnalysis, Total: 650},
		{Stage: execution.ProgressStageFindingPersistence, Total: 9461},
	} {
		writeLocalProgress(&output, event)
	}
	text := output.String()
	for _, expected := range []string{"Collecting evidence", "3316 resources, 38847 relationships", "Reconciling inventory", "Running 650 analyzers", "Saving 9461 findings"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("progress output missing %q: %s", expected, text)
		}
	}
	for _, forbidden := range []string{"source-id", "prometheus.hqlygk.com", "token=", "bearer"} {
		if strings.Contains(strings.ToLower(text), forbidden) {
			t.Fatalf("progress output leaked %q: %s", forbidden, text)
		}
	}
}
