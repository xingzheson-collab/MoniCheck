package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

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
