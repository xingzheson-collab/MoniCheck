package logger

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestQuietLoggerSuppressesRuntimeDiagnostics(t *testing.T) {
	var output bytes.Buffer
	New(&output, "quiet").Error(context.Background(), "private connector failure", "endpoint", "https://prometheus.internal")
	if output.Len() != 0 {
		t.Fatalf("quiet logger emitted runtime diagnostics: %s", output.String())
	}

	New(&output, "error").Error(context.Background(), "connector failure")
	if !strings.Contains(output.String(), "connector failure") {
		t.Fatalf("error logger did not remain available: %s", output.String())
	}
}
