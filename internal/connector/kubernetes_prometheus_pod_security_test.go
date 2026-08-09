package connector

import (
	"strings"
	"testing"
	"time"
)

func TestKubernetesManifestConnectorMapsPrometheusPodSecurity(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: risky, namespace: monitoring}
spec:
  securityContext:
    runAsNonRoot: false
    runAsUser: 0
    seccompProfile: {type: Unconfined}
  containers:
    - name: prometheus
      securityContext:
        privileged: true
        allowPrivilegeEscalation: true
        readOnlyRootFilesystem: false
        capabilities:
          add: [NET_ADMIN]
  initContainers:
    - name: bootstrap
      securityContext:
        windowsOptions: {hostProcess: true}
---
apiVersion: monitoring.coreos.com/v1alpha1
kind: PrometheusAgent
metadata: {name: invalid, namespace: monitoring}
spec:
  securityContext:
    runAsNonRoot: enabled
    seccompProfile: {type: Unknown}
  containers:
    - name: prometheus
      securityContext:
        privileged: enabled
        capabilities: {add: invalid}
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resources := alertmanagerConfigSourceResourcesByName(snapshot.Resources)
	risky := resources["monitoring/risky"]
	expected := map[string]string{
		"prometheus_root_user_context_count":                "1",
		"prometheus_non_root_disabled_context_count":        "1",
		"prometheus_privileged_container_count":             "1",
		"prometheus_host_process_context_count":             "1",
		"prometheus_privilege_escalation_context_count":     "1",
		"prometheus_unconfined_seccomp_context_count":       "1",
		"prometheus_capability_addition_context_count":      "1",
		"prometheus_writable_root_filesystem_context_count": "1",
		"prometheus_security_context_invalid_count":         "0",
	}
	for key, value := range expected {
		if risky.Metadata[key] != value {
			t.Fatalf("expected %s=%s, got %#v", key, value, risky.Metadata)
		}
	}
	invalid := resources["monitoring/invalid"]
	if invalid.Metadata["prometheus_pod_security_metadata"] != "true" || invalid.Metadata["prometheus_security_context_invalid_count"] != "4" {
		t.Fatalf("unexpected invalid PrometheusAgent security metadata: %#v", invalid.Metadata)
	}
	for _, resource := range snapshot.Resources {
		for key, value := range resource.Metadata {
			for _, private := range []string{"NET_ADMIN", "bootstrap"} {
				if strings.Contains(value, private) {
					t.Fatalf("Prometheus security detail persisted in %s=%q: %#v", key, value, resource.Metadata)
				}
			}
		}
	}
}

func TestKubernetesPodSecuritySummarySharedWithAlertmanager(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: prometheus, namespace: monitoring}
spec:
  securityContext: {runAsUser: 0, runAsNonRoot: false}
  containers:
    - name: prometheus
      securityContext: {privileged: true, allowPrivilegeEscalation: true}
---
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: alertmanager, namespace: monitoring}
spec:
  securityContext: {runAsUser: 0, runAsNonRoot: false}
  containers:
    - name: alertmanager
      securityContext: {privileged: true, allowPrivilegeEscalation: true}
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resources := alertmanagerConfigSourceResourcesByName(snapshot.Resources)
	prometheus := resources["monitoring/prometheus"]
	alertmanager := resources["monitoring/alertmanager"]
	for _, suffix := range []string{"root_user_context_count", "non_root_disabled_context_count", "privileged_container_count", "privilege_escalation_context_count", "security_context_invalid_count"} {
		if prometheus.Metadata["prometheus_"+suffix] != alertmanager.Metadata["alertmanager_"+suffix] {
			t.Fatalf("shared Pod security parsing diverged for %s: prometheus=%q alertmanager=%q", suffix, prometheus.Metadata["prometheus_"+suffix], alertmanager.Metadata["alertmanager_"+suffix])
		}
	}
}
