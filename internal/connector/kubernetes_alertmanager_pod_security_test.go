package connector

import (
	"testing"
	"time"
)

func TestKubernetesManifestConnectorMapsAlertmanagerPodSecurity(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: risky, namespace: monitoring}
spec:
  securityContext:
    runAsNonRoot: false
    runAsUser: 0
    seccompProfile: {type: Unconfined}
  containers:
    - name: alertmanager
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
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/risky"]
	expected := map[string]string{
		"alertmanager_root_user_context_count":                "1",
		"alertmanager_non_root_disabled_context_count":        "1",
		"alertmanager_privileged_container_count":             "1",
		"alertmanager_host_process_context_count":             "1",
		"alertmanager_privilege_escalation_context_count":     "1",
		"alertmanager_unconfined_seccomp_context_count":       "1",
		"alertmanager_capability_addition_context_count":      "1",
		"alertmanager_writable_root_filesystem_context_count": "1",
		"alertmanager_security_context_invalid_count":         "0",
	}
	for key, value := range expected {
		if resource.Metadata[key] != value {
			t.Fatalf("expected %s=%s, got %#v", key, value, resource.Metadata)
		}
	}
}

func TestKubernetesManifestConnectorRejectsMalformedAlertmanagerPodSecurity(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: invalid, namespace: monitoring}
spec:
  securityContext:
    runAsNonRoot: enabled
    seccompProfile: {type: Unknown}
  containers:
    - name: alertmanager
      securityContext:
        privileged: enabled
        capabilities: {add: invalid}
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/invalid"]
	if resource.Metadata["alertmanager_security_context_invalid_count"] != "4" {
		t.Fatalf("unexpected invalid security metadata: %#v", resource.Metadata)
	}
}
