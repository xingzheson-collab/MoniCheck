package connector

import (
	"strconv"

	"gopkg.in/yaml.v3"
	"monicheck/internal/model"
)

func populateKubernetesAlertmanagerPodSecurityObject(object *kubernetesObject, spec *yaml.Node) {
	summary := parseKubernetesPodSecuritySummary(spec)
	object.AlertmanagerPodSecurityMetadata = true
	object.AlertmanagerSecurityContextInvalidCount = summary.InvalidCount
	object.AlertmanagerRootUserContextCount = summary.RootUserCount
	object.AlertmanagerNonRootDisabledContextCount = summary.NonRootDisabledCount
	object.AlertmanagerPrivilegedContainerCount = summary.PrivilegedCount
	object.AlertmanagerHostProcessContextCount = summary.HostProcessCount
	object.AlertmanagerPrivilegeEscalationContextCount = summary.PrivilegeEscalationCount
	object.AlertmanagerUnconfinedSeccompContextCount = summary.UnconfinedSeccompCount
	object.AlertmanagerCapabilityAdditionContextCount = summary.CapabilityAdditionCount
	object.AlertmanagerWritableRootFilesystemContextCount = summary.WritableRootFSCount
}

func populateKubernetesAlertmanagerPodSecurityMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["alertmanager_pod_security_metadata"] = strconv.FormatBool(object.AlertmanagerPodSecurityMetadata)
	resource.Metadata["alertmanager_security_context_invalid_count"] = strconv.Itoa(object.AlertmanagerSecurityContextInvalidCount)
	resource.Metadata["alertmanager_root_user_context_count"] = strconv.Itoa(object.AlertmanagerRootUserContextCount)
	resource.Metadata["alertmanager_non_root_disabled_context_count"] = strconv.Itoa(object.AlertmanagerNonRootDisabledContextCount)
	resource.Metadata["alertmanager_privileged_container_count"] = strconv.Itoa(object.AlertmanagerPrivilegedContainerCount)
	resource.Metadata["alertmanager_host_process_context_count"] = strconv.Itoa(object.AlertmanagerHostProcessContextCount)
	resource.Metadata["alertmanager_privilege_escalation_context_count"] = strconv.Itoa(object.AlertmanagerPrivilegeEscalationContextCount)
	resource.Metadata["alertmanager_unconfined_seccomp_context_count"] = strconv.Itoa(object.AlertmanagerUnconfinedSeccompContextCount)
	resource.Metadata["alertmanager_capability_addition_context_count"] = strconv.Itoa(object.AlertmanagerCapabilityAdditionContextCount)
	resource.Metadata["alertmanager_writable_root_filesystem_context_count"] = strconv.Itoa(object.AlertmanagerWritableRootFilesystemContextCount)
}
