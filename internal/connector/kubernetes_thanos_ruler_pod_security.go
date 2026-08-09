package connector

import (
	"strconv"

	"gopkg.in/yaml.v3"
	"monicheck/internal/model"
)

func populateKubernetesThanosRulerPodSecurityObject(object *kubernetesObject, spec *yaml.Node) {
	summary := parseKubernetesPodSecuritySummary(spec)
	object.ThanosRulerPodSecurityMetadata = true
	object.ThanosRulerSecurityContextInvalidCount = summary.InvalidCount
	object.ThanosRulerRootUserContextCount = summary.RootUserCount
	object.ThanosRulerNonRootDisabledContextCount = summary.NonRootDisabledCount
	object.ThanosRulerPrivilegedContainerCount = summary.PrivilegedCount
	object.ThanosRulerHostProcessContextCount = summary.HostProcessCount
	object.ThanosRulerPrivilegeEscalationContextCount = summary.PrivilegeEscalationCount
	object.ThanosRulerUnconfinedSeccompContextCount = summary.UnconfinedSeccompCount
	object.ThanosRulerCapabilityAdditionContextCount = summary.CapabilityAdditionCount
	object.ThanosRulerWritableRootFilesystemContextCount = summary.WritableRootFSCount
}

func populateKubernetesThanosRulerPodSecurityMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["thanos_ruler_pod_security_metadata"] = strconv.FormatBool(object.ThanosRulerPodSecurityMetadata)
	resource.Metadata["thanos_ruler_security_context_invalid_count"] = strconv.Itoa(object.ThanosRulerSecurityContextInvalidCount)
	resource.Metadata["thanos_ruler_root_user_context_count"] = strconv.Itoa(object.ThanosRulerRootUserContextCount)
	resource.Metadata["thanos_ruler_non_root_disabled_context_count"] = strconv.Itoa(object.ThanosRulerNonRootDisabledContextCount)
	resource.Metadata["thanos_ruler_privileged_container_count"] = strconv.Itoa(object.ThanosRulerPrivilegedContainerCount)
	resource.Metadata["thanos_ruler_host_process_context_count"] = strconv.Itoa(object.ThanosRulerHostProcessContextCount)
	resource.Metadata["thanos_ruler_privilege_escalation_context_count"] = strconv.Itoa(object.ThanosRulerPrivilegeEscalationContextCount)
	resource.Metadata["thanos_ruler_unconfined_seccomp_context_count"] = strconv.Itoa(object.ThanosRulerUnconfinedSeccompContextCount)
	resource.Metadata["thanos_ruler_capability_addition_context_count"] = strconv.Itoa(object.ThanosRulerCapabilityAdditionContextCount)
	resource.Metadata["thanos_ruler_writable_root_filesystem_context_count"] = strconv.Itoa(object.ThanosRulerWritableRootFilesystemContextCount)
}
