package connector

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"monicheck/internal/model"

	"gopkg.in/yaml.v3"
)

const kubernetesSystem = "kubernetes"

type KubernetesManifestConnector struct {
	manifestPath string
}

func NewKubernetesManifestConnector(manifestPath string) (*KubernetesManifestConnector, error) {
	manifestPath = strings.TrimSpace(manifestPath)
	if manifestPath == "" {
		return nil, fmt.Errorf("kubernetes manifest path is empty")
	}
	return &KubernetesManifestConnector{manifestPath: manifestPath}, nil
}

func (c *KubernetesManifestConnector) ID() string {
	return "kubernetes"
}

func (c *KubernetesManifestConnector) Name() string {
	return "Kubernetes Manifest Connector"
}

func (c *KubernetesManifestConnector) Sync(ctx context.Context) (Snapshot, error) {
	select {
	case <-ctx.Done():
		return Snapshot{}, ctx.Err()
	default:
	}
	content, err := readKubernetesManifestContent(ctx, c.manifestPath)
	if err != nil {
		return Snapshot{}, err
	}
	snapshot, err := kubernetesSnapshotFromManifest(content, c.manifestPath, time.Now().UTC())
	if err != nil {
		return Snapshot{}, fmt.Errorf("parse kubernetes manifest %s: %w", c.manifestPath, err)
	}
	return snapshot, nil
}

func readKubernetesManifestContent(ctx context.Context, manifestPath string) (string, error) {
	info, err := os.Stat(manifestPath)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		content, err := os.ReadFile(manifestPath)
		if err != nil {
			return "", err
		}
		return string(content), nil
	}

	paths := make([]string, 0)
	err = filepath.WalkDir(manifestPath, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if entry.IsDir() {
			if path != manifestPath && strings.HasPrefix(entry.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		extension := strings.ToLower(filepath.Ext(entry.Name()))
		if extension == ".yaml" || extension == ".yml" || extension == ".json" {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if len(paths) == 0 {
		return "", fmt.Errorf("kubernetes manifest directory %s contains no YAML or JSON files", manifestPath)
	}
	sort.Strings(paths)

	var combined strings.Builder
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		if _, err := decodeKubernetesManifestNodes(string(content)); err != nil {
			return "", fmt.Errorf("parse kubernetes manifest file %s: %w", path, err)
		}
		if combined.Len() > 0 {
			combined.WriteString("\n---\n")
		}
		combined.Write(content)
	}
	return combined.String(), nil
}

type kubernetesObject struct {
	Kind                                            string
	Name                                            string
	Namespace                                       string
	Labels                                          map[string]string
	Selector                                        map[string]string
	NamespaceSelectorAny                            bool
	NamespaceSelectorNames                          []string
	EndpointCount                                   int
	EndpointPorts                                   []string
	ProbeJobName                                    string
	ProbeModule                                     string
	ProbeProberURL                                  string
	ProbeProberScheme                               string
	ProbeProberPath                                 string
	ProbeTargetMode                                 string
	ProbeTargetCount                                int
	ProbeInterval                                   string
	ProbeScrapeTimeout                              string
	ScrapeConfigJobName                             string
	ScrapeConfigMetricsPath                         string
	ScrapeConfigScheme                              string
	ScrapeConfigInterval                            string
	ScrapeConfigTimeout                             string
	ScrapeConfigStaticCount                         int
	ScrapeConfigEmptyStaticCount                    int
	ScrapeConfigStaticTargetCount                   int
	ScrapeConfigDiscoveryConfigCount                int
	ScrapeConfigDiscoveryConfigTypes                []string
	PrometheusVersion                               string
	PrometheusPaused                                bool
	PrometheusReplicas                              int
	PrometheusReplicasDeclared                      bool
	PrometheusShards                                int
	PrometheusShardsDeclared                        bool
	PrometheusMode                                  string
	PrometheusAgentMode                             string
	PrometheusRemoteWriteCount                      int
	PrometheusPodSecurityMetadata                   bool
	PrometheusSecurityContextInvalidCount           int
	PrometheusRootUserContextCount                  int
	PrometheusNonRootDisabledContextCount           int
	PrometheusPrivilegedContainerCount              int
	PrometheusHostProcessContextCount               int
	PrometheusPrivilegeEscalationContextCount       int
	PrometheusUnconfinedSeccompContextCount         int
	PrometheusCapabilityAdditionContextCount        int
	PrometheusWritableRootFilesystemContextCount    int
	PrometheusResourceMetadata                      bool
	PrometheusResourcesDeclared                     bool
	PrometheusResourcesObjectValid                  bool
	PrometheusResourceInvalidSettingCount           int
	PrometheusCPURequestDeclared                    bool
	PrometheusCPURequestValid                       bool
	PrometheusCPURequestPositive                    bool
	PrometheusMemoryRequestDeclared                 bool
	PrometheusMemoryRequestValid                    bool
	PrometheusMemoryRequestPositive                 bool
	PrometheusCPULimitDeclared                      bool
	PrometheusCPULimitValid                         bool
	PrometheusCPULimitPositive                      bool
	PrometheusMemoryLimitDeclared                   bool
	PrometheusMemoryLimitValid                      bool
	PrometheusMemoryLimitPositive                   bool
	PrometheusStatefulSetMetadata                   bool
	PrometheusStatefulSetApplicable                 bool
	PrometheusPodManagementPolicyDeclared           bool
	PrometheusPodManagementPolicyValid              bool
	PrometheusPodManagementPolicy                   string
	PrometheusUpdateStrategyDeclared                bool
	PrometheusUpdateStrategyObjectValid             bool
	PrometheusUpdateStrategyTypeValid               bool
	PrometheusUpdateStrategyType                    string
	PrometheusRollingUpdateDeclared                 bool
	PrometheusRollingUpdateValid                    bool
	PrometheusMaxUnavailableDeclared                bool
	PrometheusMaxUnavailableValid                   bool
	PrometheusMaxUnavailable                        int64
	PrometheusMaxUnavailablePercent                 bool
	PrometheusUpdateStrategyInvalidSettingCount     int
	PrometheusDNSMetadata                           bool
	PrometheusHostNetworkDeclared                   bool
	PrometheusHostNetworkValid                      bool
	PrometheusHostNetworkEnabled                    bool
	PrometheusAutomountTokenDeclared                bool
	PrometheusAutomountTokenValid                   bool
	PrometheusAutomountTokenEnabled                 bool
	PrometheusDNSPolicyDeclared                     bool
	PrometheusDNSPolicyValid                        bool
	PrometheusDNSPolicy                             string
	PrometheusDNSConfigDeclared                     bool
	PrometheusDNSConfigObjectValid                  bool
	PrometheusDNSNameserverCount                    int
	PrometheusDNSInvalidSettingCount                int
	PrometheusServiceLinksDeclared                  bool
	PrometheusServiceLinksValid                     bool
	PrometheusServiceLinksEnabled                   bool
	PrometheusImageMetadata                         bool
	PrometheusImageDeclared                         bool
	PrometheusImageValid                            bool
	PrometheusImageDigestPinned                     bool
	PrometheusImageLatestTag                        bool
	PrometheusImagePullPolicyDeclared               bool
	PrometheusImagePullPolicyValid                  bool
	PrometheusImagePullPolicy                       string
	PrometheusLegacyImageFieldCount                 int
	PrometheusShadowedLegacyImageFieldCount         int
	PrometheusImagePullSecretsDeclared              bool
	PrometheusImagePullSecretCount                  int
	PrometheusImageInvalidSettingCount              int
	PrometheusPlacementMetadata                     bool
	PrometheusNodeSelectorDeclared                  bool
	PrometheusNodeSelectorValid                     bool
	PrometheusNodeSelectorCount                     int
	PrometheusSchedulerNameDeclared                 bool
	PrometheusSchedulerNameValid                    bool
	PrometheusCustomScheduler                       bool
	PrometheusPriorityClassNameDeclared             bool
	PrometheusPriorityClassNameValid                bool
	PrometheusTolerationsDeclared                   bool
	PrometheusTolerationCount                       int
	PrometheusTolerationInvalidSettingCount         int
	PrometheusBroadTolerationCount                  int
	PrometheusIndefiniteNoExecuteTolerationCount    int
	PrometheusPodReferenceMetadata                  bool
	PrometheusSecretsDeclared                       bool
	PrometheusSecretCount                           int
	PrometheusConfigMapsDeclared                    bool
	PrometheusConfigMapCount                        int
	PrometheusPodReferenceInvalidSettingCount       int
	PrometheusGeneratedVolumeCollisionCount         int
	PrometheusServiceAccountNameDeclared            bool
	PrometheusServiceAccountNameValid               bool
	PrometheusCustomServiceAccount                  bool
	PrometheusVolumeMetadata                        bool
	PrometheusVolumesDeclared                       bool
	PrometheusVolumeMountsDeclared                  bool
	PrometheusVolumeInvalidSettingCount             int
	PrometheusVolumeCount                           int
	PrometheusVolumeMountCount                      int
	PrometheusHostPathVolumeCount                   int
	PrometheusWritableHostPathMountCount            int
	PrometheusBidirectionalMountCount               int
	PrometheusPodCustomizationMetadata              bool
	PrometheusPodMetadataDeclared                   bool
	PrometheusPodMetadataObjectValid                bool
	PrometheusPodMetadataLabelCount                 int
	PrometheusPodMetadataAnnotationCount            int
	PrometheusReservedLabelOverrideCount            int
	PrometheusReservedAnnotationOverrideCount       int
	PrometheusHostAliasesDeclared                   bool
	PrometheusHostAliasCount                        int
	PrometheusHostAliasHostnameCount                int
	PrometheusLoopbackHostAliasCount                int
	PrometheusPodCustomizationInvalidSettingCount   int
	PrometheusRolloutMetadata                       bool
	PrometheusMinReadySecondsDeclared               bool
	PrometheusMinReadySecondsValid                  bool
	PrometheusMinReadySeconds                       int64
	PrometheusAffinityDeclared                      bool
	PrometheusAffinityValid                         bool
	PrometheusPodAntiAffinityDeclared               bool
	PrometheusPodAntiAffinityTermCount              int
	PrometheusTopologySpreadDeclared                bool
	PrometheusTopologySpreadCount                   int
	PrometheusSchedulingInvalidSettingCount         int
	PrometheusRuntimeMetadata                       bool
	PrometheusListenLocalDeclared                   bool
	PrometheusListenLocalValid                      bool
	PrometheusListenLocalEnabled                    bool
	PrometheusLogLevelDeclared                      bool
	PrometheusLogLevelValid                         bool
	PrometheusLogLevel                              string
	PrometheusLogFormatDeclared                     bool
	PrometheusLogFormatValid                        bool
	PrometheusLogFormat                             string
	PrometheusContainersDeclared                    bool
	PrometheusSidecarContainerCount                 int
	PrometheusContainerInvalidCount                 int
	PrometheusInitContainersDeclared                bool
	PrometheusInitContainerInvalidCount             int
	PrometheusManagedContainerOverrideCount         int
	PrometheusManagedInitContainerOverrideCount     int
	PrometheusArgumentMetadata                      bool
	PrometheusFeatureDeclared                       bool
	PrometheusFeatureCount                          int
	PrometheusFeatureInvalidCount                   int
	PrometheusFeatureDuplicateCount                 int
	PrometheusAdditionalArgsDeclared                bool
	PrometheusAdditionalArgCount                    int
	PrometheusAdditionalArgInvalidCount             int
	PrometheusAdditionalArgDuplicateCount           int
	PrometheusStorageDeclared                       bool
	PrometheusStorageMode                           string
	PrometheusStorageOptionCount                    int
	PrometheusPVCRequestDeclared                    bool
	PrometheusPVCRequestValid                       bool
	PrometheusPVCRequestBytes                       int64
	PrometheusPVCRetentionApplicable                bool
	PrometheusPVCRetentionPolicyDeclared            bool
	PrometheusPVCRetentionPolicyObjectValid         bool
	PrometheusPVCWhenDeletedValid                   bool
	PrometheusPVCWhenDeleted                        string
	PrometheusPVCWhenScaledValid                    bool
	PrometheusPVCWhenScaled                         string
	PrometheusPVCRetentionInvalidSettingCount       int
	PrometheusTerminationGraceDeclared              bool
	PrometheusTerminationGraceValid                 bool
	PrometheusTerminationGraceSeconds               int64
	PrometheusRetentionDeclared                     bool
	PrometheusRetentionValid                        bool
	PrometheusRetentionSeconds                      int64
	PrometheusRetentionSizeDeclared                 bool
	PrometheusRetentionSizeValid                    bool
	PrometheusRetentionSizeBytes                    int64
	PrometheusWALCompressionDeclared                bool
	PrometheusWALCompressionEnabled                 bool
	PrometheusDisableCompaction                     bool
	PrometheusThanosObjectStorage                   bool
	AlertmanagerStorageDeclared                     bool
	AlertmanagerStorageMode                         string
	AlertmanagerStorageOptionCount                  int
	AlertmanagerPVCRequestDeclared                  bool
	AlertmanagerPVCRequestValid                     bool
	AlertmanagerPVCRequestBytes                     int64
	AlertmanagerRetentionDeclared                   bool
	AlertmanagerRetentionValid                      bool
	AlertmanagerRetentionMilliseconds               int64
	AlertmanagerPVCRetentionPolicyDeclared          bool
	AlertmanagerPVCRetentionPolicyObjectValid       bool
	AlertmanagerPVCWhenDeletedValid                 bool
	AlertmanagerPVCWhenDeleted                      string
	AlertmanagerPVCWhenScaledValid                  bool
	AlertmanagerPVCWhenScaled                       string
	AlertmanagerPVCRetentionInvalidSettingCount     int
	AlertmanagerTerminationGraceDeclared            bool
	AlertmanagerTerminationGraceValid               bool
	AlertmanagerTerminationGraceSeconds             int64
	AlertmanagerTerminationGraceVersionEvaluable    bool
	AlertmanagerTerminationGraceVersionUnsupported  bool
	AlertmanagerLimitsDeclared                      bool
	AlertmanagerLimitsObjectValid                   bool
	AlertmanagerLimitsInvalidSettingCount           int
	AlertmanagerMaxSilencesDeclared                 bool
	AlertmanagerMaxSilencesValid                    bool
	AlertmanagerMaxSilences                         int64
	AlertmanagerMaxPerSilenceBytesDeclared          bool
	AlertmanagerMaxPerSilenceBytesValid             bool
	AlertmanagerMaxPerSilenceBytes                  int64
	AlertmanagerLimitsVersionEvaluable              bool
	AlertmanagerLimitsVersionUnsupported            bool
	AlertmanagerSecurityMetadata                    bool
	AlertmanagerHostNetworkDeclared                 bool
	AlertmanagerHostNetworkValid                    bool
	AlertmanagerHostNetworkEnabled                  bool
	AlertmanagerAutomountTokenDeclared              bool
	AlertmanagerAutomountTokenValid                 bool
	AlertmanagerAutomountTokenEnabled               bool
	AlertmanagerClusterTLSDeclared                  bool
	AlertmanagerClusterTLSComplete                  bool
	AlertmanagerClusterTLSInvalidSettingCount       int
	AlertmanagerClusterTLSVersionEvaluable          bool
	AlertmanagerClusterTLSVersionUnsupported        bool
	AlertmanagerArgumentMetadata                    bool
	AlertmanagerFeatureDeclared                     bool
	AlertmanagerFeatureCount                        int
	AlertmanagerFeatureInvalidCount                 int
	AlertmanagerFeatureDuplicateCount               int
	AlertmanagerFeatureVersionEvaluable             bool
	AlertmanagerFeatureVersionUnsupported           bool
	AlertmanagerAdditionalArgsDeclared              bool
	AlertmanagerAdditionalArgCount                  int
	AlertmanagerAdditionalArgInvalidCount           int
	AlertmanagerAdditionalArgDuplicateCount         int
	AlertmanagerAdditionalArgsVersionEvaluable      bool
	AlertmanagerAdditionalArgsVersionUnsupported    bool
	AlertmanagerWebMetadata                         bool
	AlertmanagerWebDeclared                         bool
	AlertmanagerWebObjectValid                      bool
	AlertmanagerWebInvalidSettingCount              int
	AlertmanagerWebGetConcurrencyDeclared           bool
	AlertmanagerWebGetConcurrencyValid              bool
	AlertmanagerWebGetConcurrency                   uint64
	AlertmanagerWebTimeoutDeclared                  bool
	AlertmanagerWebTimeoutValid                     bool
	AlertmanagerWebTimeoutSeconds                   uint64
	AlertmanagerWebTLSDeclared                      bool
	AlertmanagerWebHTTPConfigDeclared               bool
	AlertmanagerExternalURLDeclared                 bool
	AlertmanagerExternalURLValid                    bool
	AlertmanagerExternalURLScheme                   string
	AlertmanagerClusterMetadata                     bool
	AlertmanagerAdditionalPeersDeclared             bool
	AlertmanagerAdditionalPeerCount                 int
	AlertmanagerAdditionalPeerInvalidCount          int
	AlertmanagerAdditionalPeerDuplicateCount        int
	AlertmanagerClusterTimingDeclaredCount          int
	AlertmanagerClusterTimingInvalidCount           int
	AlertmanagerForceClusterModeDeclared            bool
	AlertmanagerForceClusterModeValid               bool
	AlertmanagerForceClusterModeEnabled             bool
	AlertmanagerClusterLabelDeclared                bool
	AlertmanagerClusterLabelValid                   bool
	AlertmanagerClusterLabelInvalid                 bool
	AlertmanagerClusterAdvertiseAddressDeclared     bool
	AlertmanagerClusterAdvertiseAddressValid        bool
	AlertmanagerClusterAdvertiseAddressLoopback     bool
	AlertmanagerClusterAdvertiseAddressUnspecified  bool
	AlertmanagerRolloutMetadata                     bool
	AlertmanagerMinReadySecondsDeclared             bool
	AlertmanagerMinReadySecondsValid                bool
	AlertmanagerMinReadySeconds                     int64
	AlertmanagerDispatchDelayVersionEvaluable       bool
	AlertmanagerDispatchDelaySupported              bool
	AlertmanagerAffinityDeclared                    bool
	AlertmanagerAffinityValid                       bool
	AlertmanagerPodAntiAffinityDeclared             bool
	AlertmanagerPodAntiAffinityTermCount            int
	AlertmanagerSchedulingInvalidSettingCount       int
	AlertmanagerTopologySpreadDeclared              bool
	AlertmanagerTopologySpreadCount                 int
	AlertmanagerRuntimeMetadata                     bool
	AlertmanagerListenLocalDeclared                 bool
	AlertmanagerListenLocalValid                    bool
	AlertmanagerListenLocalEnabled                  bool
	AlertmanagerLogLevelDeclared                    bool
	AlertmanagerLogLevelValid                       bool
	AlertmanagerLogLevel                            string
	AlertmanagerLogFormatDeclared                   bool
	AlertmanagerLogFormatValid                      bool
	AlertmanagerLogFormat                           string
	AlertmanagerContainersDeclared                  bool
	AlertmanagerSidecarContainerCount               int
	AlertmanagerContainerInvalidCount               int
	AlertmanagerInitContainersDeclared              bool
	AlertmanagerInitContainerInvalidCount           int
	AlertmanagerManagedContainerOverrideCount       int
	AlertmanagerManagedInitContainerOverrideCount   int
	AlertmanagerConfigSourceMetadata                bool
	AlertmanagerConfigSecretDeclared                bool
	AlertmanagerConfigSecretConfigured              bool
	AlertmanagerConfigSecretValid                   bool
	AlertmanagerConfigurationDeclared               bool
	AlertmanagerConfigurationValid                  bool
	AlertmanagerConfigurationFound                  bool
	AlertmanagerConfigSourceConflict                bool
	AlertmanagerServiceNameDeclared                 bool
	AlertmanagerServiceNameConfigured               bool
	AlertmanagerServiceNameValid                    bool
	AlertmanagerServiceName                         string
	AlertmanagerPortNameDeclared                    bool
	AlertmanagerPortNameConfigured                  bool
	AlertmanagerPortNameValid                       bool
	AlertmanagerSharedServiceCount                  int
	AlertmanagerPodSecurityMetadata                 bool
	AlertmanagerSecurityContextInvalidCount         int
	AlertmanagerRootUserContextCount                int
	AlertmanagerNonRootDisabledContextCount         int
	AlertmanagerPrivilegedContainerCount            int
	AlertmanagerHostProcessContextCount             int
	AlertmanagerPrivilegeEscalationContextCount     int
	AlertmanagerUnconfinedSeccompContextCount       int
	AlertmanagerCapabilityAdditionContextCount      int
	AlertmanagerWritableRootFilesystemContextCount  int
	AlertmanagerResourceMetadata                    bool
	AlertmanagerResourcesDeclared                   bool
	AlertmanagerResourcesObjectValid                bool
	AlertmanagerResourceInvalidSettingCount         int
	AlertmanagerCPURequestDeclared                  bool
	AlertmanagerCPURequestValid                     bool
	AlertmanagerCPURequestPositive                  bool
	AlertmanagerMemoryRequestDeclared               bool
	AlertmanagerMemoryRequestValid                  bool
	AlertmanagerMemoryRequestPositive               bool
	AlertmanagerCPULimitDeclared                    bool
	AlertmanagerCPULimitValid                       bool
	AlertmanagerCPULimitPositive                    bool
	AlertmanagerMemoryLimitDeclared                 bool
	AlertmanagerMemoryLimitValid                    bool
	AlertmanagerMemoryLimitPositive                 bool
	AlertmanagerStatefulSetMetadata                 bool
	AlertmanagerPodManagementPolicyDeclared         bool
	AlertmanagerPodManagementPolicyValid            bool
	AlertmanagerPodManagementPolicy                 string
	AlertmanagerUpdateStrategyDeclared              bool
	AlertmanagerUpdateStrategyObjectValid           bool
	AlertmanagerUpdateStrategyTypeValid             bool
	AlertmanagerUpdateStrategyType                  string
	AlertmanagerRollingUpdateDeclared               bool
	AlertmanagerRollingUpdateValid                  bool
	AlertmanagerMaxUnavailableDeclared              bool
	AlertmanagerMaxUnavailableValid                 bool
	AlertmanagerMaxUnavailable                      int64
	AlertmanagerMaxUnavailablePercent               bool
	AlertmanagerUpdateStrategyInvalidSettingCount   int
	AlertmanagerDNSMetadata                         bool
	AlertmanagerDNSPolicyDeclared                   bool
	AlertmanagerDNSPolicyValid                      bool
	AlertmanagerDNSPolicy                           string
	AlertmanagerDNSConfigDeclared                   bool
	AlertmanagerDNSConfigObjectValid                bool
	AlertmanagerDNSNameserverCount                  int
	AlertmanagerDNSInvalidSettingCount              int
	AlertmanagerServiceLinksDeclared                bool
	AlertmanagerServiceLinksValid                   bool
	AlertmanagerServiceLinksEnabled                 bool
	AlertmanagerImageMetadata                       bool
	AlertmanagerImageDeclared                       bool
	AlertmanagerImageValid                          bool
	AlertmanagerImageDigestPinned                   bool
	AlertmanagerImageLatestTag                      bool
	AlertmanagerImagePullPolicyDeclared             bool
	AlertmanagerImagePullPolicyValid                bool
	AlertmanagerImagePullPolicy                     string
	AlertmanagerLegacyImageFieldCount               int
	AlertmanagerShadowedLegacyImageFieldCount       int
	AlertmanagerImagePullSecretsDeclared            bool
	AlertmanagerImagePullSecretCount                int
	AlertmanagerImageInvalidSettingCount            int
	AlertmanagerVolumeMetadata                      bool
	AlertmanagerVolumesDeclared                     bool
	AlertmanagerVolumeMountsDeclared                bool
	AlertmanagerVolumeInvalidSettingCount           int
	AlertmanagerVolumeCount                         int
	AlertmanagerVolumeMountCount                    int
	AlertmanagerHostPathVolumeCount                 int
	AlertmanagerWritableHostPathMountCount          int
	AlertmanagerBidirectionalMountCount             int
	AlertmanagerPlacementMetadata                   bool
	AlertmanagerNodeSelectorDeclared                bool
	AlertmanagerNodeSelectorValid                   bool
	AlertmanagerNodeSelectorCount                   int
	AlertmanagerSchedulerNameDeclared               bool
	AlertmanagerSchedulerNameValid                  bool
	AlertmanagerCustomScheduler                     bool
	AlertmanagerPriorityClassNameDeclared           bool
	AlertmanagerPriorityClassNameValid              bool
	AlertmanagerTolerationsDeclared                 bool
	AlertmanagerTolerationCount                     int
	AlertmanagerTolerationInvalidSettingCount       int
	AlertmanagerBroadTolerationCount                int
	AlertmanagerIndefiniteNoExecuteTolerationCount  int
	AlertmanagerPodReferenceMetadata                bool
	AlertmanagerSecretsDeclared                     bool
	AlertmanagerSecretCount                         int
	AlertmanagerConfigMapsDeclared                  bool
	AlertmanagerConfigMapCount                      int
	AlertmanagerPodReferenceInvalidSettingCount     int
	AlertmanagerGeneratedVolumeCollisionCount       int
	AlertmanagerServiceAccountNameDeclared          bool
	AlertmanagerServiceAccountNameValid             bool
	AlertmanagerCustomServiceAccount                bool
	AlertmanagerPodCustomizationMetadata            bool
	AlertmanagerPodMetadataDeclared                 bool
	AlertmanagerPodMetadataObjectValid              bool
	AlertmanagerPodMetadataLabelCount               int
	AlertmanagerPodMetadataAnnotationCount          int
	AlertmanagerReservedLabelOverrideCount          int
	AlertmanagerReservedAnnotationOverrideCount     int
	AlertmanagerHostAliasesDeclared                 bool
	AlertmanagerHostAliasCount                      int
	AlertmanagerHostAliasHostnameCount              int
	AlertmanagerLoopbackHostAliasCount              int
	AlertmanagerPodCustomizationInvalidSettingCount int
	PrometheusQueryDeclared                         bool
	PrometheusQueryObjectValid                      bool
	PrometheusQueryMaxConcurrency                   int
	PrometheusQueryMaxConcDeclared                  bool
	PrometheusQueryMaxConcValid                     bool
	PrometheusQueryMaxSamples                       int
	PrometheusQueryMaxSamplesDeclared               bool
	PrometheusQueryMaxSamplesValid                  bool
	PrometheusQueryTimeoutSeconds                   int64
	PrometheusQueryTimeoutDeclared                  bool
	PrometheusQueryTimeoutValid                     bool
	PrometheusQueryLookbackSeconds                  int64
	PrometheusQueryLookbackDeclared                 bool
	PrometheusQueryLookbackValid                    bool
	PrometheusScrapeIntervalSeconds                 int64
	PrometheusScrapeIntervalDeclared                bool
	PrometheusScrapeIntervalValid                   bool
	PrometheusScrapeTimeoutSeconds                  int64
	PrometheusScrapeTimeoutDeclared                 bool
	PrometheusScrapeTimeoutValid                    bool
	PrometheusScrapeTimingInvalid                   int
	PrometheusScrapeTimingConflict                  bool
	PrometheusArbitraryFSAccessDenied               bool
	PrometheusOverrideHonorLabels                   bool
	PrometheusOverrideHonorTimestamps               bool
	PrometheusIgnoreNamespaceSelectors              bool
	PrometheusEnforcedNamespaceLabel                string
	PrometheusNamespaceLabelExclusions              []kubernetesObjectReference
	PrometheusAdditionalScrapeDeclared              bool
	PrometheusReplicaExternalDeclared               bool
	PrometheusReplicaExternalEnabled                bool
	PrometheusInstanceExternalDeclared              bool
	PrometheusInstanceExternalEnabled               bool
	PrometheusExternalLabelCount                    int
	PrometheusAdminAPIEnabled                       bool
	PrometheusRemoteWriteReceiver                   bool
	PrometheusOTLPReceiver                          bool
	PrometheusOTLPConfigDeclared                    bool
	PrometheusReceiverVersionEvaluable              bool
	PrometheusRemoteReceiverUnsupported             bool
	PrometheusOTLPReceiverUnsupported               bool
	PrometheusWebDeclared                           bool
	PrometheusWebInvalidSettingCount                int
	PrometheusWebMaxConnectionsDeclared             bool
	PrometheusWebMaxConnectionsValid                bool
	PrometheusWebMaxConnections                     int64
	PrometheusExternalURLDeclared                   bool
	PrometheusExternalURLValid                      bool
	PrometheusExternalURLScheme                     string
	ThanosRulerQueryEndpointCount                   int
	ThanosRulerQueryConfigDeclared                  bool
	ThanosRulerRuntimeMetadata                      bool
	ThanosRulerListenLocalDeclared                  bool
	ThanosRulerListenLocalValid                     bool
	ThanosRulerListenLocalEnabled                   bool
	ThanosRulerLogLevelDeclared                     bool
	ThanosRulerLogLevelValid                        bool
	ThanosRulerLogLevel                             string
	ThanosRulerLogFormatDeclared                    bool
	ThanosRulerLogFormatValid                       bool
	ThanosRulerLogFormat                            string
	ThanosRulerContainersDeclared                   bool
	ThanosRulerSidecarContainerCount                int
	ThanosRulerContainerInvalidCount                int
	ThanosRulerInitContainersDeclared               bool
	ThanosRulerInitContainerInvalidCount            int
	ThanosRulerManagedContainerOverrideCount        int
	ThanosRulerManagedInitContainerOverrideCount    int
	ThanosRulerResourceMetadata                     bool
	ThanosRulerResourcesDeclared                    bool
	ThanosRulerResourcesObjectValid                 bool
	ThanosRulerResourceInvalidSettingCount          int
	ThanosRulerCPURequestDeclared                   bool
	ThanosRulerCPURequestValid                      bool
	ThanosRulerCPURequestPositive                   bool
	ThanosRulerMemoryRequestDeclared                bool
	ThanosRulerMemoryRequestValid                   bool
	ThanosRulerMemoryRequestPositive                bool
	ThanosRulerCPULimitDeclared                     bool
	ThanosRulerCPULimitValid                        bool
	ThanosRulerCPULimitPositive                     bool
	ThanosRulerMemoryLimitDeclared                  bool
	ThanosRulerMemoryLimitValid                     bool
	ThanosRulerMemoryLimitPositive                  bool
	ThanosRulerPodSecurityMetadata                  bool
	ThanosRulerSecurityContextInvalidCount          int
	ThanosRulerRootUserContextCount                 int
	ThanosRulerNonRootDisabledContextCount          int
	ThanosRulerPrivilegedContainerCount             int
	ThanosRulerHostProcessContextCount              int
	ThanosRulerPrivilegeEscalationContextCount      int
	ThanosRulerUnconfinedSeccompContextCount        int
	ThanosRulerCapabilityAdditionContextCount       int
	ThanosRulerWritableRootFilesystemContextCount   int
	ThanosRulerStorageMetadata                      bool
	ThanosRulerStorageDeclared                      bool
	ThanosRulerStorageObjectValid                   bool
	ThanosRulerStorageMode                          string
	ThanosRulerStorageOptionCount                   int
	ThanosRulerStorageInvalidSettingCount           int
	ThanosRulerPVCRequestDeclared                   bool
	ThanosRulerPVCRequestValid                      bool
	ThanosRulerPVCRequestBytes                      int64
	ThanosRulerRetentionDeclared                    bool
	ThanosRulerRetentionValid                       bool
	ThanosRulerRetentionSeconds                     int64
	ThanosRulerStatelessMode                        bool
	ThanosRulerTerminationGraceDeclared             bool
	ThanosRulerTerminationGraceValid                bool
	ThanosRulerTerminationGraceSeconds              int64
	ThanosRulerStatefulSetMetadata                  bool
	ThanosRulerPodManagementPolicyDeclared          bool
	ThanosRulerPodManagementPolicyValid             bool
	ThanosRulerPodManagementPolicy                  string
	ThanosRulerUpdateStrategyDeclared               bool
	ThanosRulerUpdateStrategyObjectValid            bool
	ThanosRulerUpdateStrategyTypeValid              bool
	ThanosRulerUpdateStrategyType                   string
	ThanosRulerRollingUpdateDeclared                bool
	ThanosRulerRollingUpdateValid                   bool
	ThanosRulerMaxUnavailableDeclared               bool
	ThanosRulerMaxUnavailableValid                  bool
	ThanosRulerMaxUnavailable                       int64
	ThanosRulerMaxUnavailablePercent                bool
	ThanosRulerUpdateStrategyInvalidSettingCount    int
	ThanosRulerDNSMetadata                          bool
	ThanosRulerDNSPolicyDeclared                    bool
	ThanosRulerDNSPolicyValid                       bool
	ThanosRulerDNSPolicy                            string
	ThanosRulerDNSConfigDeclared                    bool
	ThanosRulerDNSConfigObjectValid                 bool
	ThanosRulerDNSNameserverCount                   int
	ThanosRulerDNSInvalidSettingCount               int
	ThanosRulerServiceLinksDeclared                 bool
	ThanosRulerServiceLinksValid                    bool
	ThanosRulerServiceLinksEnabled                  bool
	ThanosRulerHostNetworkUnsupported               bool
	ThanosRulerImageMetadata                        bool
	ThanosRulerImageDeclared                        bool
	ThanosRulerImageValid                           bool
	ThanosRulerImageDigestPinned                    bool
	ThanosRulerImageLatestTag                       bool
	ThanosRulerImagePullPolicyDeclared              bool
	ThanosRulerImagePullPolicyValid                 bool
	ThanosRulerImagePullPolicy                      string
	ThanosRulerImagePullSecretsDeclared             bool
	ThanosRulerImagePullSecretCount                 int
	ThanosRulerUnsupportedLegacyImageFieldCount     int
	ThanosRulerImageInvalidSettingCount             int
	ThanosRulerPlacementMetadata                    bool
	ThanosRulerNodeSelectorDeclared                 bool
	ThanosRulerNodeSelectorValid                    bool
	ThanosRulerNodeSelectorCount                    int
	ThanosRulerSchedulerNameDeclared                bool
	ThanosRulerSchedulerNameValid                   bool
	ThanosRulerCustomScheduler                      bool
	ThanosRulerPriorityClassNameDeclared            bool
	ThanosRulerPriorityClassNameValid               bool
	ThanosRulerTolerationsDeclared                  bool
	ThanosRulerTolerationCount                      int
	ThanosRulerTolerationInvalidSettingCount        int
	ThanosRulerBroadTolerationCount                 int
	ThanosRulerIndefiniteNoExecuteTolerationCount   int
	ThanosRulerVolumeMetadata                       bool
	ThanosRulerVolumesDeclared                      bool
	ThanosRulerVolumeMountsDeclared                 bool
	ThanosRulerVolumeInvalidSettingCount            int
	ThanosRulerVolumeCount                          int
	ThanosRulerVolumeMountCount                     int
	ThanosRulerHostPathVolumeCount                  int
	ThanosRulerWritableHostPathMountCount           int
	ThanosRulerBidirectionalMountCount              int
	ThanosRulerPodCustomizationMetadata             bool
	ThanosRulerPodMetadataDeclared                  bool
	ThanosRulerPodMetadataObjectValid               bool
	ThanosRulerPodMetadataLabelCount                int
	ThanosRulerPodMetadataAnnotationCount           int
	ThanosRulerReservedLabelOverrideCount           int
	ThanosRulerReservedAnnotationOverrideCount      int
	ThanosRulerHostAliasesDeclared                  bool
	ThanosRulerHostAliasCount                       int
	ThanosRulerHostAliasHostnameCount               int
	ThanosRulerLoopbackHostAliasCount               int
	ThanosRulerPodCustomizationInvalidSettingCount  int
	ThanosRulerWorkloadIdentityMetadata             bool
	ThanosRulerServiceNameDeclared                  bool
	ThanosRulerServiceNameValid                     bool
	ThanosRulerServiceNameConfigured                bool
	ThanosRulerServiceName                          string
	ThanosRulerSharedServiceCount                   int
	ThanosRulerServiceAccountNameDeclared           bool
	ThanosRulerServiceAccountNameValid              bool
	ThanosRulerCustomServiceAccount                 bool
	ThanosRulerRolloutMetadata                      bool
	ThanosRulerMinReadySeconds                      int64
	ThanosRulerMinReadySecondsDeclared              bool
	ThanosRulerMinReadySecondsValid                 bool
	ThanosRulerAffinityDeclared                     bool
	ThanosRulerAffinityValid                        bool
	ThanosRulerPodAntiAffinityDeclared              bool
	ThanosRulerPodAntiAffinityTermCount             int
	ThanosRulerTopologySpreadDeclared               bool
	ThanosRulerTopologySpreadCount                  int
	ThanosRulerSchedulingInvalidSettingCount        int
	ThanosRulerArgumentMetadata                     bool
	ThanosRulerAdditionalArgsDeclared               bool
	ThanosRulerAdditionalArgCount                   int
	ThanosRulerAdditionalArgInvalidCount            int
	ThanosRulerAdditionalArgDuplicateCount          int
	ThanosRulerFeatureDeclared                      bool
	ThanosRulerFeatureCount                         int
	ThanosRulerFeatureInvalidCount                  int
	ThanosRulerFeatureDuplicateCount                int
	ThanosRulerFeatureVersionEvaluable              bool
	ThanosRulerFeatureVersionUnsupported            bool
	ThanosRulerWebMetadata                          bool
	ThanosRulerWebDeclared                          bool
	ThanosRulerWebObjectValid                       bool
	ThanosRulerWebInvalidSettingCount               int
	ThanosRulerWebTLSDeclared                       bool
	ThanosRulerWebTLSComplete                       bool
	ThanosRulerWebHTTPConfigDeclared                bool
	ThanosRulerWebHTTP2Declared                     bool
	ThanosRulerWebHTTP2Valid                        bool
	ThanosRulerWebHTTP2Enabled                      bool
	ThanosRulerGRPCTLSMetadata                      bool
	ThanosRulerGRPCTLSDeclared                      bool
	ThanosRulerGRPCTLSComplete                      bool
	ThanosRulerGRPCTLSInvalidSettingCount           int
	ThanosRulerGRPCTLSUnsupportedSettingCount       int
	ThanosRulerSecretConfigMetadata                 bool
	ThanosRulerSecretSelectorDeclaredCount          int
	ThanosRulerSecretConfigInvalidSettingCount      int
	ThanosRulerShadowedSecretConfigCount            int
	ThanosRulerFileConfigDeclaredCount              int
	ThanosRulerEvaluationMetadata                   bool
	ThanosRulerEvaluationInterval                   kubernetesDurationSetting
	ThanosRulerResendDelay                          kubernetesDurationSetting
	ThanosRulerRuleOutageTolerance                  kubernetesDurationSetting
	ThanosRulerRuleQueryOffset                      kubernetesDurationSetting
	ThanosRulerRuleGracePeriod                      kubernetesDurationSetting
	ThanosRulerRuleConcurrentEvalDeclared           bool
	ThanosRulerRuleConcurrentEvalValid              bool
	ThanosRulerRuleConcurrentEval                   int64
	ThanosRulerEvaluationInvalidSettingCount        int
	ThanosRulerEvaluationVersionEvaluable           bool
	ThanosRulerEvaluationUnsupportedSettingCount    int
	ThanosRulerRestorationTimingInconsistent        bool
	ThanosRulerPresentationMetadata                 bool
	ThanosRulerPortNameDeclared                     bool
	ThanosRulerPortNameValid                        bool
	ThanosRulerExternalPrefixDeclared               bool
	ThanosRulerExternalPrefixValid                  bool
	ThanosRulerRoutePrefixDeclared                  bool
	ThanosRulerRoutePrefixValid                     bool
	ThanosRulerAlertQueryURLDeclared                bool
	ThanosRulerAlertQueryURLValid                   bool
	ThanosRulerAlertQueryURLScheme                  string
	ThanosRulerAlertQueryURLLoopback                bool
	ThanosRulerExternalLabelsDeclared               bool
	ThanosRulerExternalLabelCount                   int
	ThanosRulerExternalLabelInvalidCount            int
	ThanosRulerReplicaLabelOverride                 bool
	ThanosRulerAlertDropLabelsDeclared              bool
	ThanosRulerAlertDropLabelCount                  int
	ThanosRulerAlertDropLabelInvalidCount           int
	ThanosRulerAlertDropLabelDuplicateCount         int
	ThanosRulerDroppedExternalLabelCount            int
	ThanosRulerHostUsersDeclared                    bool
	ThanosRulerHostUsersValid                       bool
	ThanosRulerUserNamespaceIsolationEnabled        bool
	ThanosRulerPresentationInvalidSettingCount      int
	ThanosRulerAlertmanagerDeliveryMetadata         bool
	ThanosRulerAlertmanagerURLDeclared              bool
	ThanosRulerAlertmanagerURLCount                 int
	ThanosRulerAlertmanagerURLInvalidCount          int
	ThanosRulerAlertmanagerURLDuplicateCount        int
	ThanosRulerPlaintextAlertmanagerURLCount        int
	ThanosRulerAlertmanagerConfigDeclared           bool
	ThanosRulerAlertmanagerConfigValid              bool
	ThanosRulerAlertmanagerDeliveryConfigured       bool
	ThanosRulerAlertmanagerConfigVersionEvaluable   bool
	ThanosRulerAlertmanagerConfigVersionUnsupported bool
	AlertmanagerVersion                             string
	AlertmanagerPaused                              bool
	AlertmanagerReplicas                            int
	AlertmanagerReplicasDeclared                    bool
	AlertmanagerConfigurationName                   string
	AlertmanagerConfigYAML                          string
	ScrapeClassName                                 string
	ScrapeClasses                                   []kubernetesScrapeClass
	RemoteWrites                                    []kubernetesRemoteWrite
	RemoteReads                                     []kubernetesRemoteRead
	RemoteWriteSelection                            kubernetesPrometheusSelection
	PrometheusSelections                            map[string]kubernetesPrometheusSelection
	PrometheusEnforcedLimits                        kubernetesIngestionLimits
	MonitorIngestionLimits                          kubernetesIngestionLimits
	MonitorScrapeTiming                             kubernetesMonitorScrapeTiming
	MonitorArbitraryFileReferenceCount              int
	MonitorHonorLabelsCount                         int
	MonitorExplicitHonorTimestampsCount             int
}

type kubernetesDurationSetting struct {
	Declared bool
	Valid    bool
	Seconds  int64
}

type kubernetesMonitorScrapeTiming struct {
	InvalidSettingCount          int
	TimeoutExceedsIntervalCount  int
	TimeoutWithoutIntervalValues []int64
}

type kubernetesIngestionLimit struct {
	Declared bool
	Valid    bool
	Value    int64
}

type kubernetesIngestionLimits struct {
	Sample           kubernetesIngestionLimit
	Target           kubernetesIngestionLimit
	Label            kubernetesIngestionLimit
	LabelNameLength  kubernetesIngestionLimit
	LabelValueLength kubernetesIngestionLimit
	Body             kubernetesIngestionLimit
	KeepDropped      kubernetesIngestionLimit
}

type kubernetesLabelExpression struct {
	Key      string
	Operator string
	Values   []string
}

type kubernetesLabelSelector struct {
	Declared         bool
	MatchLabels      map[string]string
	MatchExpressions []kubernetesLabelExpression
}

type kubernetesPrometheusSelection struct {
	ResourceSelector  kubernetesLabelSelector
	NamespaceSelector kubernetesLabelSelector
}

type kubernetesObjectReference struct {
	Group     string
	Resource  string
	Namespace string
	Name      string
}

type kubernetesScrapeClass struct {
	Name                   string
	Default                bool
	DefaultDefinitionCount int
	DefinitionCount        int
	OptionCount            int
	TLSConfigDeclared      bool
	TLSInsecureSkipVerify  bool
	AuthorizationDeclared  bool
	BasicAuthDeclared      bool
	OAuth2Declared         bool
	RelabelingCount        int
	MetricRelabelingCount  int
}

type kubernetesRemoteWrite struct {
	Name                    string
	Index                   int
	DestinationDeclared     bool
	URLScheme               string
	URLValid                bool
	MessageVersion          string
	SendExemplars           bool
	SendNativeHistograms    bool
	TLSConfigDeclared       bool
	TLSInsecureSkipVerify   bool
	AuthorizationDeclared   bool
	BasicAuthDeclared       bool
	OAuth2Declared          bool
	SigV4Declared           bool
	AzureADDeclared         bool
	BearerTokenDeclared     bool
	BearerTokenFileDeclared bool
	AuthMethodCount         int
	HeaderCount             int
	WriteRelabelingCount    int
	ProxyDeclared           bool
	QueueConfigDeclared     bool
	QueueCapacityDeclared   bool
	QueueCapacityValid      bool
	QueueCapacity           int
	QueueMinShardsDeclared  bool
	QueueMinShardsValid     bool
	QueueMinShards          int
	QueueMaxShardsDeclared  bool
	QueueMaxShardsValid     bool
	QueueMaxShards          int
	QueueMaxSamplesDeclared bool
	QueueMaxSamplesValid    bool
	QueueMaxSamplesPerSend  int
	MetadataConfigDeclared  bool
}

type kubernetesRemoteRead struct {
	Name                    string
	Index                   int
	DestinationDeclared     bool
	URLScheme               string
	URLValid                bool
	RequiredMatcherCount    int
	RemoteTimeout           string
	HeaderCount             int
	ReadRecent              bool
	ReadRecentDeclared      bool
	FilterExternalLabels    bool
	FilterExternalDeclared  bool
	TLSConfigDeclared       bool
	TLSInsecureSkipVerify   bool
	AuthorizationDeclared   bool
	BasicAuthDeclared       bool
	OAuth2Declared          bool
	BearerTokenDeclared     bool
	BearerTokenFileDeclared bool
	AuthMethodCount         int
	ProxyDeclared           bool
}

type kubernetesPrometheusResource struct {
	Resource model.Resource
	Object   kubernetesObject
}

type kubernetesAlertmanagerConfigResource struct {
	Resource model.Resource
	Object   kubernetesObject
}

type kubernetesRemoteWriteResource struct {
	Resource model.Resource
	Object   kubernetesObject
}

type kubernetesPrometheusRule struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name      string         `yaml:"name"`
		Namespace string         `yaml:"namespace"`
		Labels    map[string]any `yaml:"labels"`
	} `yaml:"metadata"`
	Spec struct {
		Groups []struct {
			Name     string `yaml:"name"`
			Interval string `yaml:"interval"`
			Rules    []struct {
				Alert       string         `yaml:"alert"`
				Record      string         `yaml:"record"`
				Expression  string         `yaml:"expr"`
				For         string         `yaml:"for"`
				Labels      map[string]any `yaml:"labels"`
				Annotations map[string]any `yaml:"annotations"`
			} `yaml:"rules"`
		} `yaml:"groups"`
	} `yaml:"spec"`
}

func kubernetesSnapshotFromManifest(content string, instance string, now time.Time) (Snapshot, error) {
	nodes, err := decodeKubernetesManifestNodes(content)
	if err != nil {
		return Snapshot{}, err
	}
	objects := parseKubernetesManifestObjects(nodes)
	prometheusRules := parseKubernetesPrometheusRules(nodes)
	resourcesByID := map[string]model.Resource{}
	relationshipsByID := map[string]model.Relationship{}
	services := make([]model.Resource, 0)
	pods := make([]model.Resource, 0)
	serviceMonitors := make([]model.Resource, 0)
	podMonitors := make([]model.Resource, 0)
	monitorSelectors := map[string]map[string]string{}
	prometheuses := make([]kubernetesPrometheusResource, 0)
	thanosRulers := make([]kubernetesPrometheusResource, 0)
	alertmanagers := make([]kubernetesPrometheusResource, 0)
	alertmanagerConfigs := make([]kubernetesAlertmanagerConfigResource, 0)
	remoteWriteResources := make([]kubernetesRemoteWriteResource, 0)
	namespaceLabels := map[string]map[string]string{}
	objectLabels := map[string]map[string]string{}
	for _, object := range objects {
		if object.Kind == "Namespace" {
			namespaceLabels[object.Name] = cloneLabels(object.Labels)
			continue
		}
		if isKubernetesPrometheusSelectableKind(object.Kind) || object.Kind == "AlertmanagerConfig" || object.Kind == "RemoteWrite" {
			object.Namespace = kubernetesNamespace(object)
			objectLabels[kubernetesSelectionObjectKey(object.Kind, kubernetesObjectName(object))] = cloneLabels(object.Labels)
		}
	}

	for _, object := range objects {
		if object.Name == "" || object.Kind == "" {
			continue
		}
		switch object.Kind {
		case "Service":
			object.Namespace = kubernetesNamespace(object)
			resource := kubernetesResource(model.ResourceTypeService, kubernetesObjectName(object), instance, object, now)
			resource.Labels = cloneLabels(object.Labels)
			resource.Metadata["selector"] = labelSetString(object.Selector)
			resourcesByID[resource.ID] = resource
			services = append(services, resource)
		case "Pod":
			object.Namespace = kubernetesNamespace(object)
			resource := kubernetesResource(model.ResourceTypeInstance, kubernetesObjectName(object), instance, object, now)
			resource.Labels = cloneLabels(object.Labels)
			resourcesByID[resource.ID] = resource
			pods = append(pods, resource)
		case "ServiceMonitor", "PodMonitor":
			object.Namespace = kubernetesNamespace(object)
			resource := kubernetesResource(model.ResourceTypeTarget, kubernetesObjectName(object), instance, object, now)
			resource.Labels = cloneLabels(object.Labels)
			resource.Metadata["selector"] = labelSetString(object.Selector)
			resource.Metadata["namespace_selector"] = namespaceSelectorString(object)
			resource.Metadata["endpoint_count"] = strconv.Itoa(object.EndpointCount)
			resource.Metadata["endpoint_ports"] = strings.Join(object.EndpointPorts, ",")
			resource.Metadata["scrape_class"] = object.ScrapeClassName
			populateKubernetesMonitorIngestionLimitMetadata(&resource, object.MonitorIngestionLimits)
			populateKubernetesMonitorScrapeTimingMetadata(&resource, object.MonitorScrapeTiming)
			populateKubernetesMonitorFileAccessMetadata(&resource, object)
			populateKubernetesMonitorHonorMetadata(&resource, object)
			resourcesByID[resource.ID] = resource
			if object.Kind == "ServiceMonitor" {
				serviceMonitors = append(serviceMonitors, resource)
			} else {
				podMonitors = append(podMonitors, resource)
			}
			monitorSelectors[resource.ID] = object.Selector
		case "Probe":
			object.Namespace = kubernetesNamespace(object)
			resource := kubernetesResource(model.ResourceTypeTarget, kubernetesObjectName(object), instance, object, now)
			resource.Labels = cloneLabels(object.Labels)
			resource.Metadata["probe_job_name"] = object.ProbeJobName
			resource.Metadata["probe_module"] = object.ProbeModule
			resource.Metadata["probe_prober_url"] = object.ProbeProberURL
			resource.Metadata["probe_prober_scheme"] = object.ProbeProberScheme
			resource.Metadata["probe_prober_path"] = object.ProbeProberPath
			resource.Metadata["probe_target_mode"] = object.ProbeTargetMode
			resource.Metadata["probe_target_count"] = strconv.Itoa(object.ProbeTargetCount)
			resource.Metadata["selector"] = labelSetString(object.Selector)
			resource.Metadata["namespace_selector"] = namespaceSelectorString(object)
			resource.Metadata["scrape_class"] = object.ScrapeClassName
			populateKubernetesMonitorIngestionLimitMetadata(&resource, object.MonitorIngestionLimits)
			populateKubernetesMonitorScrapeTimingMetadata(&resource, object.MonitorScrapeTiming)
			populateKubernetesMonitorFileAccessMetadata(&resource, object)
			populateKubernetesMonitorHonorMetadata(&resource, object)
			if object.ProbeInterval != "" {
				resource.Metadata[model.MetadataScrapeInterval] = object.ProbeInterval
			}
			if object.ProbeScrapeTimeout != "" {
				resource.Metadata[model.MetadataScrapeTimeout] = object.ProbeScrapeTimeout
			}
			resourcesByID[resource.ID] = resource
		case "ScrapeConfig":
			object.Namespace = kubernetesNamespace(object)
			resource := kubernetesResource(model.ResourceTypeTarget, kubernetesObjectName(object), instance, object, now)
			resource.Labels = cloneLabels(object.Labels)
			resource.Metadata["scrape_config_job_name"] = object.ScrapeConfigJobName
			resource.Metadata["scrape_config_metrics_path"] = object.ScrapeConfigMetricsPath
			resource.Metadata["scrape_config_scheme"] = object.ScrapeConfigScheme
			resource.Metadata["scrape_config_static_count"] = strconv.Itoa(object.ScrapeConfigStaticCount)
			resource.Metadata["scrape_config_empty_static_count"] = strconv.Itoa(object.ScrapeConfigEmptyStaticCount)
			resource.Metadata["scrape_config_static_target_count"] = strconv.Itoa(object.ScrapeConfigStaticTargetCount)
			resource.Metadata["scrape_config_discovery_count"] = strconv.Itoa(object.ScrapeConfigDiscoveryConfigCount)
			resource.Metadata["scrape_config_discovery_types"] = strings.Join(object.ScrapeConfigDiscoveryConfigTypes, ",")
			resource.Metadata["scrape_class"] = object.ScrapeClassName
			populateKubernetesMonitorIngestionLimitMetadata(&resource, object.MonitorIngestionLimits)
			populateKubernetesMonitorScrapeTimingMetadata(&resource, object.MonitorScrapeTiming)
			populateKubernetesMonitorFileAccessMetadata(&resource, object)
			populateKubernetesMonitorHonorMetadata(&resource, object)
			if object.ScrapeConfigInterval != "" {
				resource.Metadata[model.MetadataScrapeInterval] = object.ScrapeConfigInterval
			}
			if object.ScrapeConfigTimeout != "" {
				resource.Metadata[model.MetadataScrapeTimeout] = object.ScrapeConfigTimeout
			}
			resourcesByID[resource.ID] = resource
		case "Prometheus", "PrometheusAgent":
			object.Namespace = kubernetesNamespace(object)
			resource := kubernetesResource(model.ResourceTypeTSDB, kubernetesObjectName(object), instance, object, now)
			resource.Labels = cloneLabels(object.Labels)
			resource.Metadata["prometheus_mode"] = object.PrometheusMode
			resource.Metadata["prometheus_version"] = object.PrometheusVersion
			resource.Metadata["prometheus_paused"] = strconv.FormatBool(object.PrometheusPaused)
			resource.Metadata["prometheus_replicas"] = strconv.Itoa(object.PrometheusReplicas)
			resource.Metadata["prometheus_replicas_declared"] = strconv.FormatBool(object.PrometheusReplicasDeclared)
			resource.Metadata["prometheus_shards"] = strconv.Itoa(object.PrometheusShards)
			resource.Metadata["prometheus_shards_declared"] = strconv.FormatBool(object.PrometheusShardsDeclared)
			resource.Metadata["prometheus_desired_pod_count"] = strconv.Itoa(kubernetesPrometheusDesiredPodCount(object))
			resource.Metadata["prometheus_declared_selector_count"] = strconv.Itoa(kubernetesPrometheusDeclaredSelectorCount(object))
			monitorSelectorCount := kubernetesPrometheusDeclaredMonitorSelectorCount(object)
			resource.Metadata["prometheus_declared_monitor_selector_count"] = strconv.Itoa(monitorSelectorCount)
			resource.Metadata["prometheus_configuration_managed"] = strconv.FormatBool(monitorSelectorCount > 0)
			resource.Metadata["prometheus_additional_scrape_configs_declared"] = strconv.FormatBool(object.PrometheusAdditionalScrapeDeclared)
			populateKubernetesPrometheusStorageMetadata(&resource, object)
			populateKubernetesPrometheusQueryMetadata(&resource, object)
			populateKubernetesPrometheusScrapeTimingMetadata(&resource, object)
			populateKubernetesPrometheusFileAccessMetadata(&resource, object)
			populateKubernetesPrometheusHonorMetadata(&resource, object)
			populateKubernetesPrometheusNamespaceBoundaryMetadata(&resource, object)
			populateKubernetesPrometheusExternalLabelMetadata(&resource, object)
			populateKubernetesPrometheusWebEndpointMetadata(&resource, object)
			populateKubernetesPrometheusPodSecurityMetadata(&resource, object)
			populateKubernetesPrometheusResourceMetadata(&resource, object)
			populateKubernetesPrometheusStatefulSetMetadata(&resource, object)
			populateKubernetesPrometheusDNSMetadata(&resource, object)
			populateKubernetesPrometheusSecurityMetadata(&resource, object)
			populateKubernetesPrometheusImageMetadata(&resource, object)
			populateKubernetesPrometheusPlacementMetadata(&resource, object)
			populateKubernetesPrometheusPodReferenceMetadata(&resource, object)
			populateKubernetesPrometheusVolumeMetadata(&resource, object)
			populateKubernetesPrometheusPodCustomizationMetadata(&resource, object)
			populateKubernetesPrometheusRolloutMetadata(&resource, object)
			populateKubernetesPrometheusRuntimeMetadata(&resource, object)
			populateKubernetesPrometheusArgumentsMetadata(&resource, object)
			populateKubernetesPrometheusEnforcedLimitMetadata(&resource, object.PrometheusEnforcedLimits)
			if object.Kind == "PrometheusAgent" {
				resource.Metadata["prometheus_agent_mode"] = object.PrometheusAgentMode
				resource.Metadata["prometheus_remote_write_count"] = strconv.Itoa(object.PrometheusRemoteWriteCount)
			}
			resourcesByID[resource.ID] = resource
			prometheuses = append(prometheuses, kubernetesPrometheusResource{Resource: resource, Object: object})
			addKubernetesScrapeClassResources(resourcesByID, relationshipsByID, resource, object, instance, now)
			addKubernetesInlineRemoteWriteResources(resourcesByID, relationshipsByID, resource, object, instance, now)
			addKubernetesRemoteReadResources(resourcesByID, relationshipsByID, resource, object, instance, now)
		case "ThanosRuler":
			object.Namespace = kubernetesNamespace(object)
			resource := kubernetesResource(model.ResourceTypeInstance, kubernetesObjectName(object), instance, object, now)
			resource.Labels = cloneLabels(object.Labels)
			resource.Metadata["thanos_ruler_version"] = object.PrometheusVersion
			resource.Metadata["thanos_ruler_paused"] = strconv.FormatBool(object.PrometheusPaused)
			resource.Metadata["thanos_ruler_replicas"] = strconv.Itoa(object.PrometheusReplicas)
			resource.Metadata["thanos_ruler_replicas_declared"] = strconv.FormatBool(object.PrometheusReplicasDeclared)
			resource.Metadata["thanos_ruler_desired_pod_count"] = strconv.Itoa(object.PrometheusReplicas)
			resource.Metadata["thanos_ruler_query_endpoint_count"] = strconv.Itoa(object.ThanosRulerQueryEndpointCount)
			resource.Metadata["thanos_ruler_query_config_declared"] = strconv.FormatBool(object.ThanosRulerQueryConfigDeclared)
			populateKubernetesThanosRulerNamespaceBoundaryMetadata(&resource, object)
			populateKubernetesThanosRulerRuntimeMetadata(&resource, object)
			populateKubernetesThanosRulerResourceMetadata(&resource, object)
			populateKubernetesThanosRulerPodSecurityMetadata(&resource, object)
			populateKubernetesThanosRulerStorageMetadata(&resource, object)
			populateKubernetesThanosRulerTerminationMetadata(&resource, object)
			populateKubernetesThanosRulerStatefulSetMetadata(&resource, object)
			populateKubernetesThanosRulerDNSMetadata(&resource, object)
			populateKubernetesThanosRulerImageMetadata(&resource, object)
			populateKubernetesThanosRulerPlacementMetadata(&resource, object)
			populateKubernetesThanosRulerVolumeMetadata(&resource, object)
			populateKubernetesThanosRulerPodCustomizationMetadata(&resource, object)
			populateKubernetesThanosRulerWorkloadIdentityMetadata(&resource, object)
			populateKubernetesThanosRulerRolloutMetadata(&resource, object)
			populateKubernetesThanosRulerArgumentsMetadata(&resource, object)
			populateKubernetesThanosRulerWebMetadata(&resource, object)
			populateKubernetesThanosRulerGRPCTLSMetadata(&resource, object)
			populateKubernetesThanosRulerSecretConfigMetadata(&resource, object)
			populateKubernetesThanosRulerEvaluationMetadata(&resource, object)
			populateKubernetesThanosRulerPresentationMetadata(&resource, object)
			populateKubernetesThanosRulerAlertmanagerDeliveryMetadata(&resource, object)
			resourcesByID[resource.ID] = resource
			thanosRulers = append(thanosRulers, kubernetesPrometheusResource{Resource: resource, Object: object})
			addKubernetesInlineRemoteWriteResources(resourcesByID, relationshipsByID, resource, object, instance, now)
		case "Alertmanager":
			object.Namespace = kubernetesNamespace(object)
			resource := kubernetesResource(model.ResourceTypeInstance, kubernetesObjectName(object), instance, object, now)
			resource.Labels = cloneLabels(object.Labels)
			resource.Metadata["alertmanager_version"] = object.AlertmanagerVersion
			resource.Metadata["alertmanager_paused"] = strconv.FormatBool(object.AlertmanagerPaused)
			resource.Metadata["alertmanager_replicas"] = strconv.Itoa(object.AlertmanagerReplicas)
			resource.Metadata["alertmanager_replicas_declared"] = strconv.FormatBool(object.AlertmanagerReplicasDeclared)
			resource.Metadata["alertmanager_desired_pod_count"] = strconv.Itoa(object.AlertmanagerReplicas)
			populateKubernetesAlertmanagerStorageMetadata(&resource, object)
			populateKubernetesAlertmanagerLimitsMetadata(&resource, object)
			populateKubernetesAlertmanagerSecurityMetadata(&resource, object)
			populateKubernetesAlertmanagerArgumentsMetadata(&resource, object)
			populateKubernetesAlertmanagerWebMetadata(&resource, object)
			populateKubernetesAlertmanagerClusterMetadata(&resource, object)
			populateKubernetesAlertmanagerRolloutMetadata(&resource, object)
			populateKubernetesAlertmanagerRuntimeMetadata(&resource, object)
			populateKubernetesAlertmanagerConfigSourceMetadata(&resource, object)
			populateKubernetesAlertmanagerPodSecurityMetadata(&resource, object)
			populateKubernetesAlertmanagerResourceMetadata(&resource, object)
			populateKubernetesAlertmanagerStatefulSetMetadata(&resource, object)
			populateKubernetesAlertmanagerDNSMetadata(&resource, object)
			populateKubernetesAlertmanagerImageMetadata(&resource, object)
			populateKubernetesAlertmanagerVolumeMetadata(&resource, object)
			populateKubernetesAlertmanagerPlacementMetadata(&resource, object)
			populateKubernetesAlertmanagerPodReferenceMetadata(&resource, object)
			populateKubernetesAlertmanagerPodCustomizationMetadata(&resource, object)
			resourcesByID[resource.ID] = resource
			alertmanagers = append(alertmanagers, kubernetesPrometheusResource{Resource: resource, Object: object})
		case "AlertmanagerConfig":
			object.Namespace = kubernetesNamespace(object)
			policy := addKubernetesAlertmanagerConfigResources(resourcesByID, relationshipsByID, object, instance, now)
			alertmanagerConfigs = append(alertmanagerConfigs, kubernetesAlertmanagerConfigResource{Resource: policy, Object: object})
		case "RemoteWrite":
			object.Namespace = kubernetesNamespace(object)
			resource := newKubernetesRemoteWriteCRDResource(object, instance, now)
			resourcesByID[resource.ID] = resource
			remoteWriteResources = append(remoteWriteResources, kubernetesRemoteWriteResource{Resource: resource, Object: object})
		}
	}
	addKubernetesPrometheusRules(resourcesByID, relationshipsByID, prometheusRules, instance, now)
	addKubernetesPrometheusSelections(resourcesByID, relationshipsByID, prometheuses, namespaceLabels, objectLabels, now)
	addKubernetesScrapeClassTopology(resourcesByID, relationshipsByID, prometheuses, now)
	addKubernetesRemoteWriteTopology(resourcesByID, relationshipsByID, prometheuses, remoteWriteResources, namespaceLabels, now)
	addKubernetesRuleEvaluatorSelections(resourcesByID, relationshipsByID, thanosRulers, namespaceLabels, objectLabels, now)
	populateKubernetesThanosRulerWorkloadIdentityTopology(resourcesByID, thanosRulers)
	addKubernetesAlertmanagerSelections(resourcesByID, relationshipsByID, alertmanagers, alertmanagerConfigs, namespaceLabels, objectLabels, now)

	for _, monitor := range serviceMonitors {
		for _, service := range services {
			if !monitorMatchesServiceNamespace(monitor, service) {
				continue
			}
			if labelsMatch(monitorSelectors[monitor.ID], service.Labels) {
				relationship := kubernetesRelationship(monitor.ID, service.ID, model.RelationshipReferences, now)
				relationshipsByID[relationship.ID] = relationship
			}
		}
	}
	for _, monitor := range podMonitors {
		for _, pod := range pods {
			if !monitorMatchesServiceNamespace(monitor, pod) {
				continue
			}
			if labelsMatch(monitorSelectors[monitor.ID], pod.Labels) {
				relationship := kubernetesRelationship(monitor.ID, pod.ID, model.RelationshipReferences, now)
				relationshipsByID[relationship.ID] = relationship
			}
		}
	}

	snapshot := Snapshot{
		Resources:     make([]model.Resource, 0, len(resourcesByID)),
		Relationships: make([]model.Relationship, 0, len(relationshipsByID)),
	}
	for _, resource := range resourcesByID {
		snapshot.Resources = append(snapshot.Resources, resource)
	}
	for _, relationship := range relationshipsByID {
		snapshot.Relationships = append(snapshot.Relationships, relationship)
	}
	sort.Slice(snapshot.Resources, func(i, j int) bool { return snapshot.Resources[i].ID < snapshot.Resources[j].ID })
	sort.Slice(snapshot.Relationships, func(i, j int) bool { return snapshot.Relationships[i].ID < snapshot.Relationships[j].ID })
	return snapshot, nil
}

func decodeKubernetesManifestNodes(content string) ([]*yaml.Node, error) {
	decoder := yaml.NewDecoder(strings.NewReader(content))
	nodes := make([]*yaml.Node, 0)
	for documentIndex := 0; ; documentIndex++ {
		var document yaml.Node
		err := decoder.Decode(&document)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("document %d: %w", documentIndex+1, err)
		}
		if len(document.Content) == 0 {
			continue
		}
		if err := appendKubernetesManifestNode(&nodes, document.Content[0]); err != nil {
			return nil, fmt.Errorf("document %d: %w", documentIndex+1, err)
		}
	}
	return nodes, nil
}

func appendKubernetesManifestNode(nodes *[]*yaml.Node, node *yaml.Node) error {
	var header struct {
		Kind string `yaml:"kind"`
	}
	if err := node.Decode(&header); err != nil {
		return err
	}
	if header.Kind != "List" {
		*nodes = append(*nodes, node)
		return nil
	}
	items := yamlMappingValue(node, "items")
	if items == nil || items.Kind != yaml.SequenceNode {
		return fmt.Errorf("Kubernetes List items must be a sequence")
	}
	for _, item := range items.Content {
		if err := appendKubernetesManifestNode(nodes, item); err != nil {
			return err
		}
	}
	return nil
}

func yamlMappingValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for index := 0; index+1 < len(node.Content); index += 2 {
		if node.Content[index].Value == key {
			return node.Content[index+1]
		}
	}
	return nil
}

func parseKubernetesPrometheusRules(nodes []*yaml.Node) []kubernetesPrometheusRule {
	rules := make([]kubernetesPrometheusRule, 0)
	for _, node := range nodes {
		var rule kubernetesPrometheusRule
		if err := node.Decode(&rule); err != nil {
			continue
		}
		if rule.Kind == "PrometheusRule" && strings.TrimSpace(rule.Metadata.Name) != "" {
			rules = append(rules, rule)
		}
	}
	return rules
}

func addKubernetesPrometheusRules(resourcesByID map[string]model.Resource, relationshipsByID map[string]model.Relationship, definitions []kubernetesPrometheusRule, instance string, now time.Time) {
	for _, definition := range definitions {
		namespace := strings.TrimSpace(definition.Metadata.Namespace)
		if namespace == "" {
			namespace = "default"
		}
		definitionName := namespace + "/" + strings.TrimSpace(definition.Metadata.Name)
		for groupIndex, group := range definition.Spec.Groups {
			groupName := strings.TrimSpace(group.Name)
			groupIdentity := groupName
			if groupIdentity == "" {
				groupIdentity = strconv.Itoa(groupIndex)
			}
			for ruleIndex, rule := range group.Rules {
				resourceType := model.ResourceTypeAlertRule
				ruleKind := "alert"
				ruleName := strings.TrimSpace(rule.Alert)
				if ruleName == "" {
					resourceType = model.ResourceTypeRecordingRule
					ruleKind = "record"
					ruleName = strings.TrimSpace(rule.Record)
				}
				if ruleName == "" {
					continue
				}

				externalID := fmt.Sprintf("prometheusrule:%s:group:%s:%s:%s:%d", definitionName, groupIdentity, ruleKind, ruleName, ruleIndex)
				ruleResource := kubernetesManifestResource(resourceType, ruleName, instance, externalID, now)
				ruleResource.Labels = kubernetesStringMap(definition.Metadata.Labels)
				for key, value := range kubernetesStringMap(rule.Labels) {
					ruleResource.Labels[key] = value
				}
				ruleResource.Metadata["kubernetes_kind"] = "PrometheusRule"
				ruleResource.Metadata["namespace"] = namespace
				ruleResource.Metadata["prometheus_rule"] = definitionName
				if groupName != "" {
					ruleResource.Metadata[model.MetadataRuleGroup] = groupName
				}
				if interval := strings.TrimSpace(group.Interval); interval != "" {
					ruleResource.Metadata[model.MetadataEvaluationInterval] = interval
				}
				if holdDuration := strings.TrimSpace(rule.For); holdDuration != "" {
					ruleResource.Metadata[model.MetadataAlertFor] = holdDuration
				}
				setQueryMetadata(ruleResource.Metadata, model.MetadataPromQL, rule.Expression)
				for key, value := range kubernetesStringMap(rule.Annotations) {
					key = strings.TrimSpace(key)
					value = strings.TrimSpace(value)
					if key != "" && value != "" {
						ruleResource.Metadata["annotation."+key] = value
					}
				}
				if resourceType == model.ResourceTypeRecordingRule {
					ruleResource.Metadata[model.MetadataRecordingRuleOutput] = ruleName
				}
				annotateSLORuleMetadata(&ruleResource)
				resourcesByID[ruleResource.ID] = ruleResource

				var outputMetric model.Resource
				if resourceType == model.ResourceTypeRecordingRule {
					outputMetric = kubernetesManifestResource(model.ResourceTypeMetric, ruleName, instance, "metric:"+ruleName, now)
					resourcesByID[outputMetric.ID] = outputMetric
					relationship := kubernetesRelationship(ruleResource.ID, outputMetric.ID, model.RelationshipProduces, now)
					relationshipsByID[relationship.ID] = relationship
				}

				for _, metricName := range ExtractPromQLMetricNames(rule.Expression) {
					metricResource := kubernetesManifestResource(model.ResourceTypeMetric, metricName, instance, "metric:"+metricName, now)
					resourcesByID[metricResource.ID] = metricResource
					relationship := kubernetesRelationship(ruleResource.ID, metricResource.ID, model.RelationshipUses, now)
					relationshipsByID[relationship.ID] = relationship
					if outputMetric.ID != "" && outputMetric.ID != metricResource.ID {
						derived := kubernetesRelationship(metricResource.ID, outputMetric.ID, model.RelationshipProduces, now)
						derived.Metadata = map[string]string{"via_rule_id": ruleResource.ID, "via_rule_name": ruleResource.Name}
						relationshipsByID[derived.ID] = derived
					}
				}
			}
		}
	}
}

func kubernetesManifestResource(resourceType model.ResourceType, name string, instance string, externalID string, now time.Time) model.Resource {
	uid := model.StableID(kubernetesSystem, externalID)
	return model.Resource{
		ID:        uid,
		UID:       uid,
		Type:      resourceType,
		Name:      name,
		Source:    model.SourceInfo{System: kubernetesSystem, Instance: instance, ExternalID: externalID},
		Labels:    map[string]string{},
		Metadata:  map[string]string{},
		Status:    model.ResourceStatusActive,
		CreatedAt: now,
		UpdatedAt: now,
	}
}

type kubernetesProbeStaticConfig struct {
	Static []string       `yaml:"static"`
	Labels map[string]any `yaml:"labels"`
}

type kubernetesScrapeStaticConfig struct {
	Targets []string       `yaml:"targets"`
	Labels  map[string]any `yaml:"labels"`
}

type kubernetesProbeIngressConfig struct {
	Selector          map[string]any `yaml:"selector"`
	NamespaceSelector struct {
		Any        bool     `yaml:"any"`
		MatchNames []string `yaml:"matchNames"`
	} `yaml:"namespaceSelector"`
}

type kubernetesManifestObjectDefinition struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name      string         `yaml:"name"`
		Namespace string         `yaml:"namespace"`
		Labels    map[string]any `yaml:"labels"`
	} `yaml:"metadata"`
	Spec struct {
		Selector          map[string]any `yaml:"selector"`
		NamespaceSelector struct {
			Any        bool     `yaml:"any"`
			MatchNames []string `yaml:"matchNames"`
		} `yaml:"namespaceSelector"`
		Endpoints           []map[string]any `yaml:"endpoints"`
		PodMetricsEndpoints []map[string]any `yaml:"podMetricsEndpoints"`
		JobName             string           `yaml:"jobName"`
		Module              string           `yaml:"module"`
		Interval            string           `yaml:"interval"`
		ScrapeTimeout       string           `yaml:"scrapeTimeout"`
		Prober              struct {
			URL    string `yaml:"url"`
			Scheme string `yaml:"scheme"`
			Path   string `yaml:"path"`
		} `yaml:"prober"`
		Targets struct {
			StaticConfig *kubernetesProbeStaticConfig  `yaml:"staticConfig"`
			Ingress      *kubernetesProbeIngressConfig `yaml:"ingress"`
		} `yaml:"targets"`
		StaticConfigs  []kubernetesScrapeStaticConfig `yaml:"staticConfigs"`
		MetricsPath    string                         `yaml:"metricsPath"`
		Scheme         string                         `yaml:"scheme"`
		ScrapeInterval string                         `yaml:"scrapeInterval"`
		Version        string                         `yaml:"version"`
		Paused         bool                           `yaml:"paused"`
		Replicas       *int                           `yaml:"replicas"`
		Shards         *int                           `yaml:"shards"`
		Mode           string                         `yaml:"mode"`
	} `yaml:"spec"`
}

func parseKubernetesManifestObjects(nodes []*yaml.Node) []kubernetesObject {
	objects := make([]kubernetesObject, 0)
	for _, node := range nodes {
		var definition kubernetesManifestObjectDefinition
		if err := node.Decode(&definition); err != nil {
			continue
		}
		object := kubernetesObject{
			Kind:                   strings.TrimSpace(definition.Kind),
			Name:                   strings.TrimSpace(definition.Metadata.Name),
			Namespace:              strings.TrimSpace(definition.Metadata.Namespace),
			Labels:                 kubernetesStringMap(definition.Metadata.Labels),
			Selector:               kubernetesSelector(definition.Spec.Selector),
			NamespaceSelectorAny:   definition.Spec.NamespaceSelector.Any,
			NamespaceSelectorNames: cleanKubernetesStrings(definition.Spec.NamespaceSelector.MatchNames),
		}
		spec := yamlMappingValue(node, "spec")
		if isKubernetesPrometheusSelectableKind(object.Kind) && object.Kind != "PrometheusRule" {
			object.MonitorIngestionLimits = parseKubernetesIngestionLimits(spec, false)
			object.MonitorScrapeTiming = parseKubernetesMonitorScrapeTiming(spec, object.Kind)
			object.MonitorArbitraryFileReferenceCount = parseKubernetesMonitorArbitraryFileReferences(spec, object.Kind)
			object.MonitorHonorLabelsCount, object.MonitorExplicitHonorTimestampsCount = parseKubernetesMonitorHonorSettings(spec, object.Kind)
		}
		object.ScrapeClassName = kubernetesScrapeClassReference(spec)
		endpoints := definition.Spec.Endpoints
		if object.Kind == "PodMonitor" {
			endpoints = definition.Spec.PodMetricsEndpoints
		}
		object.EndpointCount = len(endpoints)
		for _, endpoint := range endpoints {
			addKubernetesEndpointPort(&object, "port", kubernetesScalarString(endpoint["port"]))
			addKubernetesEndpointPort(&object, "targetPort", kubernetesScalarString(endpoint["targetPort"]))
		}
		if object.Kind == "Probe" {
			populateKubernetesProbeObject(&object, definition)
		}
		if object.Kind == "ScrapeConfig" {
			populateKubernetesScrapeConfigObject(&object, definition, node)
		}
		if object.Kind == "Prometheus" || object.Kind == "PrometheusAgent" {
			populateKubernetesPrometheusObject(&object, definition, node)
		}
		if object.Kind == "ThanosRuler" {
			populateKubernetesThanosRulerObject(&object, definition, node)
		}
		if object.Kind == "Alertmanager" {
			populateKubernetesAlertmanagerObject(&object, definition, node)
		}
		if object.Kind == "AlertmanagerConfig" {
			populateKubernetesAlertmanagerConfigObject(&object, node)
		}
		if object.Kind == "RemoteWrite" {
			populateKubernetesRemoteWriteCRDObject(&object, node)
		}
		if object.Kind != "" && object.Name != "" {
			objects = append(objects, object)
		}
	}
	return objects
}

func populateKubernetesThanosRulerObject(object *kubernetesObject, definition kubernetesManifestObjectDefinition, node *yaml.Node) {
	object.PrometheusVersion = strings.TrimSpace(definition.Spec.Version)
	object.PrometheusPaused = definition.Spec.Paused
	object.PrometheusReplicas = 1
	if definition.Spec.Replicas != nil {
		object.PrometheusReplicas = *definition.Spec.Replicas
		object.PrometheusReplicasDeclared = true
	}
	spec := yamlMappingValue(node, "spec")
	populateKubernetesNamespaceEnforcementObject(object, spec)
	populateKubernetesThanosRulerRuntimeObject(object, spec)
	populateKubernetesThanosRulerResourceObject(object, spec)
	populateKubernetesThanosRulerPodSecurityObject(object, spec)
	object.ThanosRulerQueryEndpointCount = yamlSequenceLength(yamlMappingValue(spec, "queryEndpoints"))
	object.ThanosRulerQueryConfigDeclared = yamlValueDeclared(yamlMappingValue(spec, "queryConfig"))
	object.RemoteWrites = parseKubernetesRemoteWrites(yamlMappingValue(spec, "remoteWrite"))
	populateKubernetesThanosRulerStorageObject(object, spec)
	populateKubernetesThanosRulerTerminationObject(object, spec)
	populateKubernetesThanosRulerStatefulSetObject(object, spec)
	populateKubernetesThanosRulerDNSObject(object, spec)
	populateKubernetesThanosRulerImageObject(object, spec)
	populateKubernetesThanosRulerPlacementObject(object, spec)
	populateKubernetesThanosRulerVolumeObject(object, spec)
	populateKubernetesThanosRulerPodCustomizationObject(object, spec)
	populateKubernetesThanosRulerWorkloadIdentityObject(object, spec)
	populateKubernetesThanosRulerRolloutObject(object, spec)
	populateKubernetesThanosRulerArgumentsObject(object, spec)
	populateKubernetesThanosRulerWebObject(object, spec)
	populateKubernetesThanosRulerGRPCTLSObject(object, spec)
	populateKubernetesThanosRulerSecretConfigObject(object, spec)
	populateKubernetesThanosRulerEvaluationObject(object, spec)
	populateKubernetesThanosRulerPresentationObject(object, spec)
	populateKubernetesThanosRulerAlertmanagerDeliveryObject(object, spec)
	object.PrometheusSelections = map[string]kubernetesPrometheusSelection{
		"PrometheusRule": {
			ResourceSelector:  parseKubernetesLabelSelector(yamlMappingValue(spec, "ruleSelector")),
			NamespaceSelector: parseKubernetesLabelSelector(yamlMappingValue(spec, "ruleNamespaceSelector")),
		},
	}
}

func populateKubernetesPrometheusObject(object *kubernetesObject, definition kubernetesManifestObjectDefinition, node *yaml.Node) {
	object.PrometheusMode = "server"
	if object.Kind == "PrometheusAgent" {
		object.PrometheusMode = "agent"
		object.PrometheusAgentMode = "statefulset"
		if mode := strings.TrimSpace(definition.Spec.Mode); mode != "" {
			object.PrometheusAgentMode = strings.ToLower(mode)
		}
	}
	object.PrometheusVersion = strings.TrimSpace(definition.Spec.Version)
	object.PrometheusPaused = definition.Spec.Paused
	object.PrometheusReplicas = 1
	if definition.Spec.Replicas != nil {
		object.PrometheusReplicas = *definition.Spec.Replicas
		object.PrometheusReplicasDeclared = true
	}
	object.PrometheusShards = 1
	if definition.Spec.Shards != nil {
		object.PrometheusShards = *definition.Spec.Shards
		object.PrometheusShardsDeclared = true
	}
	object.PrometheusSelections = map[string]kubernetesPrometheusSelection{}
	spec := yamlMappingValue(node, "spec")
	object.PrometheusAdditionalScrapeDeclared = yamlValueDeclared(yamlMappingValue(spec, "additionalScrapeConfigs"))
	populateKubernetesPrometheusStorageObject(object, spec)
	populateKubernetesPrometheusScrapeTimingObject(object, spec)
	populateKubernetesPrometheusFileAccessObject(object, spec)
	populateKubernetesPrometheusHonorObject(object, spec)
	populateKubernetesPrometheusNamespaceBoundaryObject(object, spec)
	populateKubernetesPrometheusExternalLabelObject(object, spec)
	populateKubernetesPrometheusWebEndpointObject(object, spec)
	populateKubernetesPrometheusQueryObject(object, spec)
	populateKubernetesPrometheusPodSecurityObject(object, spec)
	populateKubernetesPrometheusResourceObject(object, spec)
	populateKubernetesPrometheusStatefulSetObject(object, spec)
	populateKubernetesPrometheusDNSObject(object, spec)
	populateKubernetesPrometheusSecurityObject(object, spec)
	populateKubernetesPrometheusImageObject(object, spec)
	populateKubernetesPrometheusPlacementObject(object, spec)
	populateKubernetesPrometheusPodReferenceObject(object, spec)
	populateKubernetesPrometheusVolumeObject(object, spec)
	populateKubernetesPrometheusPodCustomizationObject(object, spec)
	populateKubernetesPrometheusRolloutObject(object, spec)
	populateKubernetesPrometheusRuntimeObject(object, spec)
	populateKubernetesPrometheusArgumentsObject(object, spec)
	object.PrometheusEnforcedLimits = parseKubernetesIngestionLimits(spec, true)
	object.ScrapeClasses = parseKubernetesScrapeClasses(yamlMappingValue(spec, "scrapeClasses"))
	object.RemoteWrites = parseKubernetesRemoteWrites(yamlMappingValue(spec, "remoteWrite"))
	object.PrometheusRemoteWriteCount = len(object.RemoteWrites)
	if object.Kind == "Prometheus" {
		object.RemoteReads = parseKubernetesRemoteReads(yamlMappingValue(spec, "remoteRead"))
	}
	object.RemoteWriteSelection = kubernetesPrometheusSelection{
		ResourceSelector:  parseKubernetesLabelSelector(yamlMappingValue(spec, "remoteWriteSelector")),
		NamespaceSelector: parseKubernetesLabelSelector(yamlMappingValue(spec, "remoteWriteNamespaceSelector")),
	}
	selectorKeys := map[string][2]string{
		"ServiceMonitor": {"serviceMonitorSelector", "serviceMonitorNamespaceSelector"},
		"PodMonitor":     {"podMonitorSelector", "podMonitorNamespaceSelector"},
		"Probe":          {"probeSelector", "probeNamespaceSelector"},
		"ScrapeConfig":   {"scrapeConfigSelector", "scrapeConfigNamespaceSelector"},
		"PrometheusRule": {"ruleSelector", "ruleNamespaceSelector"},
	}
	if object.Kind == "PrometheusAgent" {
		delete(selectorKeys, "PrometheusRule")
	}
	for kind, keys := range selectorKeys {
		object.PrometheusSelections[kind] = kubernetesPrometheusSelection{
			ResourceSelector:  parseKubernetesLabelSelector(yamlMappingValue(spec, keys[0])),
			NamespaceSelector: parseKubernetesLabelSelector(yamlMappingValue(spec, keys[1])),
		}
	}
}

func yamlSequenceLength(node *yaml.Node) int {
	if node == nil || node.Kind != yaml.SequenceNode {
		return 0
	}
	return len(node.Content)
}

func yamlValueDeclared(node *yaml.Node) bool {
	return node != nil && node.Tag != "!!null"
}

func parseKubernetesLabelSelector(node *yaml.Node) kubernetesLabelSelector {
	selector := kubernetesLabelSelector{MatchLabels: map[string]string{}}
	if node == nil || node.Tag == "!!null" {
		return selector
	}
	selector.Declared = true
	if node.Kind != yaml.MappingNode {
		return selector
	}
	var decoded struct {
		MatchLabels      map[string]any `yaml:"matchLabels"`
		MatchExpressions []struct {
			Key      string   `yaml:"key"`
			Operator string   `yaml:"operator"`
			Values   []string `yaml:"values"`
		} `yaml:"matchExpressions"`
	}
	if err := node.Decode(&decoded); err != nil {
		return selector
	}
	selector.MatchLabels = kubernetesStringMap(decoded.MatchLabels)
	for _, expression := range decoded.MatchExpressions {
		selector.MatchExpressions = append(selector.MatchExpressions, kubernetesLabelExpression{
			Key:      strings.TrimSpace(expression.Key),
			Operator: strings.TrimSpace(expression.Operator),
			Values:   cleanKubernetesStrings(expression.Values),
		})
	}
	return selector
}

func populateKubernetesScrapeConfigObject(object *kubernetesObject, definition kubernetesManifestObjectDefinition, node *yaml.Node) {
	object.ScrapeConfigJobName = strings.TrimSpace(definition.Spec.JobName)
	object.ScrapeConfigMetricsPath = strings.TrimSpace(definition.Spec.MetricsPath)
	object.ScrapeConfigScheme = strings.TrimSpace(definition.Spec.Scheme)
	object.ScrapeConfigInterval = strings.TrimSpace(definition.Spec.ScrapeInterval)
	object.ScrapeConfigTimeout = strings.TrimSpace(definition.Spec.ScrapeTimeout)
	object.ScrapeConfigStaticCount = len(definition.Spec.StaticConfigs)
	for _, staticConfig := range definition.Spec.StaticConfigs {
		object.ScrapeConfigStaticTargetCount += len(staticConfig.Targets)
		if len(staticConfig.Targets) == 0 {
			object.ScrapeConfigEmptyStaticCount++
		}
	}
	for key, value := range commonKubernetesScrapeLabels(definition.Spec.StaticConfigs) {
		object.Labels[key] = value
	}
	object.ScrapeConfigDiscoveryConfigTypes, object.ScrapeConfigDiscoveryConfigCount = kubernetesScrapeDiscoverySummary(node)
}

func commonKubernetesScrapeLabels(configs []kubernetesScrapeStaticConfig) map[string]string {
	if len(configs) == 0 {
		return map[string]string{}
	}
	common := kubernetesStringMap(configs[0].Labels)
	for _, config := range configs[1:] {
		labels := kubernetesStringMap(config.Labels)
		for key, value := range common {
			if labels[key] != value {
				delete(common, key)
			}
		}
	}
	return common
}

func kubernetesScrapeDiscoverySummary(node *yaml.Node) ([]string, int) {
	spec := yamlMappingValue(node, "spec")
	if spec == nil || spec.Kind != yaml.MappingNode {
		return nil, 0
	}
	types := make([]string, 0)
	count := 0
	for index := 0; index+1 < len(spec.Content); index += 2 {
		key := strings.TrimSpace(spec.Content[index].Value)
		if !strings.HasSuffix(key, "SDConfigs") {
			continue
		}
		configs := spec.Content[index+1]
		if configs.Kind != yaml.SequenceNode || len(configs.Content) == 0 {
			continue
		}
		types = append(types, strings.TrimSuffix(key, "SDConfigs"))
		count += len(configs.Content)
	}
	sort.Strings(types)
	return types, count
}

func populateKubernetesProbeObject(object *kubernetesObject, definition kubernetesManifestObjectDefinition) {
	object.ProbeJobName = strings.TrimSpace(definition.Spec.JobName)
	object.ProbeModule = strings.TrimSpace(definition.Spec.Module)
	object.ProbeProberURL = strings.TrimSpace(definition.Spec.Prober.URL)
	object.ProbeProberScheme = strings.TrimSpace(definition.Spec.Prober.Scheme)
	object.ProbeProberPath = strings.TrimSpace(definition.Spec.Prober.Path)
	object.ProbeInterval = strings.TrimSpace(definition.Spec.Interval)
	object.ProbeScrapeTimeout = strings.TrimSpace(definition.Spec.ScrapeTimeout)

	if definition.Spec.Targets.StaticConfig != nil {
		object.ProbeTargetMode = "static"
		object.ProbeTargetCount = len(definition.Spec.Targets.StaticConfig.Static)
		for key, value := range kubernetesStringMap(definition.Spec.Targets.StaticConfig.Labels) {
			object.Labels[key] = value
		}
		return
	}
	if definition.Spec.Targets.Ingress != nil {
		object.ProbeTargetMode = "ingress"
		object.Selector = kubernetesSelector(definition.Spec.Targets.Ingress.Selector)
		object.NamespaceSelectorAny = definition.Spec.Targets.Ingress.NamespaceSelector.Any
		object.NamespaceSelectorNames = cleanKubernetesStrings(definition.Spec.Targets.Ingress.NamespaceSelector.MatchNames)
	}
}

func kubernetesSelector(selector map[string]any) map[string]string {
	if matchLabels, ok := selector["matchLabels"]; ok {
		return kubernetesStringMap(kubernetesMap(matchLabels))
	}
	return kubernetesStringMap(selector)
}

func kubernetesMap(value any) map[string]any {
	switch typed := value.(type) {
	case map[string]any:
		return typed
	case map[any]any:
		result := make(map[string]any, len(typed))
		for key, value := range typed {
			keyString := kubernetesScalarString(key)
			if keyString != "" {
				result[keyString] = value
			}
		}
		return result
	default:
		return map[string]any{}
	}
}

func kubernetesStringMap(values map[string]any) map[string]string {
	result := make(map[string]string, len(values))
	for key, value := range values {
		key = strings.TrimSpace(key)
		valueString := kubernetesScalarString(value)
		if key != "" && valueString != "" {
			result[key] = valueString
		}
	}
	return result
}

func kubernetesScalarString(value any) string {
	switch value.(type) {
	case nil, map[string]any, map[any]any, []any:
		return ""
	default:
		return strings.TrimSpace(fmt.Sprint(value))
	}
}

func cleanKubernetesStrings(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}

func addKubernetesPrometheusSelections(
	resourcesByID map[string]model.Resource,
	relationshipsByID map[string]model.Relationship,
	prometheuses []kubernetesPrometheusResource,
	namespaceLabels map[string]map[string]string,
	objectLabels map[string]map[string]string,
	now time.Time,
) {
	if len(prometheuses) == 0 {
		return
	}
	selectedByPrometheus := map[string]int{}
	nonzeroSelectedByPrometheus := map[string]int{}
	for resourceID, candidate := range resourcesByID {
		kind := strings.TrimSpace(candidate.Metadata["kubernetes_kind"])
		if !isKubernetesPrometheusSelectableKind(kind) {
			continue
		}
		arbitraryFileReferenceCount, _ := strconv.Atoi(strings.TrimSpace(candidate.Metadata["monitor_arbitrary_file_reference_count"]))
		honorLabelsCount, _ := strconv.Atoi(strings.TrimSpace(candidate.Metadata["monitor_honor_labels_count"]))
		honorTimestampsCount, _ := strconv.Atoi(strings.TrimSpace(candidate.Metadata["monitor_explicit_honor_timestamps_count"]))
		objectName := candidate.Name
		if kind == "PrometheusRule" {
			objectName = strings.TrimSpace(candidate.Metadata["prometheus_rule"])
		}
		labels := objectLabels[kubernetesSelectionObjectKey(kind, objectName)]
		allKnown := true
		selectedCount := 0
		nonzeroSelectedCount := 0
		ingestionCoverage := map[string]int{}
		scrapeTimeoutConflictCount := 0
		arbitraryFileAccessProtectedCount := 0
		honorLabelsOverrideCount := 0
		honorTimestampsOverrideCount := 0
		namespaceSelectorIgnoredCount := 0
		crossNamespaceSelectedCount := 0
		namespaceLabelEnforcedCount := 0
		namespaceLabelExcludedCount := 0
		namespaceLabelUnprotectedCount := 0
		for _, prometheus := range prometheuses {
			selection := prometheus.Object.PrometheusSelections[kind]
			resourceMatches, resourceKnown := kubernetesLabelSelectorMatches(selection.ResourceSelector, labels)
			if !resourceKnown {
				allKnown = false
				continue
			}
			if !resourceMatches {
				continue
			}
			namespaceMatches, namespaceKnown := kubernetesNamespaceSelectorMatches(
				selection.NamespaceSelector,
				prometheus.Object.Namespace,
				candidate.Metadata["namespace"],
				namespaceLabels,
			)
			if !namespaceKnown {
				allKnown = false
				continue
			}
			if !namespaceMatches {
				continue
			}
			relationship := kubernetesRelationship(prometheus.Resource.ID, candidate.ID, model.RelationshipReferences, now)
			relationship.Metadata = map[string]string{"selection_kind": kind}
			relationshipsByID[relationship.ID] = relationship
			selectedCount++
			if candidate.Metadata["namespace"] != prometheus.Object.Namespace {
				crossNamespaceSelectedCount++
				switch kubernetesNamespaceEnforcementFor(prometheus.Object, kind, objectName, candidate.Metadata["namespace"]) {
				case kubernetesNamespaceEnforced:
					namespaceLabelEnforcedCount++
				case kubernetesNamespaceExcluded:
					namespaceLabelExcludedCount++
				default:
					namespaceLabelUnprotectedCount++
				}
			}
			if kind != "PrometheusRule" {
				for _, dimension := range kubernetesIngestionCoverageDimensions {
					if candidate.Metadata[dimension.localKey] == "true" || dimension.global(prometheus.Object.PrometheusEnforcedLimits).Valid {
						ingestionCoverage[dimension.name]++
					}
				}
				if prometheus.Object.PrometheusScrapeIntervalDeclared && prometheus.Object.PrometheusScrapeIntervalValid {
					for _, timeout := range kubernetesMetadataInt64List(candidate.Metadata["monitor_scrape_timeout_without_interval_seconds"]) {
						if timeout > prometheus.Object.PrometheusScrapeIntervalSeconds {
							scrapeTimeoutConflictCount++
						}
					}
				}
				if arbitraryFileReferenceCount > 0 && prometheus.Object.PrometheusArbitraryFSAccessDenied {
					arbitraryFileAccessProtectedCount++
				}
				if honorLabelsCount > 0 && prometheus.Object.PrometheusOverrideHonorLabels {
					honorLabelsOverrideCount++
				}
				if honorTimestampsCount > 0 && prometheus.Object.PrometheusOverrideHonorTimestamps {
					honorTimestampsOverrideCount++
				}
				if kubernetesMonitorHasBroadNamespaceSelector(candidate) && prometheus.Object.PrometheusIgnoreNamespaceSelectors {
					namespaceSelectorIgnoredCount++
				}
			}
			selectedByPrometheus[prometheus.Resource.ID]++
			if kubernetesPrometheusDesiredPodCount(prometheus.Object) > 0 {
				nonzeroSelectedCount++
				nonzeroSelectedByPrometheus[prometheus.Resource.ID]++
			}
		}
		candidate.Metadata["prometheus_selection_candidate"] = "true"
		candidate.Metadata["prometheus_selection_evaluable"] = strconv.FormatBool(selectedCount > 0 || allKnown)
		candidate.Metadata["prometheus_selected_count"] = strconv.Itoa(selectedCount)
		candidate.Metadata["prometheus_nonzero_selected_count"] = strconv.Itoa(nonzeroSelectedCount)
		candidate.Metadata["prometheus_cross_namespace_selected_count"] = strconv.Itoa(crossNamespaceSelectedCount)
		candidate.Metadata["prometheus_namespace_label_enforced_count"] = strconv.Itoa(namespaceLabelEnforcedCount)
		candidate.Metadata["prometheus_namespace_label_excluded_count"] = strconv.Itoa(namespaceLabelExcludedCount)
		candidate.Metadata["prometheus_namespace_label_unprotected_count"] = strconv.Itoa(namespaceLabelUnprotectedCount)
		if kind != "PrometheusRule" {
			for _, dimension := range kubernetesIngestionCoverageDimensions {
				covered := ingestionCoverage[dimension.name]
				candidate.Metadata["prometheus_"+dimension.name+"_limit_covered_count"] = strconv.Itoa(covered)
				candidate.Metadata["prometheus_"+dimension.name+"_limit_unprotected_count"] = strconv.Itoa(selectedCount - covered)
			}
			candidate.Metadata["prometheus_scrape_timeout_conflict_count"] = strconv.Itoa(scrapeTimeoutConflictCount)
			candidate.Metadata["prometheus_arbitrary_file_access_protected_count"] = strconv.Itoa(arbitraryFileAccessProtectedCount)
			if arbitraryFileReferenceCount > 0 {
				candidate.Metadata["prometheus_arbitrary_file_access_unprotected_count"] = strconv.Itoa(selectedCount - arbitraryFileAccessProtectedCount)
			} else {
				candidate.Metadata["prometheus_arbitrary_file_access_unprotected_count"] = "0"
			}
			candidate.Metadata["prometheus_honor_labels_override_count"] = strconv.Itoa(honorLabelsOverrideCount)
			if honorLabelsCount > 0 {
				candidate.Metadata["prometheus_honor_labels_unprotected_count"] = strconv.Itoa(selectedCount - honorLabelsOverrideCount)
			} else {
				candidate.Metadata["prometheus_honor_labels_unprotected_count"] = "0"
			}
			candidate.Metadata["prometheus_honor_timestamps_override_count"] = strconv.Itoa(honorTimestampsOverrideCount)
			if honorTimestampsCount > 0 {
				candidate.Metadata["prometheus_honor_timestamps_unprotected_count"] = strconv.Itoa(selectedCount - honorTimestampsOverrideCount)
			} else {
				candidate.Metadata["prometheus_honor_timestamps_unprotected_count"] = "0"
			}
			candidate.Metadata["prometheus_namespace_selector_ignored_count"] = strconv.Itoa(namespaceSelectorIgnoredCount)
			if kubernetesMonitorHasBroadNamespaceSelector(candidate) {
				candidate.Metadata["prometheus_namespace_selector_effective_count"] = strconv.Itoa(selectedCount - namespaceSelectorIgnoredCount)
			} else {
				candidate.Metadata["prometheus_namespace_selector_effective_count"] = "0"
			}
		}
		resourcesByID[resourceID] = candidate
	}
	for _, prometheus := range prometheuses {
		resource := resourcesByID[prometheus.Resource.ID]
		resource.Metadata["prometheus_selected_resource_count"] = strconv.Itoa(selectedByPrometheus[prometheus.Resource.ID])
		resource.Metadata["prometheus_nonzero_selected_resource_count"] = strconv.Itoa(nonzeroSelectedByPrometheus[prometheus.Resource.ID])
		resourcesByID[resource.ID] = resource
	}
}

func addKubernetesRuleEvaluatorSelections(
	resourcesByID map[string]model.Resource,
	relationshipsByID map[string]model.Relationship,
	thanosRulers []kubernetesPrometheusResource,
	namespaceLabels map[string]map[string]string,
	objectLabels map[string]map[string]string,
	now time.Time,
) {
	selectedByRuler := map[string]int{}
	selectedAlertsByRuler := map[string]int{}
	for resourceID, candidate := range resourcesByID {
		if strings.TrimSpace(candidate.Metadata["kubernetes_kind"]) != "PrometheusRule" {
			continue
		}
		selectedCount, _ := strconv.Atoi(strings.TrimSpace(candidate.Metadata["prometheus_selected_count"]))
		nonzeroSelectedCount, _ := strconv.Atoi(strings.TrimSpace(candidate.Metadata["prometheus_nonzero_selected_count"]))
		crossNamespaceSelectedCount, _ := strconv.Atoi(strings.TrimSpace(candidate.Metadata["prometheus_cross_namespace_selected_count"]))
		namespaceLabelEnforcedCount, _ := strconv.Atoi(strings.TrimSpace(candidate.Metadata["prometheus_namespace_label_enforced_count"]))
		namespaceLabelExcludedCount, _ := strconv.Atoi(strings.TrimSpace(candidate.Metadata["prometheus_namespace_label_excluded_count"]))
		namespaceLabelUnprotectedCount, _ := strconv.Atoi(strings.TrimSpace(candidate.Metadata["prometheus_namespace_label_unprotected_count"]))
		allKnown := candidate.Metadata["prometheus_selection_evaluable"] != "false"
		objectName := strings.TrimSpace(candidate.Metadata["prometheus_rule"])
		labels := objectLabels[kubernetesSelectionObjectKey("PrometheusRule", objectName)]
		for _, ruler := range thanosRulers {
			selection := ruler.Object.PrometheusSelections["PrometheusRule"]
			resourceMatches, resourceKnown := kubernetesLabelSelectorMatches(selection.ResourceSelector, labels)
			if !resourceKnown {
				allKnown = false
				continue
			}
			if !resourceMatches {
				continue
			}
			namespaceMatches, namespaceKnown := kubernetesNamespaceSelectorMatches(selection.NamespaceSelector, ruler.Object.Namespace, candidate.Metadata["namespace"], namespaceLabels)
			if !namespaceKnown {
				allKnown = false
				continue
			}
			if !namespaceMatches {
				continue
			}
			relationship := kubernetesRelationship(ruler.Resource.ID, candidate.ID, model.RelationshipReferences, now)
			relationship.Metadata = map[string]string{"selection_kind": "PrometheusRule", "rule_evaluator_kind": "ThanosRuler"}
			relationshipsByID[relationship.ID] = relationship
			selectedCount++
			if candidate.Metadata["namespace"] != ruler.Object.Namespace {
				crossNamespaceSelectedCount++
				switch kubernetesNamespaceEnforcementFor(ruler.Object, "PrometheusRule", objectName, candidate.Metadata["namespace"]) {
				case kubernetesNamespaceEnforced:
					namespaceLabelEnforcedCount++
				case kubernetesNamespaceExcluded:
					namespaceLabelExcludedCount++
				default:
					namespaceLabelUnprotectedCount++
				}
			}
			selectedByRuler[ruler.Resource.ID]++
			if candidate.Type == model.ResourceTypeAlertRule {
				selectedAlertsByRuler[ruler.Resource.ID]++
			}
			if ruler.Object.PrometheusReplicas > 0 {
				nonzeroSelectedCount++
			}
		}
		candidate.Metadata["rule_evaluator_selection_candidate"] = "true"
		candidate.Metadata["rule_evaluator_selection_evaluable"] = strconv.FormatBool(selectedCount > 0 || allKnown)
		candidate.Metadata["rule_evaluator_selected_count"] = strconv.Itoa(selectedCount)
		candidate.Metadata["rule_evaluator_nonzero_selected_count"] = strconv.Itoa(nonzeroSelectedCount)
		candidate.Metadata["rule_evaluator_cross_namespace_selected_count"] = strconv.Itoa(crossNamespaceSelectedCount)
		candidate.Metadata["rule_evaluator_namespace_label_enforced_count"] = strconv.Itoa(namespaceLabelEnforcedCount)
		candidate.Metadata["rule_evaluator_namespace_label_excluded_count"] = strconv.Itoa(namespaceLabelExcludedCount)
		candidate.Metadata["rule_evaluator_namespace_label_unprotected_count"] = strconv.Itoa(namespaceLabelUnprotectedCount)
		resourcesByID[resourceID] = candidate
	}
	for _, ruler := range thanosRulers {
		resource := resourcesByID[ruler.Resource.ID]
		resource.Metadata["thanos_ruler_selected_rule_count"] = strconv.Itoa(selectedByRuler[ruler.Resource.ID])
		resource.Metadata["thanos_ruler_selected_alert_rule_count"] = strconv.Itoa(selectedAlertsByRuler[ruler.Resource.ID])
		resourcesByID[resource.ID] = resource
	}
}

func kubernetesLabelSelectorMatches(selector kubernetesLabelSelector, labels map[string]string) (bool, bool) {
	if !selector.Declared {
		return false, true
	}
	for key, expected := range selector.MatchLabels {
		if actual, ok := labels[key]; !ok || actual != expected {
			return false, true
		}
	}
	for _, expression := range selector.MatchExpressions {
		if expression.Key == "" {
			return false, false
		}
		actual, exists := labels[expression.Key]
		switch expression.Operator {
		case "In":
			if !exists || !kubernetesStringContains(expression.Values, actual) {
				return false, true
			}
		case "NotIn":
			if exists && kubernetesStringContains(expression.Values, actual) {
				return false, true
			}
		case "Exists":
			if !exists {
				return false, true
			}
		case "DoesNotExist":
			if exists {
				return false, true
			}
		default:
			return false, false
		}
	}
	return true, true
}

func kubernetesNamespaceSelectorMatches(selector kubernetesLabelSelector, prometheusNamespace string, candidateNamespace string, namespaceLabels map[string]map[string]string) (bool, bool) {
	if !selector.Declared {
		return prometheusNamespace == candidateNamespace, true
	}
	if len(selector.MatchLabels) == 0 && len(selector.MatchExpressions) == 0 {
		return true, true
	}
	labels, known := namespaceLabels[candidateNamespace]
	if !known {
		return false, false
	}
	return kubernetesLabelSelectorMatches(selector, labels)
}

func kubernetesStringContains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func isKubernetesPrometheusSelectableKind(kind string) bool {
	switch kind {
	case "ServiceMonitor", "PodMonitor", "Probe", "ScrapeConfig", "PrometheusRule":
		return true
	default:
		return false
	}
}

func kubernetesSelectionObjectKey(kind string, name string) string {
	return strings.TrimSpace(kind) + ":" + strings.TrimSpace(name)
}

func kubernetesPrometheusDeclaredSelectorCount(object kubernetesObject) int {
	count := 0
	for _, selection := range object.PrometheusSelections {
		if selection.ResourceSelector.Declared {
			count++
		}
	}
	if object.RemoteWriteSelection.ResourceSelector.Declared {
		count++
	}
	return count
}

func kubernetesPrometheusDeclaredMonitorSelectorCount(object kubernetesObject) int {
	count := 0
	for _, kind := range []string{"ServiceMonitor", "PodMonitor", "Probe", "ScrapeConfig"} {
		if object.PrometheusSelections[kind].ResourceSelector.Declared {
			count++
		}
	}
	return count
}

func kubernetesPrometheusDesiredPodCount(object kubernetesObject) int {
	if object.Kind == "PrometheusAgent" && object.PrometheusAgentMode == "daemonset" {
		return 1
	}
	if object.PrometheusReplicas <= 0 || object.PrometheusShards <= 0 {
		return 0
	}
	return object.PrometheusReplicas * object.PrometheusShards
}

func kubernetesResource(resourceType model.ResourceType, name string, instance string, object kubernetesObject, now time.Time) model.Resource {
	externalID := strings.ToLower(object.Kind) + ":" + name
	uid := model.StableID(kubernetesSystem, externalID)
	resource := model.Resource{
		ID:        uid,
		UID:       uid,
		Type:      resourceType,
		Name:      name,
		Source:    model.SourceInfo{System: kubernetesSystem, Instance: instance, ExternalID: externalID},
		Metadata:  map[string]string{"kubernetes_kind": object.Kind},
		Status:    model.ResourceStatusActive,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if object.Namespace != "" {
		resource.Metadata["namespace"] = object.Namespace
	}
	return resource
}

func kubernetesRelationship(fromID string, toID string, relationshipType model.RelationshipType, now time.Time) model.Relationship {
	return model.Relationship{
		ID:        model.StableID(kubernetesSystem, string(relationshipType), fromID, toID),
		FromID:    fromID,
		ToID:      toID,
		Type:      relationshipType,
		CreatedAt: now,
	}
}

func kubernetesObjectName(object kubernetesObject) string {
	if object.Namespace == "" {
		return object.Name
	}
	return object.Namespace + "/" + object.Name
}

func kubernetesNamespace(object kubernetesObject) string {
	namespace := strings.TrimSpace(object.Namespace)
	if namespace == "" {
		return "default"
	}
	return namespace
}

func monitorMatchesServiceNamespace(monitor model.Resource, service model.Resource) bool {
	selector := strings.TrimSpace(monitor.Metadata["namespace_selector"])
	serviceNamespace := strings.TrimSpace(service.Metadata["namespace"])
	monitorNamespace := strings.TrimSpace(monitor.Metadata["namespace"])
	if selector == "*" {
		return true
	}
	if strings.HasPrefix(selector, "matchNames=") {
		names := strings.Split(strings.TrimPrefix(selector, "matchNames="), ",")
		for _, name := range names {
			if strings.TrimSpace(name) == serviceNamespace {
				return true
			}
		}
		return false
	}
	return monitorNamespace == serviceNamespace
}

func namespaceSelectorString(object kubernetesObject) string {
	if object.NamespaceSelectorAny {
		return "*"
	}
	if len(object.NamespaceSelectorNames) == 0 {
		return ""
	}
	names := append([]string(nil), object.NamespaceSelectorNames...)
	sort.Strings(names)
	return "matchNames=" + strings.Join(names, ",")
}

func addKubernetesEndpointPort(object *kubernetesObject, key string, value string) {
	key = strings.TrimSpace(key)
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	if key != "port" && key != "targetPort" {
		return
	}
	port := key + "=" + value
	for _, existing := range object.EndpointPorts {
		if existing == port {
			return
		}
	}
	object.EndpointPorts = append(object.EndpointPorts, port)
	sort.Strings(object.EndpointPorts)
}

func labelsMatch(selector map[string]string, labels map[string]string) bool {
	if len(selector) == 0 {
		return false
	}
	for key, value := range selector {
		if labels[key] != value {
			return false
		}
	}
	return true
}

func labelSetString(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+labels[key])
	}
	return strings.Join(parts, ",")
}
