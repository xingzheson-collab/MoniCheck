package model

import "time"

type ResourceType string

const (
	ResourceTypeMetric               ResourceType = "Metric"
	ResourceTypeMetricLabel          ResourceType = "MetricLabel"
	ResourceTypeTSDB                 ResourceType = "TSDB"
	ResourceTypeService              ResourceType = "Service"
	ResourceTypeDashboard            ResourceType = "Dashboard"
	ResourceTypeFolder               ResourceType = "Folder"
	ResourceTypePanel                ResourceType = "Panel"
	ResourceTypeDatasource           ResourceType = "Datasource"
	ResourceTypeAlert                ResourceType = "Alert"
	ResourceTypeAlertRule            ResourceType = "AlertRule"
	ResourceTypeSilence              ResourceType = "Silence"
	ResourceTypeReceiver             ResourceType = "Receiver"
	ResourceTypeNotificationPolicy   ResourceType = "NotificationPolicy"
	ResourceTypeInhibitionRule       ResourceType = "InhibitionRule"
	ResourceTypeTimeInterval         ResourceType = "TimeInterval"
	ResourceTypeNotificationTemplate ResourceType = "NotificationTemplate"
	ResourceTypeProcessor            ResourceType = "Processor"
	ResourceTypePipeline             ResourceType = "Pipeline"
	ResourceTypeExtension            ResourceType = "Extension"
	ResourceTypeTelemetryConnector   ResourceType = "TelemetryConnector"
	ResourceTypeRecordingRule        ResourceType = "RecordingRule"
	ResourceTypeTarget               ResourceType = "Target"
	ResourceTypeExporter             ResourceType = "Exporter"
	ResourceTypeJob                  ResourceType = "Job"
	ResourceTypeInstance             ResourceType = "Instance"
	ResourceTypeLogLabel             ResourceType = "LogLabel"
	ResourceTypeLogLabelValue        ResourceType = "LogLabelValue"
	ResourceTypeTraceTag             ResourceType = "TraceTag"
	ResourceTypeTraceTagValue        ResourceType = "TraceTagValue"
	ResourceTypeTraceOperation       ResourceType = "TraceOperation"
	ResourceTypeProfileType          ResourceType = "ProfileType"
	ResourceTypeProfileLabel         ResourceType = "ProfileLabel"
	ResourceTypeProfileLabelValue    ResourceType = "ProfileLabelValue"
	ResourceTypeProfileService       ResourceType = "ProfileService"
	ResourceTypeLogStream            ResourceType = "LogStream"
	ResourceTypeTraceService         ResourceType = "TraceService"
	ResourceTypeTable                ResourceType = "Table"
	ResourceTypeScrapeClass          ResourceType = "ScrapeClass"
)

type ResourceStatus string

const (
	ResourceStatusActive     ResourceStatus = "ACTIVE"
	ResourceStatusDeprecated ResourceStatus = "DEPRECATED"
	ResourceStatusOrphan     ResourceStatus = "ORPHAN"
	ResourceStatusBroken     ResourceStatus = "BROKEN"
	ResourceStatusDeleted    ResourceStatus = "DELETED"
)

type SourceInfo struct {
	System     string `json:"system"`
	Cluster    string `json:"cluster,omitempty"`
	Instance   string `json:"instance"`
	ExternalID string `json:"external_id"`
}

type Resource struct {
	ID        string            `json:"id"`
	Type      ResourceType      `json:"type"`
	Name      string            `json:"name"`
	UID       string            `json:"uid"`
	Source    SourceInfo        `json:"source"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
	Status    ResourceStatus    `json:"status"`
}

type RelationshipType string

const (
	RelationshipUses       RelationshipType = "USES"
	RelationshipBelongsTo  RelationshipType = "BELONGS_TO"
	RelationshipReferences RelationshipType = "REFERENCES"
	RelationshipDependsOn  RelationshipType = "DEPENDS_ON"
	RelationshipProduces   RelationshipType = "PRODUCES"
)

type Relationship struct {
	ID        string            `json:"id"`
	FromID    string            `json:"from_id"`
	ToID      string            `json:"to_id"`
	Type      RelationshipType  `json:"type"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
}

type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityWarning  Severity = "WARNING"
	SeverityCritical Severity = "CRITICAL"
)

type FindingStatus string

const (
	FindingStatusOpen     FindingStatus = "OPEN"
	FindingStatusAcked    FindingStatus = "ACKED"
	FindingStatusApproved FindingStatus = "APPROVED"
	FindingStatusWaived   FindingStatus = "WAIVED"
	FindingStatusResolved FindingStatus = "RESOLVED"
	FindingStatusClosed   FindingStatus = "CLOSED"
)

type ResourceRef struct {
	ID   string       `json:"id"`
	Type ResourceType `json:"type"`
	Name string       `json:"name"`
}

type Finding struct {
	ID             string             `json:"id"`
	Type           string             `json:"type"`
	Severity       Severity           `json:"severity"`
	Category       FindingCategory    `json:"category"`
	RiskScore      *FindingRiskScore  `json:"risk_score,omitempty"`
	Occurrence     *FindingOccurrence `json:"occurrence,omitempty"`
	Resource       ResourceRef        `json:"resource"`
	Evidence       []string           `json:"evidence"`
	Recommendation string             `json:"recommendation"`
	Metadata       map[string]string  `json:"metadata,omitempty"`
	Status         FindingStatus      `json:"status"`
	CreatedAt      time.Time          `json:"created_at"`
	UpdatedAt      time.Time          `json:"updated_at"`
}

type FindingRiskComponent struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Value       int    `json:"value"`
	Maximum     int    `json:"maximum"`
	Explanation string `json:"explanation"`
}

type FindingRiskScore struct {
	Version              string                 `json:"version"`
	Score                int                    `json:"score"`
	Level                string                 `json:"level"`
	Confidence           int                    `json:"confidence"`
	ConfidenceLevel      string                 `json:"confidence_level"`
	Components           []FindingRiskComponent `json:"components"`
	ConfidenceComponents []FindingRiskComponent `json:"confidence_components"`
}

type FindingWorkflowEvent struct {
	ID        string            `json:"id"`
	FindingID string            `json:"finding_id"`
	Action    string            `json:"action"`
	Actor     string            `json:"actor,omitempty"`
	From      string            `json:"from,omitempty"`
	To        string            `json:"to,omitempty"`
	Note      string            `json:"note,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
}

type FindingCategory string

const (
	FindingCategoryQuality       FindingCategory = "QUALITY"
	FindingCategoryCost          FindingCategory = "COST"
	FindingCategoryLifecycle     FindingCategory = "LIFECYCLE"
	FindingCategoryReliability   FindingCategory = "RELIABILITY"
	FindingCategoryConfiguration FindingCategory = "CONFIGURATION"
	FindingCategorySecurity      FindingCategory = "SECURITY"
)

func DefaultFindingCategory(findingType string, resourceType ResourceType) FindingCategory {
	switch findingType {
	case "HighCardinalityMetric", "RiskyMetricLabel", "HighCardinalityMetricLabel", "HighMemoryMetricLabel", "HighSeriesTSDB", "HighTSDBLabelMemory", "RapidTSDBGrowth", "HighCardinalityLogLabel", "RiskyLogLabel", "HighCardinalityTraceTag", "RiskyTraceTag", "HighCardinalityProfileLabel", "RiskyProfileLabel", "HighOperationCountService", "ExpensiveQuery", "WideRangeQuery", "WideLogQuery", "HighCardinalityAggregation", "UnscopedQuery", "UnscopedLogQuery", "UnscopedTraceQuery", "QueryWithoutRecordingRule", "DuplicateQuery", "DuplicateObservabilityQuery", "LargeDashboard", "DashboardQueryFanout", "FastDashboardRefresh", "LongDashboardTimeRange", "OpenSearchHighShardDensity", "ElasticsearchHighShardDensity", "PrometheusHighQueryConcurrency", "PrometheusHighQuerySampleLimit", "PrometheusLongQueryTimeout", "PrometheusUnboundedRemoteReadConcurrency", "PrometheusUnboundedRemoteReadSamples", "PrometheusUnboundedSearchAPI", "PrometheusLargeRemoteReadFrame", "PrometheusHighWebConnectionLimit", "PrometheusAgentWALCompressionDisabled", "PrometheusAgentLongWALRetention", "PrometheusAgentLongWALMinimumRetention", "PrometheusTSDBWALCompressionDisabled", "PrometheusAutoGOMAXPROCSDisabled", "PrometheusDebugLogging", "PrometheusHighNotificationSubscriberLimit", "PrometheusLongStorageRetention", "PrometheusExemplarStorageEnabled", "PrometheusCreatedTimestampZeroIngestion", "PrometheusMetadataWALRecordsEnabled", "PrometheusTypeAndUnitLabelsEnabled":
		return FindingCategoryCost
	case "UnusedMetric", "UnusedDatasource", "UnusedRecordingRule", "UnusedReceiver", "UnusedTimeInterval", "UnusedNotificationTemplate", "OrphanAlert", "OrphanedResource", "DisabledAlert", "MissingOwner", "DatadogServiceWithoutTeam", "NewRelicEntityWithoutOwner", "NewRelicDisabledCondition", "StaleResource", "OldResource", "StaleUpdate", "SuppressedAlert", "LongSilence", "SilenceWithoutComment", "NoActiveAlertInstance", "PrometheusDeprecatedExtraScrapeMetrics", "PrometheusExperimentalXOR2Encoding", "PrometheusExperimentalSTStorage":
		return FindingCategoryLifecycle
	case "UnallocatedMetricCost", "AmbiguousMetricCostAllocation", "HighMonthlyMetricCost", "RapidMetricCostGrowth", "OverdueCostVerification", "CostOptimizationReadinessOverride":
		return FindingCategoryCost
	case "OTelProbabilisticSamplerInvalidOptions":
		return FindingCategoryReliability
	case "OTelProbabilisticSamplerRecordSourceWithoutAttribute":
		return FindingCategoryReliability
	case "OTelProbabilisticSamplerRecordSourceUnsupportedMode":
		return FindingCategoryReliability
	case "OTelProbabilisticSamplerFailOpen":
		return FindingCategoryCost
	case "OTelTailSamplingPolicyAttributionEnabled":
		return FindingCategoryCost
	case "OTelTailSamplingDetailedMetricsEnabled":
		return FindingCategoryCost
	case "OTelTailSamplingOverflowEvictionEnabled":
		return FindingCategoryReliability
	case "NewRelicCriticalConditionWithoutLossOfSignal":
		return FindingCategoryReliability
	case "NewRelicCriticalConditionShortViolationTimeLimit":
		return FindingCategoryReliability
	case "NewRelicCriticalConditionInvalidSlidingWindow":
		return FindingCategoryReliability
	case "NewRelicConditionSlidingWindowCost":
		return FindingCategoryCost
	case "NewRelicConditionInvalidThresholdPriorityCount":
		return FindingCategoryConfiguration
	case "NewRelicConditionInvalidThresholdTermSemantics":
		return FindingCategoryConfiguration
	case "NewRelicConditionInvalidThresholdValue":
		return FindingCategoryConfiguration
	case "NewRelicConditionInvalidGapFillOption":
		return FindingCategoryConfiguration
	case "NewRelicConditionInvalidStaticGapFillValue":
		return FindingCategoryConfiguration
	case "NewRelicConditionPerTargetIncidentFanout":
		return FindingCategoryReliability
	case "NewRelicCriticalConditionAtLeastOnceThreshold":
		return FindingCategoryReliability
	case "NewRelicCriticalConditionInvalidLossOfSignalDuration":
		return FindingCategoryReliability
	case "NewRelicCriticalConditionShortLossOfSignalDuration":
		return FindingCategoryReliability
	case "NewRelicCriticalConditionEvaluationDelay":
		return FindingCategoryReliability
	case "NewRelicCriticalConditionLastValueGapFilling":
		return FindingCategoryReliability
	case "NewRelicCriticalConditionStaticGapFillBreachesThreshold":
		return FindingCategoryReliability
	case "NewRelicCriticalConditionWithoutCloseOnSignalLoss":
		return FindingCategoryReliability
	case "NewRelicCriticalConditionInvalidAggregationDelay":
		return FindingCategoryReliability
	case "NewRelicCriticalConditionWithoutEntityScope":
		return FindingCategoryReliability
	case "NewRelicConditionIncompatibleNRQLClause":
		return FindingCategoryConfiguration
	case "NewRelicBaselineConditionInvalidThresholdDuration":
		return FindingCategoryConfiguration
	case "NewRelicBaselineConditionInvalidDirection":
		return FindingCategoryConfiguration
	case "NewRelicStaticConditionInvalidValueFunction":
		return FindingCategoryConfiguration
	case "DatadogPriorityMonitorWithoutNoDataNotification":
		return FindingCategoryReliability
	case "DatadogPriorityMonitorWithoutNotificationCoverage":
		return FindingCategoryReliability
	case "DatadogPriorityMetricMonitorWithoutRecoveryThreshold":
		return FindingCategoryReliability
	case "OTelTailSamplingRuntimeDrops", "OTelTailSamplingPolicyEvaluationErrors", "OTelExporterEnqueueFailures", "OTelExporterSendFailures", "OTelReceiverRefusedTelemetry", "OTelScraperErrors", "OTelExporterQueueSaturated", "OTelExporterQueueNearSaturation":
		return FindingCategoryReliability
	case "PanelMetricNotCollected", "AlertRuleMetricNotCollected", "RecordingRuleInputNotCollected", "BrokenTarget", "BrokenRule", "BrokenDashboard", "InvalidDatasource", "HighImpactMetric", "HighImpactService", "HighServiceDependencyFanout", "CircularServiceDependency", "JaegerDependencyDiscoveryTruncated", "JaegerRuntimeUnhealthy", "ServiceObservabilityGap", "LokiNotReady", "SkyWalkingOAPUnhealthy", "SkyWalkingServiceWithoutInstance", "SkyWalkingServiceAlarmBurst", "TempoServiceDiscoveryTruncated", "TempoNotReady", "PyroscopeNotReady", "OTelCollectorHealthCheckDisabled", "OTelCollectorRuntimeUnhealthy", "OTelConnectorOneSided", "OTelExporterSendingQueueDisabled", "OTelExporterRetryDisabled", "OTelMemoryLimiterWithoutLimit", "OTelMemoryLimiterInvalidConfig", "OTelMemoryLimiterNotFirst", "OTelBatchInvalidConfig", "OTelBatchPassThrough", "OTelBatchBeforeSampling", "OTelTailSamplingWithoutPolicy", "OTelTailSamplingInvalidConfig", "OTelTailSamplingDropsPendingOnShutdown", "OTelTailSamplingZeroTraceCapacity", "OTelTailSamplingUndersizedDecisionCache", "OTelTailSamplingTailStorageGateDisabled", "OTelTailSamplingTailStorageExtensionUnavailable", "OTelTailSamplingUnboundedTraceSize", "OTelProbabilisticSamplerDropAll", "OTelProbabilisticSamplerInvalidConfig", "N9ECurrentAlertDiscoveryUnavailable", "N9EHistoryDiscoveryUnavailable", "N9EEventDiscoveryTruncated", "AlertmanagerClusterNotReady", "AlertmanagerSingletonCluster", "OpenSearchClusterRed", "OpenSearchClusterYellow", "OpenSearchPendingTasks", "OpenSearchNoDataNodes", "OpenSearchNodeStatsIncomplete", "OpenSearchHighDiskUsage", "OpenSearchHighHeapUsage", "OpenSearchHighFileDescriptorUsage", "ElasticsearchClusterRed", "ElasticsearchClusterYellow", "ElasticsearchPendingTasks", "ElasticsearchNoDataNodes", "ElasticsearchNodeStatsIncomplete", "ElasticsearchHighDiskUsage", "ElasticsearchHighHeapUsage", "ElasticsearchHighFileDescriptorUsage", "DatadogMonitorNoData", "DatadogMonitorUnknown", "DatadogPriorityMonitorWithoutRenotify", "NewRelicEntityNotReporting", "NewRelicEntityCritical", "NewRelicCriticalConditionCadenceAggregation", "NewRelicCriticalConditionInvalidEventTimer", "NewRelicCriticalConditionInvalidAggregationWindow", "NewRelicCriticalConditionEventTimerShorterThanWindow", "NewRelicCriticalConditionInvalidThresholdDuration", "PrometheusWithoutActiveAlertmanager", "PrometheusDroppedAlertmanagerTargets", "PrometheusSingleAlertmanagerTarget", "PrometheusZeroNotificationQueueCapacity", "PrometheusNotificationQueueNotDrained", "PrometheusShortAlertResendDelay", "PrometheusLargeNotificationBatchSize", "PrometheusTSDBCorruptionDetected", "PrometheusShortStorageRetention", "PrometheusLongQueryLookback", "PrometheusRuleQuerySaturationRisk", "PrometheusLongWebReadTimeout", "PrometheusTSDBLockfileDisabled", "PrometheusAgentLockfileDisabled", "PrometheusAgentShortRemoteFlushDeadline", "PrometheusAutoGOMEMLIMITDisabled", "PrometheusHighAutoGOMEMLIMITRatio", "PrometheusLongAutoReloadInterval", "PrometheusShortAlertOutageTolerance", "PrometheusAlertForBelowGracePeriod", "PrometheusOTLPDeltaToCumulative", "PrometheusSTSynthesisEnabled", "PrometheusOTLPNativeDeltaIngestion", "PrometheusExperimentalUncachedIO", "GrafanaDatabaseUnhealthy", "ServiceWithoutSLO", "SLOWithoutAlert", "MissingSLOObjective", "InvalidSLOObjective", "InconsistentSLOObjective", "InvalidSLOWindow", "InsufficientSLOWindows", "IncompleteSLOWindowCoverage", "HighImpactDatasource", "HighImpactAlertWithoutReceiver", "KubernetesServiceWithoutMonitor", "KubernetesMonitorWithoutMatchedService", "KubernetesPodMonitorWithoutMatchedPod", "LongFiringAlert", "NoisyAlertRule", "FlappingAlertRule", "PoorAlertRecovery", "AlertNotificationStorm", "StaleAlertUpdate", "SlowRuleEvaluation", "StaleRuleEvaluation", "SlowTargetScrape", "StaleTargetScrape", "TargetScrapeTimeoutRisk", "ExpiredActiveAlert", "UnsafeAlertStateHandling", "ReceiverWithoutIntegration", "UndefinedReceiver", "MissingDefaultReceiver", "UndefinedNotificationPolicy", "NotificationPolicyWithoutReceiver", "DisabledNotificationPolicy", "BroadAlertSubscription", "ComplexNotificationPolicy", "ShadowedNotificationRoute", "NotificationFanoutRisk", "NotificationGroupingDisabled", "InvalidNotificationTiming", "IneffectiveRepeatInterval", "BroadInhibitionRule", "InhibitionRuleWithoutEqualLabels", "UndefinedTimeInterval", "UndefinedNotificationTemplate", "BroadSilenceMatcher":
		return FindingCategoryReliability
	case "OTelTailSamplingFullCapture", "OTelProbabilisticSamplerFullCapture":
		return FindingCategoryCost
	case "PublicDatasource", "InsecureDatasource", "DirectDatasourceAccess", "BasicAuthHTTPDatasource", "InsecureReceiverEndpoint", "SensitiveLabel", "PublicOTelDiagnosticExtension", "OTelExporterInsecureTLS", "OTelReceiverPublicUnauthenticated", "OTelReceiverPublicPlaintext", "PrometheusAdminAPIEnabled", "PrometheusLifecycleAPIEnabled":
		return FindingCategorySecurity
	case "MissingMetricType", "MissingMetricHelp", "MissingMetricUnit", "MissingDatasourceType", "InvalidDatasourceType", "MutableDatasource", "MultipleDefaultDatasource", "UnattributedMonitoringResource", "ServiceOwnerMismatch", "DatadogMonitorWithoutService", "DatadogMonitorWithoutPriority", "DatadogPriorityMonitorWithoutRunbook", "NewRelicCriticalConditionWithoutDescription", "NewRelicCriticalConditionWithoutTitleTemplate", "NewRelicCriticalConditionWithoutRunbook", "SkyWalkingEndpointDiscoveryTruncated", "JaegerOperationDiscoveryTruncated", "PrometheusConfigReloadFailed", "PrometheusRemoteWriteReceiverEnabled", "PrometheusOTLPReceiverEnabled", "NoAnnotation", "MetricNamingViolation", "AlertNamingViolation", "MissingRequiredLabel", "MissingSeverityLabel", "InvalidSeverityLabel", "MissingRunbook", "InvalidRunbookURL", "MissingAlertDuration", "InvalidAlertDuration", "AlertWithoutReceiver", "BlackholeReceiver", "AlertWithoutGeneratorURL", "DashboardWithoutFolder", "DashboardWithoutTags", "EditableDashboard", "PanelWithoutVisualizationType", "PanelWithoutTitle", "PanelWithoutUnit", "PanelWithoutThresholds", "UnresolvedPanelDatasource", "PanelQueryWithoutDatasource", "EmptyNotificationTemplate", "UnusedOTelComponent", "IncompleteOTelPipeline", "MissingOTelProcessor", "DebugOTelExporter", "KubernetesMonitorWithoutEndpoint", "KubernetesMonitorWithoutEndpointPort", "KubernetesMonitorWithoutSelector", "KubernetesMonitorBroadNamespaceSelector":
		return FindingCategoryConfiguration
	case "DuplicateMetric", "DuplicateRule", "DuplicateRecordingRuleOutput", "DuplicateDashboard", "DuplicateNotificationTemplateDefinition", "EmptyDashboard", "MissingPanelQuery", "UnresolvedPanelQueryMetric", "MissingRuleQuery", "UnresolvedRuleQueryMetric", "PanelQueryDependencyParseError", "TinyPanel":
		return FindingCategoryQuality
	}

	switch resourceType {
	case ResourceTypeTarget, ResourceTypeDatasource:
		return FindingCategoryReliability
	case ResourceTypeReceiver, ResourceTypeNotificationPolicy, ResourceTypeInhibitionRule, ResourceTypeTimeInterval, ResourceTypeNotificationTemplate, ResourceTypeProcessor, ResourceTypePipeline, ResourceTypeExtension, ResourceTypeTelemetryConnector, ResourceTypeScrapeClass:
		return FindingCategoryConfiguration
	case ResourceTypeMetric, ResourceTypeMetricLabel, ResourceTypeTSDB, ResourceTypeService, ResourceTypeDashboard, ResourceTypeFolder, ResourceTypePanel, ResourceTypeAlert, ResourceTypeAlertRule, ResourceTypeSilence, ResourceTypeRecordingRule, ResourceTypeLogLabel, ResourceTypeLogLabelValue, ResourceTypeTraceTag, ResourceTypeTraceTagValue, ResourceTypeTraceOperation, ResourceTypeProfileType, ResourceTypeProfileLabel, ResourceTypeProfileLabelValue, ResourceTypeProfileService, ResourceTypeLogStream, ResourceTypeTraceService, ResourceTypeTable:
		return FindingCategoryQuality
	default:
		return FindingCategoryQuality
	}
}
