package coverage

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"monicheck/internal/graph"
	"monicheck/internal/model"
)

type SignalState string

const (
	SignalObserved SignalState = "OBSERVED"
	SignalMissing  SignalState = "MISSING"
	SignalUnknown  SignalState = "UNKNOWN"
	SignalExempt   SignalState = "EXEMPT"
)

type AssessmentState string

const (
	AssessmentCompliant AssessmentState = "COMPLIANT"
	AssessmentMissing   AssessmentState = "MISSING"
	AssessmentUnknown   AssessmentState = "UNKNOWN"
)

type EvidenceState string

const (
	EvidenceComplete      EvidenceState = "COMPLETE"
	EvidencePartial       EvidenceState = "PARTIAL"
	EvidenceUnavailable   EvidenceState = "UNAVAILABLE"
	EvidenceNotApplicable EvidenceState = "NOT_APPLICABLE"
)

type SignalAssessment struct {
	Signal      model.CoverageSignal `json:"signal"`
	State       SignalState          `json:"state"`
	ExceptionID string               `json:"exception_id,omitempty"`
}

type Assessment struct {
	ExpectationID             string             `json:"expectation_id"`
	ExpectationName           string             `json:"expectation_name"`
	ServiceID                 string             `json:"service_id"`
	ServiceName               string             `json:"service_name"`
	ServiceIdentitySource     string             `json:"service_identity_source"`
	ServiceIdentityConfidence string             `json:"service_identity_confidence"`
	State                     AssessmentState    `json:"state"`
	Signals                   []SignalAssessment `json:"signals"`
	ObservedCount             int                `json:"observed_count"`
	MissingCount              int                `json:"missing_count"`
	UnknownCount              int                `json:"unknown_count"`
	ExemptCount               int                `json:"exempt_count"`
	EvaluableCount            int                `json:"evaluable_count"`
	CoveragePercent           *float64           `json:"coverage_percent,omitempty"`
	EvidenceState             EvidenceState      `json:"evidence_state"`
	EvidenceCompleteness      *float64           `json:"evidence_completeness_percent,omitempty"`
}

type Summary struct {
	GeneratedAt          time.Time              `json:"generated_at"`
	ExpectationCount     int                    `json:"expectation_count"`
	ServiceCount         int                    `json:"service_count"`
	InferredServiceCount int                    `json:"inferred_service_count"`
	AssessmentCount      int                    `json:"assessment_count"`
	CompliantCount       int                    `json:"compliant_count"`
	MissingCount         int                    `json:"missing_count"`
	UnknownCount         int                    `json:"unknown_count"`
	ObservedSignals      int                    `json:"observed_signals"`
	MissingSignals       int                    `json:"missing_signals"`
	UnknownSignals       int                    `json:"unknown_signals"`
	ExemptSignals        int                    `json:"exempt_signals"`
	EvaluableSignals     int                    `json:"evaluable_signals"`
	CoveragePercent      *float64               `json:"coverage_percent,omitempty"`
	EvidenceState        EvidenceState          `json:"evidence_state"`
	EvidenceCompleteness *float64               `json:"evidence_completeness_percent,omitempty"`
	AvailableSignals     []model.CoverageSignal `json:"available_signals"`
	Assessments          []Assessment           `json:"assessments"`
}

var signalOrder = []model.CoverageSignal{
	model.CoverageSignalMetrics,
	model.CoverageSignalLogs,
	model.CoverageSignalDashboards,
	model.CoverageSignalAlerts,
	model.CoverageSignalTraces,
	model.CoverageSignalProfiles,
}

func NormalizeSignals(signals []model.CoverageSignal) ([]model.CoverageSignal, error) {
	seen := map[model.CoverageSignal]bool{}
	for _, signal := range signals {
		signal = model.CoverageSignal(strings.ToLower(strings.TrimSpace(string(signal))))
		if !validSignal(signal) {
			return nil, fmt.Errorf("unsupported coverage signal %q", signal)
		}
		seen[signal] = true
	}
	result := make([]model.CoverageSignal, 0, len(seen))
	for _, signal := range signalOrder {
		if seen[signal] {
			result = append(result, signal)
		}
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("at least one required signal is required")
	}
	return result, nil
}

func ValidateExpectation(expectation model.CoverageExpectation) error {
	if strings.TrimSpace(expectation.ID) == "" || strings.TrimSpace(expectation.Name) == "" {
		return fmt.Errorf("id and name are required")
	}
	if expectation.Scope != model.CoverageScopeAllServices && expectation.Scope != model.CoverageScopeService {
		return fmt.Errorf("scope must be ALL_SERVICES or SERVICE")
	}
	if expectation.Scope == model.CoverageScopeService && strings.TrimSpace(expectation.ScopeValue) == "" {
		return fmt.Errorf("scope_value is required for SERVICE scope")
	}
	if strings.TrimSpace(expectation.Owner) == "" || strings.TrimSpace(expectation.Rationale) == "" {
		return fmt.Errorf("owner and rationale are required")
	}
	_, err := NormalizeSignals(expectation.RequiredSignals)
	return err
}

func ValidateException(exception model.CoverageException, expectations []model.CoverageExpectation, now time.Time) error {
	if strings.TrimSpace(exception.ExpectationID) == "" || strings.TrimSpace(exception.ServiceID) == "" {
		return fmt.Errorf("expectation_id and service_id are required")
	}
	if !validSignal(exception.Signal) {
		return fmt.Errorf("unsupported coverage signal %q", exception.Signal)
	}
	if strings.TrimSpace(exception.Owner) == "" || strings.TrimSpace(exception.Reason) == "" || strings.TrimSpace(exception.CreatedBy) == "" {
		return fmt.Errorf("owner, reason, and created_by are required")
	}
	if !exception.ExpiresAt.After(now) {
		return fmt.Errorf("expires_at must be in the future")
	}
	for _, expectation := range expectations {
		if expectation.ID != exception.ExpectationID {
			continue
		}
		for _, signal := range expectation.RequiredSignals {
			if signal == exception.Signal {
				return nil
			}
		}
		return fmt.Errorf("signal is not required by expectation")
	}
	return fmt.Errorf("expectation not found")
}

func Assess(resources []model.Resource, resourceGraph *graph.Graph, expectations []model.CoverageExpectation, exceptions []model.CoverageException, now time.Time) Summary {
	available := availableSignals(resources)
	activeExceptions := map[string]model.CoverageException{}
	for _, exception := range exceptions {
		if exception.State(now) == model.CoverageExceptionActive {
			activeExceptions[exceptionKey(exception.ExpectationID, exception.ServiceID, exception.Signal)] = exception
		}
	}
	services := make([]model.Resource, 0)
	for _, resource := range resources {
		if resource.Type == model.ResourceTypeService && resource.Status == model.ResourceStatusActive {
			services = append(services, resource)
		}
	}
	sort.Slice(services, func(i, j int) bool { return services[i].ID < services[j].ID })
	summary := Summary{GeneratedAt: now.UTC(), AvailableSignals: orderedSignalSet(available)}
	serviceSeen := map[string]bool{}
	inferredServiceSeen := map[string]bool{}
	for _, expectation := range expectations {
		if !expectation.Enabled {
			continue
		}
		summary.ExpectationCount++
		required, err := NormalizeSignals(expectation.RequiredSignals)
		if err != nil {
			continue
		}
		for _, service := range services {
			if expectation.Scope == model.CoverageScopeService && expectation.ScopeValue != service.ID {
				continue
			}
			serviceSeen[service.ID] = true
			identitySource := strings.TrimSpace(service.Metadata[model.MetadataServiceIdentitySource])
			identityConfidence := strings.TrimSpace(service.Metadata[model.MetadataServiceIdentityConfidence])
			if identitySource == "" {
				identitySource = strings.TrimSpace(service.Source.System)
			}
			if identityConfidence == "" {
				identityConfidence = "DECLARED"
			}
			if identityConfidence == "INFERRED" {
				inferredServiceSeen[service.ID] = true
			}
			observed := availableSignals(serviceRelatedResources(service.ID, resourceGraph))
			assessment := Assessment{
				ExpectationID: expectation.ID, ExpectationName: expectation.Name,
				ServiceID: service.ID, ServiceName: service.Name, State: AssessmentCompliant,
				ServiceIdentitySource: identitySource, ServiceIdentityConfidence: identityConfidence,
			}
			for _, signal := range required {
				item := SignalAssessment{Signal: signal}
				if exception, ok := activeExceptions[exceptionKey(expectation.ID, service.ID, signal)]; ok {
					item.State = SignalExempt
					item.ExceptionID = exception.ID
					assessment.ExemptCount++
					summary.ExemptSignals++
				} else if observed[signal] {
					item.State = SignalObserved
					assessment.ObservedCount++
					assessment.EvaluableCount++
					summary.ObservedSignals++
					summary.EvaluableSignals++
				} else if available[signal] {
					item.State = SignalMissing
					assessment.MissingCount++
					assessment.EvaluableCount++
					summary.MissingSignals++
					summary.EvaluableSignals++
				} else {
					item.State = SignalUnknown
					assessment.UnknownCount++
					summary.UnknownSignals++
				}
				assessment.Signals = append(assessment.Signals, item)
			}
			if assessment.EvaluableCount > 0 {
				value := float64(assessment.ObservedCount) * 100 / float64(assessment.EvaluableCount)
				assessment.CoveragePercent = &value
			}
			assessment.EvidenceState, assessment.EvidenceCompleteness = coverageEvidence(assessment.EvaluableCount, assessment.UnknownCount)
			switch {
			case assessment.MissingCount > 0:
				assessment.State = AssessmentMissing
				summary.MissingCount++
			case assessment.UnknownCount > 0:
				assessment.State = AssessmentUnknown
				summary.UnknownCount++
			default:
				summary.CompliantCount++
			}
			summary.Assessments = append(summary.Assessments, assessment)
		}
	}
	summary.ServiceCount = len(serviceSeen)
	summary.InferredServiceCount = len(inferredServiceSeen)
	summary.AssessmentCount = len(summary.Assessments)
	if summary.EvaluableSignals > 0 {
		value := float64(summary.ObservedSignals) * 100 / float64(summary.EvaluableSignals)
		summary.CoveragePercent = &value
	}
	summary.EvidenceState, summary.EvidenceCompleteness = coverageEvidence(summary.EvaluableSignals, summary.UnknownSignals)
	sort.Slice(summary.Assessments, func(i, j int) bool {
		left, right := summary.Assessments[i], summary.Assessments[j]
		if assessmentPriority(left.State) != assessmentPriority(right.State) {
			return assessmentPriority(left.State) < assessmentPriority(right.State)
		}
		if left.ServiceName != right.ServiceName {
			return left.ServiceName < right.ServiceName
		}
		return left.ExpectationID < right.ExpectationID
	})
	return summary
}

func coverageEvidence(evaluable, unknown int) (EvidenceState, *float64) {
	total := evaluable + unknown
	if total == 0 {
		return EvidenceNotApplicable, nil
	}
	value := float64(evaluable) * 100 / float64(total)
	switch {
	case evaluable == 0:
		return EvidenceUnavailable, &value
	case unknown > 0:
		return EvidencePartial, &value
	default:
		return EvidenceComplete, &value
	}
}

func validSignal(signal model.CoverageSignal) bool {
	for _, candidate := range signalOrder {
		if signal == candidate {
			return true
		}
	}
	return false
}

func availableSignals(resources []model.Resource) map[model.CoverageSignal]bool {
	result := map[model.CoverageSignal]bool{}
	for _, resource := range resources {
		if resource.Status != model.ResourceStatusActive {
			continue
		}
		if signal := resourceSignal(resource); signal != "" {
			result[signal] = true
		}
	}
	return result
}

func resourceSignal(resource model.Resource) model.CoverageSignal {
	switch resource.Type {
	case model.ResourceTypeMetric, model.ResourceTypeRecordingRule, model.ResourceTypeTarget, model.ResourceTypeJob, model.ResourceTypeExporter:
		return model.CoverageSignalMetrics
	case model.ResourceTypeDashboard, model.ResourceTypePanel:
		return model.CoverageSignalDashboards
	case model.ResourceTypeAlert:
		return model.CoverageSignalAlerts
	case model.ResourceTypeAlertRule:
		if !strings.EqualFold(resource.Metadata["disabled"], "true") && !strings.EqualFold(resource.Metadata["enabled"], "false") {
			return model.CoverageSignalAlerts
		}
	case model.ResourceTypeLogStream:
		return model.CoverageSignalLogs
	case model.ResourceTypeTraceService, model.ResourceTypeTraceOperation:
		return model.CoverageSignalTraces
	case model.ResourceTypeProfileService:
		return model.CoverageSignalProfiles
	}
	return ""
}

func serviceRelatedResources(serviceID string, resourceGraph *graph.Graph) []model.Resource {
	if resourceGraph == nil {
		return nil
	}
	seen := map[string]bool{}
	result := []model.Resource{}
	add := func(id string) bool {
		if id == serviceID || seen[id] {
			return false
		}
		resource, ok := resourceGraph.Resource(id)
		if !ok || resource.Status != model.ResourceStatusActive {
			return false
		}
		seen[id] = true
		result = append(result, resource)
		return true
	}

	// Ownership may be nested, for example Target -> Job -> Service.
	ownershipQueue := []string{serviceID}
	for len(ownershipQueue) > 0 {
		id := ownershipQueue[0]
		ownershipQueue = ownershipQueue[1:]
		for _, relationship := range resourceGraph.Incoming(id) {
			if relationship.Type == model.RelationshipBelongsTo && add(relationship.FromID) {
				ownershipQueue = append(ownershipQueue, relationship.FromID)
			}
		}
	}

	// Follow production only in its declared direction. This includes metrics
	// emitted by an owned Target or recording rule without traversing through a
	// shared dashboard into every other metric that dashboard happens to use.
	productionQueue := make([]string, 0, len(result))
	for _, resource := range result {
		productionQueue = append(productionQueue, resource.ID)
	}
	for len(productionQueue) > 0 {
		id := productionQueue[0]
		productionQueue = productionQueue[1:]
		for _, relationship := range resourceGraph.Outgoing(id) {
			if relationship.Type == model.RelationshipProduces && add(relationship.ToID) {
				productionQueue = append(productionQueue, relationship.ToID)
			}
		}
	}

	// A dashboard, panel, or alert that consumes scoped evidence is relevant,
	// but it is a terminal consumer. Do not enqueue it and fan back out through
	// its other USES edges.
	evidenceIDs := make([]string, 0, len(result))
	for _, resource := range result {
		evidenceIDs = append(evidenceIDs, resource.ID)
	}
	for _, id := range evidenceIDs {
		for _, relationship := range resourceGraph.Incoming(id) {
			switch relationship.Type {
			case model.RelationshipUses, model.RelationshipReferences, model.RelationshipProduces:
				add(relationship.FromID)
			}
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

// RelatedResourcesForService returns the active evidence resources used to
// assess one Service. Callers must still bound any identifiers they disclose.
func RelatedResourcesForService(serviceID string, resourceGraph *graph.Graph) []model.Resource {
	return serviceRelatedResources(strings.TrimSpace(serviceID), resourceGraph)
}

// RelatedServiceIDs returns active Services whose coverage evidence graph
// contains resourceID.
func RelatedServiceIDs(resourceID string, resourceGraph *graph.Graph) []string {
	resourceID = strings.TrimSpace(resourceID)
	if resourceID == "" || resourceGraph == nil {
		return nil
	}
	result := []string{}
	for _, resource := range resourceGraph.Resources() {
		if resource.Type != model.ResourceTypeService || resource.Status != model.ResourceStatusActive {
			continue
		}
		for _, related := range serviceRelatedResources(resource.ID, resourceGraph) {
			if related.ID == resourceID {
				result = append(result, resource.ID)
				break
			}
		}
	}
	sort.Strings(result)
	return result
}

func orderedSignalSet(values map[model.CoverageSignal]bool) []model.CoverageSignal {
	result := []model.CoverageSignal{}
	for _, signal := range signalOrder {
		if values[signal] {
			result = append(result, signal)
		}
	}
	return result
}

func exceptionKey(expectationID, serviceID string, signal model.CoverageSignal) string {
	return expectationID + "\x00" + serviceID + "\x00" + string(signal)
}

func assessmentPriority(state AssessmentState) int {
	switch state {
	case AssessmentMissing:
		return 0
	case AssessmentUnknown:
		return 1
	default:
		return 2
	}
}
