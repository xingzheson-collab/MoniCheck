package contract

import (
	"fmt"
	"strings"

	"monicheck/internal/connector"
	"monicheck/internal/model"
)

const (
	DiagnosticIDSnapshot = "data_flow_contract"
)

type Violation struct {
	Code    string `json:"code"`
	Entity  string `json:"entity"`
	Field   string `json:"field,omitempty"`
	Message string `json:"message"`
}

type ValidationResult struct {
	Valid      bool        `json:"valid"`
	Violations []Violation `json:"violations,omitempty"`
}

func ValidateSnapshot(snapshot connector.Snapshot) ValidationResult {
	result := ValidationResult{Valid: true}
	resourceIDs := map[string]bool{}
	relationshipIDs := map[string]bool{}

	validateResource := func(resource model.Resource, entity string) {
		if strings.TrimSpace(resource.ID) == "" {
			result.add("MissingField", entity, "id", "resource id is required")
		}
		if resourceIDs[resource.ID] {
			result.add("DuplicateID", entity, "id", "resource id must be unique within connector snapshot")
		}
		resourceIDs[resource.ID] = true
		if resource.Type == "" {
			result.add("MissingField", entity, "type", "resource type is required")
		}
		if strings.TrimSpace(resource.Name) == "" {
			result.add("MissingField", entity, "name", "resource name is required")
		}
		if strings.TrimSpace(resource.UID) == "" {
			result.add("MissingField", entity, "uid", "resource uid is required")
		}
		if strings.TrimSpace(resource.Source.System) == "" {
			result.add("MissingField", entity, "source.system", "resource source system is required")
		}
		if strings.TrimSpace(resource.Source.ExternalID) == "" {
			result.add("MissingField", entity, "source.external_id", "resource source external_id is required")
		}
		if resource.Status == "" {
			result.add("MissingField", entity, "status", "resource status is required")
		}
	}
	for index, resource := range snapshot.Resources {
		validateResource(resource, fmt.Sprintf("resources[%d]", index))
	}
	for index, resource := range snapshot.References {
		validateResource(resource, fmt.Sprintf("references[%d]", index))
	}

	for index, relationship := range snapshot.Relationships {
		entity := fmt.Sprintf("relationships[%d]", index)
		if strings.TrimSpace(relationship.ID) == "" {
			result.add("MissingField", entity, "id", "relationship id is required")
		}
		if relationshipIDs[relationship.ID] {
			result.add("DuplicateID", entity, "id", "relationship id must be unique within connector snapshot")
		}
		relationshipIDs[relationship.ID] = true
		if strings.TrimSpace(relationship.FromID) == "" {
			result.add("MissingField", entity, "from_id", "relationship from_id is required")
		} else if !resourceIDs[relationship.FromID] {
			result.add("InvalidReference", entity, "from_id", "relationship from_id must reference a resource in the same snapshot")
		}
		if strings.TrimSpace(relationship.ToID) == "" {
			result.add("MissingField", entity, "to_id", "relationship to_id is required")
		} else if !resourceIDs[relationship.ToID] {
			result.add("InvalidReference", entity, "to_id", "relationship to_id must reference a resource in the same snapshot")
		}
		if relationship.Type == "" {
			result.add("MissingField", entity, "type", "relationship type is required")
		}
	}

	return result
}

func NormalizeFindings(analyzerID string, findings []model.Finding) []model.Finding {
	normalized := make([]model.Finding, len(findings))
	for index, finding := range findings {
		if finding.Status == "" {
			finding.Status = model.FindingStatusOpen
		}
		if finding.Category == "" {
			finding.Category = model.DefaultFindingCategory(finding.Type, finding.Resource.Type)
		}
		if finding.Metadata == nil {
			finding.Metadata = map[string]string{}
		}
		if strings.TrimSpace(finding.Metadata["analyzer_id"]) == "" && analyzerID != "" {
			finding.Metadata["analyzer_id"] = analyzerID
		}
		if strings.HasPrefix(analyzerID, "builtin.") && analyzerID != "builtin.rule_engine" {
			if strings.TrimSpace(finding.Recommendation) == "" || containsHan(finding.Recommendation) {
				finding.Recommendation = EnglishRecommendation(finding)
				finding.Metadata["recommendation.localized"] = "en"
			}
			if evidenceContainsHan(finding.Evidence) {
				finding.Evidence = EnglishEvidence(finding)
				finding.Metadata["evidence.localized"] = "en"
			}
		}
		normalized[index] = finding
	}
	return normalized
}

func ValidateFindings(findings []model.Finding) ValidationResult {
	result := ValidationResult{Valid: true}
	ids := map[string]bool{}
	for index, finding := range findings {
		entity := fmt.Sprintf("findings[%d]", index)
		if strings.TrimSpace(finding.ID) == "" {
			result.add("MissingField", entity, "id", "finding id is required")
		}
		if ids[finding.ID] {
			result.add("DuplicateID", entity, "id", "finding id must be unique within analyzer output")
		}
		ids[finding.ID] = true
		if strings.TrimSpace(finding.Type) == "" {
			result.add("MissingField", entity, "type", "finding type is required")
		}
		if finding.Severity == "" {
			result.add("MissingField", entity, "severity", "finding severity is required")
		}
		if finding.Category == "" {
			result.add("MissingField", entity, "category", "finding category is required")
		}
		if strings.TrimSpace(finding.Resource.ID) == "" {
			result.add("MissingField", entity, "resource.id", "finding resource id is required")
		}
		if finding.Resource.Type == "" {
			result.add("MissingField", entity, "resource.type", "finding resource type is required")
		}
		if len(finding.Evidence) == 0 {
			result.add("MissingField", entity, "evidence", "finding evidence is required")
		}
		if finding.Status == "" {
			result.add("MissingField", entity, "status", "finding status is required")
		}
		if strings.TrimSpace(finding.Metadata["analyzer_id"]) == "" && strings.TrimSpace(finding.Metadata["rule_id"]) == "" {
			result.add("MissingField", entity, "metadata.analyzer_id", "finding source analyzer_id or rule_id is required")
		}
	}
	return result
}

func SnapshotDiagnostic(result ValidationResult) model.Diagnostic {
	status := model.ExecutionStatusSucceeded
	message := "Connector snapshot satisfies data-flow contract"
	if !result.Valid {
		status = model.ExecutionStatusFailed
		message = fmt.Sprintf("Connector snapshot has %d data-flow contract violations", len(result.Violations))
	}
	return model.Diagnostic{
		ID:       DiagnosticIDSnapshot,
		Name:     "Data-flow contract",
		Status:   status,
		Message:  message,
		Metadata: violationMetadata(result),
	}
}

func (r *ValidationResult) add(code string, entity string, field string, message string) {
	r.Valid = false
	r.Violations = append(r.Violations, Violation{
		Code:    code,
		Entity:  entity,
		Field:   field,
		Message: message,
	})
}

func violationMetadata(result ValidationResult) map[string]string {
	metadata := map[string]string{"valid": fmt.Sprintf("%t", result.Valid)}
	if len(result.Violations) == 0 {
		return metadata
	}
	metadata["violation_count"] = fmt.Sprintf("%d", len(result.Violations))
	limit := len(result.Violations)
	if limit > 5 {
		limit = 5
	}
	for index := 0; index < limit; index++ {
		violation := result.Violations[index]
		metadata[fmt.Sprintf("violation_%d", index+1)] = violation.Code + " " + violation.Entity + "." + violation.Field
	}
	return metadata
}
