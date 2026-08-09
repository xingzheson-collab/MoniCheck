package rule

import (
	"reflect"

	"monicheck/internal/model"
)

type DiffStatus string

const (
	DiffAdded     DiffStatus = "ADDED"
	DiffRemoved   DiffStatus = "REMOVED"
	DiffChanged   DiffStatus = "CHANGED"
	DiffUnchanged DiffStatus = "UNCHANGED"
)

type DiffItem struct {
	ID     string     `json:"id"`
	Status DiffStatus `json:"status"`
	Before *Rule      `json:"before,omitempty"`
	After  *Rule      `json:"after,omitempty"`
}

type DiffResult struct {
	Items     []DiffItem         `json:"items"`
	Summary   map[DiffStatus]int `json:"summary"`
	Changed   bool               `json:"changed"`
	RuleCount int                `json:"rule_count"`
}

func Diff(before []Rule, after []Rule) DiffResult {
	beforeByID := make(map[string]Rule, len(before))
	afterByID := make(map[string]Rule, len(after))
	ids := make([]string, 0, len(before)+len(after))
	seen := make(map[string]bool)
	for _, item := range before {
		beforeByID[item.ID] = item
		if !seen[item.ID] {
			ids = append(ids, item.ID)
			seen[item.ID] = true
		}
	}
	for _, item := range after {
		afterByID[item.ID] = item
		if !seen[item.ID] {
			ids = append(ids, item.ID)
			seen[item.ID] = true
		}
	}

	result := DiffResult{
		Items:     make([]DiffItem, 0, len(ids)),
		Summary:   map[DiffStatus]int{},
		RuleCount: len(after),
	}
	for _, id := range ids {
		beforeRule, hadBefore := beforeByID[id]
		afterRule, hasAfter := afterByID[id]
		item := DiffItem{ID: id}
		switch {
		case !hadBefore && hasAfter:
			item.Status = DiffAdded
			item.After = copyRule(afterRule)
		case hadBefore && !hasAfter:
			item.Status = DiffRemoved
			item.Before = copyRule(beforeRule)
		case !reflect.DeepEqual(beforeRule, afterRule):
			item.Status = DiffChanged
			item.Before = copyRule(beforeRule)
			item.After = copyRule(afterRule)
		default:
			item.Status = DiffUnchanged
			item.Before = copyRule(beforeRule)
			item.After = copyRule(afterRule)
		}
		if item.Status != DiffUnchanged {
			result.Changed = true
		}
		result.Summary[item.Status]++
		result.Items = append(result.Items, item)
	}
	return result
}

func copyRule(item Rule) *Rule {
	copied := item
	copied.Scope = append([]model.ResourceType(nil), item.Scope...)
	if item.Metadata != nil {
		copied.Metadata = make(map[string]string, len(item.Metadata))
		for key, value := range item.Metadata {
			copied.Metadata[key] = value
		}
	}
	return &copied
}
