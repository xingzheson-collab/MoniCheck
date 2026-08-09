package connector

import (
	"strconv"
	"strings"

	"monicheck/internal/model"
)

func setQueryMetadata(metadata map[string]string, key string, query string) {
	query = strings.TrimSpace(query)
	if query == "" {
		return
	}
	metadata[key] = query
	metadata[model.MetadataQueryLength] = strconv.Itoa(len(query))
}
