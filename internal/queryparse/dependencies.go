package queryparse

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

type LogStream struct {
	Fingerprint  string
	MatcherCount int
	LabelCount   int
}

func LogStreams(query string) ([]LogStream, error) {
	selectors, err := bracedSelectors(query)
	if err != nil {
		return nil, err
	}
	byFingerprint := map[string]LogStream{}
	for _, selector := range selectors {
		labels := map[string]bool{}
		matcherCount := 0
		body := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(selector, "{"), "}"))
		if body != "" {
			for _, matcher := range splitQuoted(body, ',') {
				matcher = strings.TrimSpace(matcher)
				if matcher == "" {
					continue
				}
				name, ok := matcherName(matcher)
				if !ok {
					return nil, fmt.Errorf("invalid LogQL stream matcher %q", matcher)
				}
				matcherCount++
				labels[name] = true
			}
		}
		sum := sha256.Sum256([]byte(selector))
		fingerprint := hex.EncodeToString(sum[:16])
		byFingerprint[fingerprint] = LogStream{
			Fingerprint:  fingerprint,
			MatcherCount: matcherCount,
			LabelCount:   len(labels),
		}
	}
	result := make([]LogStream, 0, len(byFingerprint))
	for _, dependency := range byFingerprint {
		result = append(result, dependency)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Fingerprint < result[j].Fingerprint
	})
	return result, nil
}

func TraceServices(query string) ([]string, error) {
	selectors, err := bracedSelectors(query)
	if err != nil {
		return nil, err
	}
	services := map[string]bool{}
	for _, selector := range selectors {
		tokens, err := traceTokens(strings.TrimSuffix(strings.TrimPrefix(selector, "{"), "}"))
		if err != nil {
			return nil, err
		}
		for index := 0; index+2 < len(tokens); index++ {
			name := normalizeTraceServiceAttribute(tokens[index].text)
			if name == "" || tokens[index+1].text != "=" || tokens[index+2].kind != tokenString {
				continue
			}
			service := strings.TrimSpace(tokens[index+2].text)
			if service == "" || strings.Contains(service, "$") {
				continue
			}
			services[service] = true
		}
	}
	result := make([]string, 0, len(services))
	for service := range services {
		result = append(result, service)
	}
	sort.Strings(result)
	return result, nil
}

func SQLTables(query string) ([]string, error) {
	tokens, err := sqlTokens(query)
	if err != nil {
		return nil, err
	}
	ctes := sqlCTENames(tokens)
	tables := map[string]bool{}
	for index := 0; index < len(tokens); index++ {
		if tokens[index].kind != tokenWord {
			continue
		}
		keyword := strings.ToUpper(tokens[index].text)
		if keyword != "FROM" && keyword != "JOIN" && keyword != "UPDATE" && keyword != "INTO" {
			continue
		}
		candidate, next := sqlQualifiedIdentifier(tokens, index+1)
		if candidate == "" {
			continue
		}
		if next < len(tokens) && tokens[next].text == "(" {
			continue
		}
		if strings.Contains(candidate, "$") || ctes[strings.ToLower(candidate)] {
			continue
		}
		tables[candidate] = true
	}
	result := make([]string, 0, len(tables))
	for table := range tables {
		result = append(result, table)
	}
	sort.Strings(result)
	return result, nil
}

func NRQLTopLevelScope(query string) (bool, bool, error) {
	tokens, err := sqlTokens(query)
	if err != nil {
		return false, false, err
	}
	depth := 0
	seenSelect := false
	seenFrom := false
	nestedSource := false
	scopeClause := false
	for index, item := range tokens {
		switch item.text {
		case "(":
			depth++
			continue
		case ")":
			depth--
			if depth < 0 {
				return false, false, fmt.Errorf("unbalanced NRQL parentheses")
			}
			continue
		}
		if depth != 0 || item.kind != tokenWord || item.quoted {
			continue
		}
		switch strings.ToUpper(item.text) {
		case "SELECT":
			seenSelect = true
		case "FROM":
			seenFrom = true
			if index+1 < len(tokens) && tokens[index+1].text == "(" {
				nestedSource = true
			}
		case "WHERE", "FACET":
			if seenFrom {
				scopeClause = true
			}
		}
	}
	if depth != 0 {
		return false, false, fmt.Errorf("unbalanced NRQL parentheses")
	}
	if !seenSelect || !seenFrom || nestedSource {
		return false, false, nil
	}
	return true, scopeClause, nil
}

// NRQLAlertCompatibility reports whether a simple NRQL query can be
// evaluated and how many top-level clauses are incompatible with streaming
// alert conditions. It deliberately returns only structural facts so callers
// do not need to persist the query text.
func NRQLAlertCompatibility(query string) (bool, int, error) {
	tokens, err := sqlTokens(query)
	if err != nil {
		return false, 0, err
	}
	depth := 0
	seenSelect := false
	seenFrom := false
	nestedSource := false
	incompatibleClauseCount := 0
	for index, item := range tokens {
		switch item.text {
		case "(":
			depth++
			continue
		case ")":
			depth--
			if depth < 0 {
				return false, 0, fmt.Errorf("unbalanced NRQL parentheses")
			}
			continue
		}
		if depth != 0 || item.kind != tokenWord || item.quoted {
			continue
		}
		keyword := strings.ToUpper(item.text)
		switch keyword {
		case "SELECT":
			seenSelect = true
		case "FROM":
			seenFrom = true
			if index+1 < len(tokens) && tokens[index+1].text == "(" {
				nestedSource = true
			}
		}
		if !seenFrom || nrqlTopLevelSourceName(tokens, index) {
			continue
		}
		switch keyword {
		case "SINCE", "UNTIL", "TIMESERIES", "LIMIT":
			incompatibleClauseCount++
		case "COMPARE":
			if nextTopLevelWord(tokens, index) == "WITH" {
				incompatibleClauseCount++
			}
		case "SLIDE":
			if nextTopLevelWord(tokens, index) == "BY" {
				incompatibleClauseCount++
			}
		}
	}
	if depth != 0 {
		return false, 0, fmt.Errorf("unbalanced NRQL parentheses")
	}
	if !seenSelect || !seenFrom || nestedSource {
		return false, 0, nil
	}
	return true, incompatibleClauseCount, nil
}

func nrqlTopLevelSourceName(tokens []token, index int) bool {
	sawComma := false
	for previous := index - 1; previous >= 0; previous-- {
		item := tokens[previous]
		if item.text == "," {
			sawComma = true
			continue
		}
		if item.kind != tokenWord || item.quoted {
			return false
		}
		keyword := strings.ToUpper(item.text)
		if keyword == "FROM" {
			return true
		}
		if !sawComma {
			return false
		}
		switch keyword {
		case "WHERE", "FACET", "SINCE", "UNTIL", "TIMESERIES", "COMPARE", "LIMIT", "SLIDE":
			return false
		}
	}
	return false
}

func nextTopLevelWord(tokens []token, index int) string {
	if index+1 < len(tokens) &&
		tokens[index+1].kind == tokenWord &&
		!tokens[index+1].quoted {
		return strings.ToUpper(tokens[index+1].text)
	}
	return ""
}

func bracedSelectors(query string) ([]string, error) {
	selectors := make([]string, 0)
	inQuote := false
	escaped := false
	for index := 0; index < len(query); index++ {
		ch := query[index]
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' && inQuote {
			escaped = true
			continue
		}
		if ch == '"' {
			inQuote = !inQuote
			continue
		}
		if ch != '{' || inQuote {
			continue
		}
		end := selectorEnd(query, index+1)
		if end < 0 {
			return nil, fmt.Errorf("unclosed query selector")
		}
		selectors = append(selectors, strings.TrimSpace(query[index:end+1]))
		index = end
	}
	return selectors, nil
}

func selectorEnd(query string, start int) int {
	inQuote := false
	escaped := false
	for index := start; index < len(query); index++ {
		ch := query[index]
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' && inQuote {
			escaped = true
			continue
		}
		if ch == '"' {
			inQuote = !inQuote
			continue
		}
		if ch == '}' && !inQuote {
			return index
		}
	}
	return -1
}

func splitQuoted(value string, separator byte) []string {
	parts := make([]string, 0)
	start := 0
	inQuote := false
	escaped := false
	for index := 0; index < len(value); index++ {
		ch := value[index]
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' && inQuote {
			escaped = true
			continue
		}
		if ch == '"' {
			inQuote = !inQuote
			continue
		}
		if ch == separator && !inQuote {
			parts = append(parts, value[start:index])
			start = index + 1
		}
	}
	return append(parts, value[start:])
}

func matcherName(matcher string) (string, bool) {
	for _, operator := range []string{"!~", "=~", "!=", "="} {
		if index := strings.Index(matcher, operator); index > 0 {
			name := strings.TrimSpace(matcher[:index])
			if validIdentifier(name) {
				return name, true
			}
			return "", false
		}
	}
	return "", false
}

func validIdentifier(value string) bool {
	if value == "" {
		return false
	}
	for index, ch := range value {
		if unicode.IsLetter(ch) || ch == '_' || (index > 0 && unicode.IsDigit(ch)) {
			continue
		}
		return false
	}
	return true
}

type tokenKind uint8

const (
	tokenWord tokenKind = iota
	tokenString
	tokenSymbol
)

type token struct {
	kind   tokenKind
	text   string
	quoted bool
}

func traceTokens(value string) ([]token, error) {
	tokens := make([]token, 0)
	for index := 0; index < len(value); {
		if unicode.IsSpace(rune(value[index])) {
			index++
			continue
		}
		if value[index] == '"' {
			decoded, next, err := quotedValue(value, index, '"')
			if err != nil {
				return nil, err
			}
			tokens = append(tokens, token{kind: tokenString, text: decoded})
			index = next
			continue
		}
		if strings.ContainsRune("=!~<>", rune(value[index])) {
			start := index
			index++
			if index < len(value) && (value[index] == '=' || value[index] == '~') {
				index++
			}
			tokens = append(tokens, token{kind: tokenSymbol, text: value[start:index]})
			continue
		}
		start := index
		for index < len(value) {
			ch := rune(value[index])
			if unicode.IsLetter(ch) || unicode.IsDigit(ch) || strings.ContainsRune("._:-", ch) {
				index++
				continue
			}
			break
		}
		if start == index {
			index++
			continue
		}
		tokens = append(tokens, token{kind: tokenWord, text: value[start:index]})
	}
	return tokens, nil
}

func normalizeTraceServiceAttribute(value string) string {
	value = strings.ToLower(strings.Trim(strings.TrimSpace(value), "."))
	switch value {
	case "service.name", "resource.service.name", "span.resource.service.name":
		return value
	default:
		return ""
	}
}

func sqlTokens(query string) ([]token, error) {
	tokens := make([]token, 0)
	for index := 0; index < len(query); {
		ch := query[index]
		if unicode.IsSpace(rune(ch)) {
			index++
			continue
		}
		if ch == '-' && index+1 < len(query) && query[index+1] == '-' {
			index += 2
			for index < len(query) && query[index] != '\n' {
				index++
			}
			continue
		}
		if ch == '/' && index+1 < len(query) && query[index+1] == '*' {
			end := strings.Index(query[index+2:], "*/")
			if end < 0 {
				return nil, fmt.Errorf("unclosed SQL block comment")
			}
			index += end + 4
			continue
		}
		if ch == '\'' {
			_, next, err := quotedValue(query, index, '\'')
			if err != nil {
				return nil, err
			}
			tokens = append(tokens, token{kind: tokenString})
			index = next
			continue
		}
		if ch == '"' || ch == '`' {
			decoded, next, err := quotedValue(query, index, ch)
			if err != nil {
				return nil, err
			}
			tokens = append(tokens, token{kind: tokenWord, text: decoded, quoted: true})
			index = next
			continue
		}
		if ch == '[' {
			end := strings.IndexByte(query[index+1:], ']')
			if end < 0 {
				return nil, fmt.Errorf("unclosed SQL bracket identifier")
			}
			tokens = append(tokens, token{kind: tokenWord, text: query[index+1 : index+1+end], quoted: true})
			index += end + 2
			continue
		}
		if unicode.IsLetter(rune(ch)) || ch == '_' || ch == '$' {
			start := index
			index++
			for index < len(query) {
				next := rune(query[index])
				if unicode.IsLetter(next) || unicode.IsDigit(next) || strings.ContainsRune("_$-", next) {
					index++
					continue
				}
				break
			}
			tokens = append(tokens, token{kind: tokenWord, text: query[start:index]})
			continue
		}
		tokens = append(tokens, token{kind: tokenSymbol, text: string(ch)})
		index++
	}
	return tokens, nil
}

func quotedValue(value string, start int, quote byte) (string, int, error) {
	for index := start + 1; index < len(value); index++ {
		if value[index] == quote {
			if index+1 < len(value) && value[index+1] == quote {
				index++
				continue
			}
			raw := value[start : index+1]
			if quote == '"' {
				decoded, err := strconv.Unquote(raw)
				if err == nil {
					return decoded, index + 1, nil
				}
			}
			inner := strings.ReplaceAll(raw[1:len(raw)-1], string([]byte{quote, quote}), string(quote))
			return inner, index + 1, nil
		}
		if value[index] == '\\' {
			index++
		}
	}
	return "", 0, fmt.Errorf("unclosed quoted value")
}

func sqlCTENames(tokens []token) map[string]bool {
	result := map[string]bool{}
	if len(tokens) == 0 || !strings.EqualFold(tokens[0].text, "WITH") {
		return result
	}
	index := 1
	if index < len(tokens) && strings.EqualFold(tokens[index].text, "RECURSIVE") {
		index++
	}
	for index < len(tokens) {
		if tokens[index].kind != tokenWord {
			break
		}
		name := strings.ToLower(tokens[index].text)
		index++
		if index < len(tokens) && tokens[index].text == "(" {
			index = matchingParen(tokens, index)
			if index < 0 {
				break
			}
		}
		if index >= len(tokens) || !strings.EqualFold(tokens[index].text, "AS") {
			break
		}
		index++
		if index >= len(tokens) || tokens[index].text != "(" {
			break
		}
		result[name] = true
		index = matchingParen(tokens, index)
		if index < 0 || index >= len(tokens) || tokens[index].text != "," {
			break
		}
		index++
	}
	return result
}

func matchingParen(tokens []token, start int) int {
	depth := 0
	for index := start; index < len(tokens); index++ {
		switch tokens[index].text {
		case "(":
			depth++
		case ")":
			depth--
			if depth == 0 {
				return index + 1
			}
		}
	}
	return -1
}

func sqlQualifiedIdentifier(tokens []token, start int) (string, int) {
	for start < len(tokens) && (strings.EqualFold(tokens[start].text, "ONLY") || strings.EqualFold(tokens[start].text, "LATERAL")) {
		start++
	}
	if start >= len(tokens) || tokens[start].kind != tokenWord {
		return "", start
	}
	parts := []string{tokens[start].text}
	index := start + 1
	for index+1 < len(tokens) && tokens[index].text == "." && tokens[index+1].kind == tokenWord {
		parts = append(parts, tokens[index+1].text)
		index += 2
	}
	return strings.Join(parts, "."), index
}
