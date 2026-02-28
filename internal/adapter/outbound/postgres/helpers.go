package postgres

import (
	"fmt"
	"strings"
)

func formatTextArray(arr []string) string {
	if len(arr) == 0 {
		return "{}"
	}
	var b strings.Builder
	b.WriteString(`{`)
	for i, s := range arr {
		if i > 0 {
			b.WriteString(`,`)
		}
		b.WriteString(`"`)
		b.WriteString(strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `"`, `""`))
		b.WriteString(`"`)
	}
	b.WriteString(`}`)
	return b.String()
}

func allowedSortColumn(input string, allowed []string, defaultCol string) string {
	for _, a := range allowed {
		if input == a {
			return a
		}
	}
	return defaultCol
}

func placeholder(n int) string {
	return fmt.Sprintf("$%d", n)
}
