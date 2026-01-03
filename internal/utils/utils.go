package utils

import "strings"

func TruncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func PadString(s string, width int) string {
	plainLen := len(StripColorTags(s))
	if plainLen >= width {
		return s
	}
	return s + strings.Repeat(" ", width-plainLen)
}

func StripColorTags(s string) string {
	var result strings.Builder
	inTag := false
	for i := 0; i < len(s); i++ {
		if s[i] == '[' {
			inTag = true
		} else if s[i] == ']' && inTag {
			inTag = false
		} else if !inTag {
			result.WriteByte(s[i])
		}
	}
	return result.String()
}
