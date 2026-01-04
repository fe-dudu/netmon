package utils

import "strings"

func SanitizeForDisplay(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '[':
			b.WriteString("[[")
			continue
		case ']':
			b.WriteString("]]")
			continue
		}
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

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
