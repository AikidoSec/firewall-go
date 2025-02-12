package helpers

import (
	"regexp"
	"strings"
)

const MinimumLength = 10

var (
	LOWERCASE             = "abcdefghijklmnopqrstuvwxyz"
	UPPERCASE             = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	NUMBERS               = "0123456789"
	SPECIAL               = "!#$%^&*|;:<>"
	KNOWN_WORD_SEPARATORS = []string{"-"}
	WHITE_SPACE           = regexp.MustCompile(`\s+`)
)

func LooksLikeASecret(str string) bool {
	if len(str) <= MinimumLength {
		return false
	}

	hasNumber := containsAny(str, NUMBERS)
	if !hasNumber {
		return false
	}

	hasLower := containsAny(str, LOWERCASE)
	hasUpper := containsAny(str, UPPERCASE)
	hasSpecial := containsAny(str, SPECIAL)
	charsets := []bool{hasLower, hasUpper, hasSpecial}

	// If the string doesn't have at least 2 different charsets, it's not a secret
	if !hasAtLeastTwoTrue(charsets) {
		return false
	}

	// If the string has white space, it's not a secret
	if WHITE_SPACE.MatchString(str) {
		return false
	}

	for _, separator := range KNOWN_WORD_SEPARATORS {
		if strings.Contains(str, separator) {
			return false
		}
	}

	// Check uniqueness of characters in a window of 10 characters
	windowSize := MinimumLength
	var ratios []float64
	for i := 0; i <= len(str)-windowSize; i++ {
		window := str[i : i+windowSize]
		uniqueChars := make(map[rune]struct{})
		for _, char := range window {
			uniqueChars[char] = struct{}{}
		}
		ratios = append(ratios, float64(len(uniqueChars))/float64(windowSize))
	}

	averageRatio := calculateAverage(ratios)

	return averageRatio > 0.75
}

func containsAny(str, chars string) bool {
	for _, char := range chars {
		if strings.ContainsRune(str, char) {
			return true
		}
	}
	return false
}

func hasAtLeastTwoTrue(charsets []bool) bool {
	count := 0
	for _, charset := range charsets {
		if charset {
			count++
		}
	}
	return count >= 2
}

func calculateAverage(ratios []float64) float64 {
	if len(ratios) == 0 {
		return 0
	}
	sum := 0.0
	for _, ratio := range ratios {
		sum += ratio
	}
	return sum / float64(len(ratios))
}
