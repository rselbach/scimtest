package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"unicode"
)

func canonicalFold(value rune) rune {
	if unicode.SimpleFold(value) == value {
		return value
	}
	canonical := rune(unicode.MaxRune)
	for candidate := value; ; {
		lower := unicode.ToLower(candidate)
		if strings.EqualFold(string(value), string(lower)) && lower < canonical {
			canonical = lower
		}
		candidate = unicode.SimpleFold(candidate)
		if candidate == value {
			return canonical
		}
	}
}

func casefoldTable() error {
	mapping := make(map[rune]rune)
	for value := rune(0); value <= unicode.MaxRune; value++ {
		if value >= 0xD800 && value <= 0xDFFF {
			continue
		}
		if canonical := canonicalFold(value); canonical != unicode.ToLower(value) {
			mapping[value] = canonical
		}
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"unicode_version": unicode.Version, "mapping": mapping})
}

func checkCasefold() error {
	var input struct {
		Folded  string `json:"folded"`
		Lowered string `json:"lowered"`
	}
	if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil {
		return err
	}
	values := []rune(input.Folded)
	lowered := []rune(input.Lowered)
	if len(values) != unicode.MaxRune+1-0x800 || len(values) != len(lowered) {
		return fmt.Errorf("casefold check needs every Unicode scalar value")
	}
	index := func(value rune) int {
		if value > 0xDFFF {
			return int(value - 0x800)
		}
		return int(value)
	}
	mismatches := make([]rune, 0)
	lowerMismatches := make([]rune, 0)
	for value := rune(0); value <= unicode.MaxRune; value++ {
		if value >= 0xD800 && value <= 0xDFFF {
			continue
		}
		folded := values[index(value)]
		if lowered[index(value)] != unicode.ToLower(value) {
			lowerMismatches = append(lowerMismatches, value)
		}
		if folded != values[index(unicode.SimpleFold(value))] || !strings.EqualFold(string(value), string(folded)) {
			mismatches = append(mismatches, value)
		}
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"unicode_version": unicode.Version, "checked": len(values), "mismatches": mismatches, "lower_mismatches": lowerMismatches})
}
