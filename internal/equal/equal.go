package equal

import (
	"slices"
	"time"
)

// OptionalString reports whether two optional strings have the same presence
// and value.
func OptionalString(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

// OptionalRFC3339Time compares valid RFC3339 values as instants. Invalid
// values are compared literally so API responses remain deterministic.
func OptionalRFC3339Time(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	leftTime, leftErr := time.Parse(time.RFC3339, *left)
	rightTime, rightErr := time.Parse(time.RFC3339, *right)
	if leftErr == nil && rightErr == nil {
		return leftTime.Equal(rightTime)
	}
	return *left == *right
}

// StringSet compares string slices without considering element order.
func StringSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	leftCopy := slices.Clone(left)
	rightCopy := slices.Clone(right)
	slices.Sort(leftCopy)
	slices.Sort(rightCopy)
	return slices.Equal(leftCopy, rightCopy)
}
