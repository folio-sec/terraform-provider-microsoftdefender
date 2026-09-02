package equal

import "testing"

func TestOptionalString(t *testing.T) {
	t.Parallel()
	value := "value"
	same := "value"
	different := "different"
	for name, test := range map[string]struct {
		left  *string
		right *string
		want  bool
	}{
		"both absent":     {want: true},
		"left absent":     {right: &value},
		"right absent":    {left: &value},
		"same value":      {left: &value, right: &same, want: true},
		"different value": {left: &value, right: &different},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := OptionalString(test.left, test.right); got != test.want {
				t.Fatalf("OptionalString() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestOptionalRFC3339Time(t *testing.T) {
	t.Parallel()
	utc := "2026-09-01T12:00:00Z"
	offset := "2026-09-01T21:00:00+09:00"
	different := "2026-09-01T12:00:01Z"
	invalid := "invalid"
	invalidCopy := "invalid"
	if !OptionalRFC3339Time(&utc, &offset) {
		t.Fatal("equivalent instants differ")
	}
	if OptionalRFC3339Time(&utc, &different) {
		t.Fatal("different instants compare equal")
	}
	if !OptionalRFC3339Time(&invalid, &invalidCopy) {
		t.Fatal("identical invalid values differ")
	}
}

func TestStringSet(t *testing.T) {
	t.Parallel()
	if !StringSet([]string{"second", "first"}, []string{"first", "second"}) {
		t.Fatal("order affected set equality")
	}
	if StringSet([]string{"first"}, []string{"second"}) {
		t.Fatal("different sets compare equal")
	}
	if StringSet([]string{"first"}, []string{"first", "second"}) {
		t.Fatal("different lengths compare equal")
	}
}
