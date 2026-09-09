package policy

// ptr returns a pointer to v, for building CheckConfig literals in tests.
func ptr[T any](v T) *T { return &v }
