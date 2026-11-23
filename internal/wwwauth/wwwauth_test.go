package wwwauth

import "testing"

func TestParseBearer(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want map[string]string
	}{
		{
			name: "nil for non-Bearer",
			in:   `Basic realm="x"`,
			want: nil,
		},
		{
			name: "empty",
			in:   ``,
			want: nil,
		},
		{
			name: "single quoted",
			in:   `Bearer realm="x"`,
			want: map[string]string{"realm": "x"},
		},
		{
			name: "multiple quoted",
			in:   `Bearer realm="x", resource_metadata="https://a/.well-known/oauth-protected-resource", scope="mcp"`,
			want: map[string]string{
				"realm":             "x",
				"resource_metadata": "https://a/.well-known/oauth-protected-resource",
				"scope":             "mcp",
			},
		},
		{
			name: "unquoted",
			in:   `Bearer realm=x, scope=mcp`,
			want: map[string]string{"realm": "x", "scope": "mcp"},
		},
		{
			name: "case-insensitive scheme + extra spaces",
			in:   `bearer  realm = "x" ,  scope = mcp  `,
			want: map[string]string{"realm": "x", "scope": "mcp"},
		},
		{
			name: "escaped quote in value",
			in:   `Bearer realm="he said \"hi\""`,
			want: map[string]string{"realm": `he said "hi"`},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseBearer(tc.in)
			if !mapEqual(got, tc.want) {
				t.Fatalf("ParseBearer(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func mapEqual(a, b map[string]string) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}
