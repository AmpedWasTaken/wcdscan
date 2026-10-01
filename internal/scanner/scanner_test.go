package scanner

import (
	"testing"

	"github.com/AmpedWasTaken/wcdscan/internal/model"
)

func TestLooksCached(t *testing.T) {
	cases := []struct {
		name string
		r    model.Result
		want bool
	}{
		{"age", model.Result{Age: "10"}, true},
		{"cloudflare", model.Result{CFCacheStatus: "HIT"}, true},
		{"miss", model.Result{CFCacheStatus: "MISS"}, false},
		{"empty", model.Result{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := looksCached(tc.r); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestUniqueStrings(t *testing.T) {
	got := uniqueStrings([]string{"b", "a", "b"})
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("unexpected: %#v", got)
	}
}
