package store

import (
	"testing"
	"time"
)

func TestSessionValid(t *testing.T) {
	grace := 30 * time.Second
	now := time.Unix(1_700_000_000, 0)

	cases := []struct {
		name   string
		expiry time.Time
		now    time.Time
		want   bool
	}{
		{"fresh exactly at grace", now.Add(grace), now, true},
		{"fresh mid-window", now.Add(15 * time.Second), now, true},
		{"fresh one second in", now.Add(1 * time.Second), now, true},
		{"exact expiry is expired", now, now, false},
		{"expired in the past", now.Add(-time.Second), now, false},
		{"forged far-future expiry", now.Add(time.Hour), now, false},
		{"one nanosecond over grace", now.Add(grace + time.Nanosecond), now, false},
		{"clock moved backwards (expiry > now+grace)", now.Add(2 * grace), now, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sessionValid(tc.expiry, tc.now, grace); got != tc.want {
				t.Errorf("sessionValid(expiry=%v, now=%v, grace=%v) = %v, want %v",
					tc.expiry, tc.now, grace, got, tc.want)
			}
		})
	}
}
