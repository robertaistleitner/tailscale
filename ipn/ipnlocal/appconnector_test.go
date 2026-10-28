// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_appconnectors

package ipnlocal

import (
	"testing"
	"time"

	"tailscale.com/envknob"
)

func TestAppcRouteAgeFor(t *testing.T) {
	for _, tt := range []struct {
		name        string
		env         string
		def         time.Duration
		storeRoutes bool
		want        time.Duration
	}{
		{"default", "", defaultAppcRouteMaxAge, true, defaultAppcRouteMaxAge},
		{"override", "1h", defaultAppcRouteMaxAge, true, time.Hour},
		{"disabled by env", "-1s", defaultAppcRouteMaxAge, true, 0},
		// Without stored route info a restarted connector can't tell which of
		// its advertised routes it learned from DNS, so expiry stays off.
		{"no stored routes", "", defaultAppcRouteMaxAge, false, 0},
		{"no stored routes with override", "1h", defaultAppcRouteMaxAge, false, 0},
		{"min age default", "", defaultAppcRouteMinAge, true, defaultAppcRouteMinAge},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(func() { envknob.Setenv("TS_APPC_ROUTE_MAX_AGE", "") })
			envknob.Setenv("TS_APPC_ROUTE_MAX_AGE", tt.env)
			if got := appcRouteAgeFor(appcRouteMaxAge(), tt.def, tt.storeRoutes); got != tt.want {
				t.Errorf("appcRouteAgeFor(%v, %v, %v) with TS_APPC_ROUTE_MAX_AGE=%q = %v, want %v",
					appcRouteMaxAge(), tt.def, tt.storeRoutes, tt.env, got, tt.want)
			}
		})
	}

	if defaultAppcRouteMinAge > defaultAppcRouteMaxAge {
		t.Errorf("defaultAppcRouteMinAge (%v) > defaultAppcRouteMaxAge (%v)",
			defaultAppcRouteMinAge, defaultAppcRouteMaxAge)
	}
}
