// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_appconnectors

package ipnlocal

import (
	"time"

	"tailscale.com/appc"
	"tailscale.com/envknob"
	"tailscale.com/types/appctype"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus"
)

// defaultAppcRouteMinAge and defaultAppcRouteMaxAge bound how long an app
// connector keeps advertising a route it discovered by observing DNS, after a
// configured domain was last seen resolving to that address. Within those
// bounds the connector scales the retention with the TTL of the records it
// learned the address from.
//
// Without an upper bound the discovered routes only ever grow: domains behind
// a CDN rotate through edge addresses, and every address a domain ever
// resolved to stays advertised for the lifetime of the node. That inflates the
// route table, and once an address is reassigned elsewhere it sends unrelated
// traffic through the connector. See
// https://github.com/tailscale/tailscale/issues/19295.
//
// The minimum keeps a route from being withdrawn between two ordinary uses of
// a service, which would leave the next client waiting for it to be advertised
// and propagated again, so it wants to be comfortably longer than the gaps in
// a working day.
const (
	defaultAppcRouteMinAge = 6 * time.Hour
	defaultAppcRouteMaxAge = 7 * 24 * time.Hour
)

// appcRouteMinAge and appcRouteMaxAge override the defaults above. A negative
// TS_APPC_ROUTE_MAX_AGE disables expiry entirely, keeping the older behavior
// of advertising a discovered route until its domain is unconfigured. There is
// no such escape hatch for the minimum: a zero floor would expire an address
// learned from a TTL-0 answer the instant it was recorded, so a negative value
// falls back to defaultAppcRouteMinAge.
var (
	appcRouteMinAge = envknob.RegisterDuration("TS_APPC_ROUTE_MIN_AGE")
	appcRouteMaxAge = envknob.RegisterDuration("TS_APPC_ROUTE_MAX_AGE")
)

// appcAppConnector is [appc.AppConnector] in builds that include app
// connectors. Builds with ts_omit_appconnectors substitute a stub type
// (see appconnector_omit.go) so that this package does not import appc
// at all, which keeps appc and its dependencies out of those binaries.
type appcAppConnector = appc.AppConnector

// newAppConnector returns a new [appc.AppConnector] publishing to bus,
// seeded with the previously stored routes in ri (which may be nil).
func newAppConnector(logf logger.Logf, bus *eventbus.Bus, ri *appctype.RouteInfo, storeRoutes bool) *appcAppConnector {
	return appc.NewAppConnector(appc.Config{
		Logf:            logf,
		EventBus:        bus,
		RouteInfo:       ri,
		HasStoredRoutes: storeRoutes,
		RouteMinAge:     appcRouteAgeFor(max(appcRouteMinAge(), 0), defaultAppcRouteMinAge, storeRoutes),
		RouteMaxAge:     appcRouteAgeFor(appcRouteMaxAge(), defaultAppcRouteMaxAge, storeRoutes),
	})
}

// appcRouteAgeFor returns the route retention bound to use for a connector
// that does or doesn't persist its route info, given the env knob value env
// and the default def.
func appcRouteAgeFor(env, def time.Duration, storeRoutes bool) time.Duration {
	if !storeRoutes {
		// Without persisted route info, a restarted connector can't tell which
		// of the routes it already advertises it learned from DNS, so it would
		// never expire those anyway. Leave expiry off rather than apply it to
		// only part of the route set.
		return 0
	}
	switch {
	case env > 0:
		return env
	case env < 0:
		return 0
	default:
		return def
	}
}

// AppConnector returns the current AppConnector, or nil if not configured.
//
// TODO(nickkhyl): move app connectors to [nodeBackend], or perhaps a feature package?
func (b *LocalBackend) AppConnector() *appc.AppConnector {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.appConnector
}
