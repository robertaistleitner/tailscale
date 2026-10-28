// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package appc implements App Connectors.
// An AppConnector provides DNS domain oriented routing of traffic. An App
// Connector becomes a DNS server for a peer, authoritative for the set of
// configured domains. DNS resolution of the target domain triggers dynamic
// publication of routes to ensure that traffic to the domain is routed through
// the App Connector.
package appc

import (
	"context"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"

	"tailscale.com/syncs"
	"tailscale.com/tstime"
	"tailscale.com/types/appctype"
	"tailscale.com/types/logger"
	"tailscale.com/types/views"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/execqueue"
	"tailscale.com/util/mak"
	"tailscale.com/util/set"
	"tailscale.com/util/slicesx"
)

// rateLogger responds to calls to update by adding a count for the current period and
// calling the callback if any previous period has finished since update was last called
type rateLogger struct {
	interval    time.Duration
	start       time.Time
	periodStart time.Time
	periodCount int64
	now         func() time.Time
	callback    func(int64, time.Time, int64)
}

func (rl *rateLogger) currentIntervalStart(now time.Time) time.Time {
	millisSince := now.Sub(rl.start).Milliseconds() % rl.interval.Milliseconds()
	return now.Add(-(time.Duration(millisSince)) * time.Millisecond)
}

func (rl *rateLogger) update(numRoutes int64) {
	now := rl.now()
	periodEnd := rl.periodStart.Add(rl.interval)
	if periodEnd.Before(now) {
		if rl.periodCount != 0 {
			rl.callback(rl.periodCount, rl.periodStart, numRoutes)
		}
		rl.periodCount = 0
		rl.periodStart = rl.currentIntervalStart(now)
	}
	rl.periodCount++
}

func newRateLogger(now func() time.Time, interval time.Duration, callback func(int64, time.Time, int64)) *rateLogger {
	nowTime := now()
	return &rateLogger{
		callback:    callback,
		now:         now,
		interval:    interval,
		start:       nowTime,
		periodStart: nowTime,
	}
}

// RouteAdvertiser is an interface that allows the AppConnector to advertise
// newly discovered routes that need to be served through the AppConnector.
type RouteAdvertiser interface {
	// AdvertiseRoute adds one or more route advertisements skipping any that
	// are already advertised.
	AdvertiseRoute(...netip.Prefix) error

	// UnadvertiseRoute removes any matching route advertisements.
	UnadvertiseRoute(...netip.Prefix) error
}

var (
	metricStoreRoutesRateBuckets = []int64{1, 2, 3, 4, 5, 10, 100, 1000}
	metricStoreRoutesNBuckets    = []int64{1, 2, 3, 4, 5, 10, 100, 1000, 10000}
	metricStoreRoutesRate        []*clientmetric.Metric
	metricStoreRoutesN           []*clientmetric.Metric
)

func initMetricStoreRoutes() {
	for _, n := range metricStoreRoutesRateBuckets {
		metricStoreRoutesRate = append(metricStoreRoutesRate, clientmetric.NewCounter(fmt.Sprintf("appc_store_routes_rate_%d", n)))
	}
	metricStoreRoutesRate = append(metricStoreRoutesRate, clientmetric.NewCounter("appc_store_routes_rate_over"))
	for _, n := range metricStoreRoutesNBuckets {
		metricStoreRoutesN = append(metricStoreRoutesN, clientmetric.NewCounter(fmt.Sprintf("appc_store_routes_n_routes_%d", n)))
	}
	metricStoreRoutesN = append(metricStoreRoutesN, clientmetric.NewCounter("appc_store_routes_n_routes_over"))
}

func recordMetric(val int64, buckets []int64, metrics []*clientmetric.Metric) {
	if len(buckets) < 1 {
		return
	}
	// finds the first bucket where val <=, or len(buckets) if none match
	// for bucket values of 1, 10, 100; 0-1 goes to [0], 2-10 goes to [1], 11-100 goes to [2], 101+ goes to [3]
	bucket, _ := slices.BinarySearch(buckets, val)
	metrics[bucket].Add(1)
}

func metricStoreRoutes(rate, nRoutes int64) {
	if len(metricStoreRoutesRate) == 0 {
		initMetricStoreRoutes()
	}
	recordMetric(rate, metricStoreRoutesRateBuckets, metricStoreRoutesRate)
	recordMetric(nRoutes, metricStoreRoutesNBuckets, metricStoreRoutesN)
}

// AppConnector is an implementation of an AppConnector that performs
// its function as a subsystem inside of a tailscale node. At the control plane
// side App Connector routing is configured in terms of domains rather than IP
// addresses.
// The AppConnectors responsibility inside tailscaled is to apply the routing
// and domain configuration as supplied in the map response.
// DNS requests for configured domains are observed. If the domains resolve to
// routes not yet served by the AppConnector the local node configuration is
// updated to advertise the new route.
type AppConnector struct {
	// These fields are immutable after initialization.
	logf            logger.Logf
	eventBus        *eventbus.Bus
	routeAdvertiser RouteAdvertiser
	pubClient       *eventbus.Client
	updatePub       *eventbus.Publisher[appctype.RouteUpdate]
	storePub        *eventbus.Publisher[appctype.RouteInfo]

	// hasStoredRoutes records whether the connector was initialized with
	// persisted route information.
	hasStoredRoutes bool

	// clock is the time source used for route expiry.
	clock tstime.Clock

	// routeMinAge and routeMaxAge bound how long a DNS-discovered address is
	// kept after the last time a configured domain was observed resolving to
	// it; see expiryForTTL. A zero routeMaxAge disables expiry, and discovered
	// routes are advertised until their domain is unconfigured.
	routeMinAge, routeMaxAge time.Duration

	// stopExpiry stops the background route expiry loop. It is nil if
	// routeMaxAge is zero.
	stopExpiry context.CancelFunc

	// mu guards the fields that follow
	mu syncs.Mutex

	// domains is a map of lower case domain names with no trailing dot, to an
	// ordered list of resolved IP addresses.
	domains map[string][]netip.Addr

	// controlRoutes is the list of routes that were last supplied by control.
	controlRoutes []netip.Prefix

	// wildcards is the list of domain strings that match subdomains.
	wildcards []string

	// expires records, for each domain in domains, when each of that domain's
	// addresses stops being advertised unless the domain resolves to it again.
	// It is only populated when routeMaxAge is positive, and holds an entry for
	// exactly the addresses recorded in domains.
	expires map[string]map[netip.Addr]time.Time

	// lastExpireScan is when expireRoutes last ran, used to notice that the
	// system clock jumped rather than that time really passed.
	lastExpireScan time.Time

	// queue provides ordering for update operations
	queue execqueue.ExecQueue

	writeRateMinute *rateLogger
	writeRateDay    *rateLogger
}

// Config carries the settings for an [AppConnector].
type Config struct {
	// Logf is the logger to which debug logs from the connector will be sent.
	// It must be non-nil.
	Logf logger.Logf

	// EventBus receives events when the collection of routes maintained by the
	// connector is updated. It must be non-nil.
	EventBus *eventbus.Bus

	// RouteAdvertiser allows the connector to update the set of advertised routes.
	RouteAdvertiser RouteAdvertiser

	// RouteInfo, if non-nil, use used as the initial set of routes for the
	// connector.  If nil, the connector starts empty.
	RouteInfo *appctype.RouteInfo

	// HasStoredRoutes indicates that the connector should assume stored routes.
	HasStoredRoutes bool

	// RouteMinAge and RouteMaxAge bound how long an address discovered by
	// observing DNS responses continues to be advertised after the last time a
	// configured domain was seen resolving to it. Within those bounds the
	// retention is derived from the TTL of the records the address was learned
	// from, so that a domain is given a generous number of chances to resolve
	// to the address again before its route is withdrawn. See expiryForTTL.
	//
	// Once the retention elapses the route is withdrawn, unless some other
	// configured domain still resolves to the same address. If RouteMaxAge is
	// zero, discovered routes never expire and RouteMinAge is ignored.
	RouteMinAge, RouteMaxAge time.Duration

	// Clock, if non-nil, is used instead of the system clock. For tests.
	Clock tstime.Clock
}

// NewAppConnector creates a new AppConnector.
func NewAppConnector(c Config) *AppConnector {
	switch {
	case c.Logf == nil:
		panic("missing logger")
	case c.EventBus == nil:
		panic("missing event bus")
	}
	ec := c.EventBus.Client("appc.AppConnector")

	clock := c.Clock
	if clock == nil {
		clock = tstime.StdClock{}
	}

	ac := &AppConnector{
		logf:            logger.WithPrefix(c.Logf, "appc: "),
		eventBus:        c.EventBus,
		pubClient:       ec,
		updatePub:       eventbus.Publish[appctype.RouteUpdate](ec),
		storePub:        eventbus.Publish[appctype.RouteInfo](ec),
		routeAdvertiser: c.RouteAdvertiser,
		hasStoredRoutes: c.HasStoredRoutes,
		clock:           clock,
		routeMaxAge:     max(c.RouteMaxAge, 0),
	}
	ac.routeMinAge = min(max(c.RouteMinAge, 0), ac.routeMaxAge)
	if c.RouteInfo != nil {
		ac.domains = c.RouteInfo.Domains
		ac.wildcards = c.RouteInfo.Wildcards
		ac.controlRoutes = c.RouteInfo.Control
		ac.expires = c.RouteInfo.Expires
	}
	if ac.routeMaxAge > 0 {
		// Addresses restored from a store written before route expiry existed,
		// or by a connector that had expiry disabled, have no recorded expiry
		// and no remembered TTL. Give them a full RouteMaxAge to be resolved
		// again before being withdrawn; the next resolution replaces that with
		// a TTL-derived expiry.
		ac.seedExpiresLocked()
		ac.lastExpireScan = clock.Now()
	} else {
		// Expiry is off, so the recorded expiries are dead weight; dropping
		// them also keeps them from being persisted back out.
		ac.expires = nil
	}
	ac.writeRateMinute = newRateLogger(time.Now, time.Minute, func(c int64, s time.Time, ln int64) {
		ac.logf("routeInfo write rate: %d in minute starting at %v (%d routes)", c, s, ln)
		metricStoreRoutes(c, ln)
	})
	ac.writeRateDay = newRateLogger(time.Now, 24*time.Hour, func(c int64, s time.Time, ln int64) {
		ac.logf("routeInfo write rate: %d in 24 hours starting at %v (%d routes)", c, s, ln)
	})

	// Started last: expireRoutes reaches the fields above, so they must all be
	// assigned before the loop can run.
	if ac.routeMaxAge > 0 {
		ctx, cancel := context.WithCancel(context.Background())
		ac.stopExpiry = cancel
		go ac.expireLoop(ctx)
	}
	return ac
}

// ShouldStoreRoutes returns true if the appconnector was created with the controlknob on
// and is storing its discovered routes persistently.
func (e *AppConnector) ShouldStoreRoutes() bool { return e.hasStoredRoutes }

// storeRoutesLocked takes the current state of the AppConnector and persists it
func (e *AppConnector) storeRoutesLocked() {
	if e.storePub.ShouldPublish() {
		// log write rate and write size
		numRoutes := int64(len(e.controlRoutes))
		for _, rs := range e.domains {
			numRoutes += int64(len(rs))
		}
		e.writeRateMinute.update(numRoutes)
		e.writeRateDay.update(numRoutes)

		var expires map[string]map[netip.Addr]time.Time
		if len(e.expires) > 0 {
			expires = make(map[string]map[netip.Addr]time.Time, len(e.expires))
			for d, m := range e.expires {
				expires[d] = maps.Clone(m)
			}
		}

		e.storePub.Publish(appctype.RouteInfo{
			// Clone here, as the subscriber will handle these outside our lock.
			Control:   slices.Clone(e.controlRoutes),
			Domains:   maps.Clone(e.domains),
			Wildcards: slices.Clone(e.wildcards),
			Expires:   expires,
		})
	}
}

// ClearRoutes removes all route state from the AppConnector.
func (e *AppConnector) ClearRoutes() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.controlRoutes = nil
	e.domains = nil
	e.wildcards = nil
	e.expires = nil
	e.storeRoutesLocked()
	return nil
}

// UpdateDomainsAndRoutes starts an asynchronous update of the configuration
// given the new domains and routes.
func (e *AppConnector) UpdateDomainsAndRoutes(domains []string, routes []netip.Prefix) {
	e.queue.Add(func() {
		// Add the new routes first.
		e.updateRoutes(routes)
		e.updateDomains(domains)
	})
}

// UpdateDomains asynchronously replaces the current set of configured domains
// with the supplied set of domains. Domains must not contain a trailing dot,
// and should be lower case. If the domain contains a leading '*' label it
// matches all subdomains of a domain.
func (e *AppConnector) UpdateDomains(domains []string) {
	e.queue.Add(func() {
		e.updateDomains(domains)
	})
}

// Wait waits for the currently scheduled asynchronous configuration changes to
// complete.
func (e *AppConnector) Wait(ctx context.Context) {
	e.queue.Wait(ctx)
}

// Close closes the connector and cleans up resources associated with it.
// It is safe (and a noop) to call Close on nil.
func (e *AppConnector) Close() {
	if e == nil {
		return
	}
	if e.stopExpiry != nil {
		e.stopExpiry()
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.queue.Shutdown() // TODO(creachadair): Should we wait for it too?
	e.pubClient.Close()
}

func (e *AppConnector) updateDomains(domains []string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	var oldDomains map[string][]netip.Addr
	oldDomains, e.domains = e.domains, make(map[string][]netip.Addr, len(domains))
	e.wildcards = e.wildcards[:0]
	for _, d := range domains {
		d = strings.ToLower(d)
		if len(d) == 0 {
			continue
		}
		if strings.HasPrefix(d, "*.") {
			e.wildcards = append(e.wildcards, d[2:])
			continue
		}
		e.domains[d] = oldDomains[d]
		delete(oldDomains, d)
	}

	// Ensure that still-live wildcards addresses are preserved as well.
	for d, addrs := range oldDomains {
		for _, wc := range e.wildcards {
			if dnsname.HasSuffix(d, wc) {
				e.domains[d] = addrs
				delete(oldDomains, d)
				break
			}
		}
	}

	// Forget expiries for domains we are no longer tracking.
	for d := range e.expires {
		if _, ok := e.domains[d]; !ok {
			delete(e.expires, d)
		}
	}

	// Everything left in oldDomains is a domain we're no longer tracking and we
	// can unadvertise the routes.
	if e.hasStoredRoutes {
		toRemove := []netip.Prefix{}
		for _, addrs := range oldDomains {
			for _, a := range addrs {
				toRemove = append(toRemove, netip.PrefixFrom(a, a.BitLen()))
			}
		}

		if len(toRemove) != 0 {
			if ra := e.routeAdvertiser; ra != nil {
				e.queue.Add(func() {
					if err := e.routeAdvertiser.UnadvertiseRoute(toRemove...); err != nil {
						e.logf("failed to unadvertise routes on domain removal: %v: %v: %v", slicesx.MapKeys(oldDomains), toRemove, err)
					}
				})
			}
			e.updatePub.Publish(appctype.RouteUpdate{Unadvertise: toRemove})
		}
	}

	e.logf("handling domains: %v and wildcards: %v", slicesx.MapKeys(e.domains), e.wildcards)
}

// updateRoutes merges the supplied routes into the currently configured routes. The routes supplied
// by control for UpdateRoutes are supplemental to the routes discovered by DNS resolution, but are
// also more often whole ranges. UpdateRoutes will remove any single address routes that are now
// covered by new ranges.
func (e *AppConnector) updateRoutes(routes []netip.Prefix) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// If there was no change since the last update, no work to do.
	if slices.Equal(e.controlRoutes, routes) {
		return
	}

	var toRemove []netip.Prefix

	// If we know e.controlRoutes is a good representation of what should be in
	// AdvertisedRoutes we can stop advertising routes that used to be in
	// e.controlRoutes but are not in routes.
	if e.hasStoredRoutes {
		toRemove = routesWithout(e.controlRoutes, routes)
	}

	obsoleted := set.Set[netip.Addr]{}
	for _, r := range routes {
		for _, addr := range e.domains {
			for _, a := range addr {
				if r.Contains(a) && netip.PrefixFrom(a, a.BitLen()) != r {
					obsoleted.Add(a)
				}
			}
		}
	}
	for a := range obsoleted.All() {
		pfx := netip.PrefixFrom(a, a.BitLen())
		toRemove = append(toRemove, pfx)
	}

	if e.routeAdvertiser != nil {
		e.queue.Add(func() {
			if err := e.routeAdvertiser.AdvertiseRoute(routes...); err != nil {
				e.logf("failed to advertise routes: %v: %v", routes, err)
			}
			if err := e.routeAdvertiser.UnadvertiseRoute(toRemove...); err != nil {
				e.logf("failed to unadvertise routes: %v: %v", toRemove, err)
			}
		})
	}
	e.updatePub.Publish(appctype.RouteUpdate{
		Advertise:   routes,
		Unadvertise: toRemove,
	})

	e.controlRoutes = routes
	e.storeRoutesLocked()
}

// Domains returns the currently configured domain list.
func (e *AppConnector) Domains() views.Slice[string] {
	e.mu.Lock()
	defer e.mu.Unlock()

	return views.SliceOf(slicesx.MapKeys(e.domains))
}

// DomainRoutes returns a map of domains to resolved IP
// addresses.
func (e *AppConnector) DomainRoutes() map[string][]netip.Addr {
	e.mu.Lock()
	defer e.mu.Unlock()

	drCopy := make(map[string][]netip.Addr)
	for k, v := range e.domains {
		drCopy[k] = append(drCopy[k], v...)
	}

	return drCopy
}

// starting from the given domain that resolved to an address, find it, or any
// of the domains in the CNAME chain toward resolving it, that are routed
// domains, returning the routed domain name and a bool indicating whether a
// routed domain was found.
// e.mu must be held.
func (e *AppConnector) findRoutedDomainLocked(domain string, cnameChain map[string]string) (string, bool) {
	var isRouted bool
	var seen set.Set[string]
	for {
		_, isRouted = e.domains[domain]
		if isRouted {
			break
		}

		// match wildcard domains
		for _, wc := range e.wildcards {
			if dnsname.HasSuffix(domain, wc) {
				e.domains[domain] = nil
				isRouted = true
				break
			}
		}

		next, ok := cnameChain[domain]
		if !ok {
			break
		}
		if seen.Contains(next) {
			break
		}
		domain = next
		seen.Make()
		seen.Add(domain)
	}
	return domain, isRouted
}

// isAddrKnownLocked returns true if the address is known to be associated with
// the given domain. Known domain tables are updated for covered routes to speed
// up future matches.
// e.mu must be held.
func (e *AppConnector) isAddrKnownLocked(domain string, addr netip.Addr) bool {
	if e.hasDomainAddrLocked(domain, addr) {
		return true
	}
	for _, route := range e.controlRoutes {
		if route.Contains(addr) {
			// record the new address associated with the domain for faster matching in subsequent
			// requests and for diagnostic records.
			e.addDomainAddrLocked(domain, addr)
			return true
		}
	}
	return false
}

// scheduleAdvertisement schedules an advertisement of the given address
// associated with the given domain, learned from records with the given TTL in
// seconds.
func (e *AppConnector) scheduleAdvertisement(domain string, ttl uint32, routes ...netip.Prefix) {
	e.queue.Add(func() {
		if e.routeAdvertiser != nil {
			if err := e.routeAdvertiser.AdvertiseRoute(routes...); err != nil {
				e.logf("failed to advertise routes for %s: %v: %v", domain, routes, err)
				return
			}
		}
		e.updatePub.Publish(appctype.RouteUpdate{Advertise: routes})
		e.mu.Lock()
		defer e.mu.Unlock()

		for _, route := range routes {
			if !route.IsSingleIP() {
				continue
			}
			addr := route.Addr()
			if !e.hasDomainAddrLocked(domain, addr) {
				e.addDomainAddrLocked(domain, addr)
				e.logf("[v2] advertised route for %v: %v", domain, addr)
			}
			e.noteAddrResolvedLocked(domain, addr, ttl)
		}
		e.storeRoutesLocked()
	})
}

// hasDomainAddrLocked returns true if the address has been observed in a
// resolution of domain.
func (e *AppConnector) hasDomainAddrLocked(domain string, addr netip.Addr) bool {
	_, ok := slices.BinarySearchFunc(e.domains[domain], addr, compareAddr)
	return ok
}

// addDomainAddrLocked adds the address to the list of addresses resolved for
// domain and ensures the list remains sorted. Does not attempt to deduplicate.
func (e *AppConnector) addDomainAddrLocked(domain string, addr netip.Addr) {
	e.domains[domain] = append(e.domains[domain], addr)
	slices.SortFunc(e.domains[domain], compareAddr)
}

// ttlExpiryFactor is how many record lifetimes an address is retained for
// after a domain was last seen resolving to it.
//
// A resolver re-queries a domain at most once per TTL, so it's roughly how
// many consecutive resolutions must come back without an address before we
// conclude the domain no longer resolves to it. It's deliberately generous:
// keeping a route a while longer is cheap, but withdrawing one that's still in
// use breaks traffic until the domain is resolved again.
const ttlExpiryFactor = 20

// expiryForTTL returns how long an address learned from a record with the
// given TTL, in seconds, is retained after a domain was last seen resolving to
// it, bounded by routeMinAge and routeMaxAge.
//
// Scaling with the TTL tracks how often we can expect to see the address again
// if it's still live: addresses behind a CDN, whose records expire in a
// minute, are dropped soon after they fall out of rotation, while addresses
// from long-lived records, which clients may only resolve once a week, aren't
// withdrawn out from under them.
func (e *AppConnector) expiryForTTL(ttl uint32) time.Duration {
	// Compute in seconds so that an absurd TTL can't overflow a Duration.
	if secs := int64(ttl) * ttlExpiryFactor; secs < int64(e.routeMaxAge/time.Second) {
		return max(time.Duration(secs)*time.Second, e.routeMinAge)
	}
	return e.routeMaxAge
}

// noteAddrResolvedLocked records that domain was just seen resolving to addr,
// in a record with the given TTL in seconds, and sets when addr expires if
// that doesn't happen again. It is a no-op if route expiry is disabled.
// e.mu must be held.
func (e *AppConnector) noteAddrResolvedLocked(domain string, addr netip.Addr, ttl uint32) {
	if e.routeMaxAge <= 0 {
		return
	}
	m := e.expires[domain]
	if m == nil {
		m = make(map[netip.Addr]time.Time)
		mak.Set(&e.expires, domain, m)
	}
	m[addr] = e.clock.Now().Add(e.expiryForTTL(ttl))
}

// seedExpiresLocked gives each address in domains with no recorded expiry one
// of a full routeMaxAge from now, leaving the recorded ones alone.
// e.mu must be held.
func (e *AppConnector) seedExpiresLocked() { e.setExpiresLocked(false) }

// resetExpiresLocked gives every address in domains a full routeMaxAge from
// now, discarding what was recorded. It is for when the recorded expiries
// can't be trusted, because they were measured against a different clock.
// e.mu must be held.
func (e *AppConnector) resetExpiresLocked() { e.setExpiresLocked(true) }

// setExpiresLocked gives each address in domains a full routeMaxAge from now,
// keeping any already-recorded expiry unless reset, and drops the recorded
// expiries of addresses that are no longer in domains.
// e.mu must be held.
func (e *AppConnector) setExpiresLocked(reset bool) {
	fresh := e.clock.Now().Add(e.routeMaxAge)
	for domain, addrs := range e.domains {
		prev := e.expires[domain]
		next := make(map[netip.Addr]time.Time, len(addrs))
		for _, a := range addrs {
			if t, ok := prev[a]; ok && !reset {
				next[a] = t
			} else {
				next[a] = fresh
			}
		}
		if len(next) == 0 {
			delete(e.expires, domain)
			continue
		}
		mak.Set(&e.expires, domain, next)
	}
	for domain := range e.expires {
		if _, ok := e.domains[domain]; !ok {
			delete(e.expires, domain)
		}
	}
}

// expireInterval returns how often to scan for expired routes given that no
// address is retained for less than minAge.
func expireInterval(minAge time.Duration) time.Duration {
	return min(max(minAge/8, time.Minute), time.Hour)
}

// expireLoop periodically expires discovered routes until ctx is done.
func (e *AppConnector) expireLoop(ctx context.Context) {
	tc, ch := e.clock.NewTicker(expireInterval(e.routeMinAge))
	defer tc.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ch:
			e.expireRoutes()
		}
	}
}

// expireRoutes drops the addresses whose expiry has passed without a
// configured domain resolving to them again, and unadvertises the route for
// each dropped address that no remaining domain still resolves to. It is a
// no-op if route expiry is disabled.
func (e *AppConnector) expireRoutes() {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.routeMaxAge <= 0 {
		return
	}

	// Expiries are absolute times, so they only mean anything if the clock has
	// been running normally. A host without an RTC starts near the epoch and
	// jumps forward once it syncs, and a suspended machine wakes up far ahead
	// of where it left off; in both cases every expiry is suddenly in the past
	// even though we never had the chance to observe a resolution. Treat a
	// jump larger than the longest retention as a correction and start the
	// clock over rather than withdrawing every discovered route at once.
	now := e.clock.Now()
	if elapsed := now.Sub(e.lastExpireScan); elapsed > e.routeMaxAge {
		e.logf("clock moved %v since the last scan; deferring expiry of %d domain(s)", elapsed, len(e.domains))
		e.resetExpiresLocked()
		e.lastExpireScan = now
		return
	}
	e.lastExpireScan = now

	// expired holds addresses dropped from at least one domain, live holds
	// those still resolved by some domain. An address can be in both, when one
	// domain has gone stale for it but another hasn't.
	var expired, live set.Set[netip.Addr]
	var changed bool
	for domain, addrs := range e.domains {
		at := e.expires[domain]
		isExpired := func(a netip.Addr) bool {
			t, ok := at[a]
			return ok && !now.Before(t)
		}
		live.Make()
		if !slices.ContainsFunc(addrs, isExpired) {
			live.AddSlice(addrs)
			continue
		}
		changed = true

		kept := make([]netip.Addr, 0, len(addrs))
		for _, a := range addrs {
			if isExpired(a) {
				expired.Make()
				expired.Add(a)
				delete(at, a)
				continue
			}
			kept = append(kept, a)
		}
		live.AddSlice(kept)
		if len(kept) != 0 {
			e.domains[domain] = kept
			continue
		}
		delete(e.expires, domain)
		if e.matchesWildcardLocked(domain) {
			// The wildcard still routes the domain and the next matching
			// lookup re-adds it, so dropping the empty entry keeps the map
			// from growing without bound as subdomains come and go. A domain
			// that control configures explicitly as well only disappears from
			// Domains until the next UpdateDomains puts its key back.
			delete(e.domains, domain)
		} else {
			e.domains[domain] = nil
		}
	}
	if !changed {
		return
	}

	var toRemove []netip.Prefix
	for a := range expired.All() {
		if live.Contains(a) {
			// Some other configured domain still resolves to it.
			continue
		}
		if slices.ContainsFunc(e.controlRoutes, func(p netip.Prefix) bool { return p.Contains(a) }) {
			// Covered by a route from control, so we never advertised a route
			// for the address itself and have nothing to withdraw. It was only
			// recorded to speed up subsequent lookups.
			continue
		}
		toRemove = append(toRemove, netip.PrefixFrom(a, a.BitLen()))
	}
	// Set iteration order is unspecified; sort so that the updates we publish
	// are deterministic.
	slices.SortFunc(toRemove, func(a, b netip.Prefix) int { return compareAddr(a.Addr(), b.Addr()) })

	if len(toRemove) != 0 {
		// An address newly observed for another domain may be sitting in the
		// queue ahead of us, waiting to be advertised and recorded; from here
		// it looks like nothing resolves to it. The queue runs in order, so by
		// the time this callback runs any such advertisement has been
		// recorded, and we can tell the difference.
		e.queue.Add(func() {
			e.mu.Lock()
			live := make(set.Set[netip.Addr])
			for _, addrs := range e.domains {
				live.AddSlice(addrs)
			}
			e.mu.Unlock()

			stillGone := slicesx.Filter(nil, toRemove, func(p netip.Prefix) bool {
				return !live.Contains(p.Addr())
			})
			if len(stillGone) == 0 {
				return
			}
			e.logf("withdrawing %d expired route(s) no configured domain still resolves to", len(stillGone))
			if e.routeAdvertiser != nil {
				if err := e.routeAdvertiser.UnadvertiseRoute(stillGone...); err != nil {
					e.logf("failed to unadvertise expired routes: %v: %v", stillGone, err)
				}
			}
			e.updatePub.Publish(appctype.RouteUpdate{Unadvertise: stillGone})
		})
	}
	e.storeRoutesLocked()
}

// matchesWildcardLocked reports whether domain is a subdomain of one of the
// configured wildcards.
// e.mu must be held.
func (e *AppConnector) matchesWildcardLocked(domain string) bool {
	for _, wc := range e.wildcards {
		if dnsname.HasSuffix(domain, wc) {
			return true
		}
	}
	return false
}

func compareAddr(a, b netip.Addr) int {
	return a.Compare(b)
}

// routesWithout returns a without b where a and b
// are unsorted slices of netip.Prefix
func routesWithout(a, b []netip.Prefix) []netip.Prefix {
	m := make(map[netip.Prefix]bool, len(b))
	for _, p := range b {
		m[p] = true
	}
	return slicesx.Filter(make([]netip.Prefix, 0, len(a)), a, func(p netip.Prefix) bool {
		return !m[p]
	})
}
