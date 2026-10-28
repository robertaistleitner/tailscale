// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package appc

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"testing"
	"time"

	"tailscale.com/appc/appctest"
	"tailscale.com/tstest"
	"tailscale.com/types/appctype"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/util/slicesx"
)

const (
	testMinAge = 6 * time.Hour
	testMaxAge = 7 * 24 * time.Hour
)

// testEpoch is when the clock of a connector from newExpiringConnector starts.
var testEpoch = time.Unix(1700000000, 0)

// storedRouteInfoForTest returns the route info the connector would persist.
func (e *AppConnector) storedRouteInfoForTest() appctype.RouteInfo {
	e.mu.Lock()
	defer e.mu.Unlock()
	expires := make(map[string]map[netip.Addr]time.Time, len(e.expires))
	for d, m := range e.expires {
		expires[d] = maps.Clone(m)
	}
	return appctype.RouteInfo{
		Control:   slices.Clone(e.controlRoutes),
		Domains:   maps.Clone(e.domains),
		Wildcards: slices.Clone(e.wildcards),
		Expires:   expires,
	}
}

// distinctRoutes sorts routes and removes duplicates, which
// [appctest.RouteCollector] records when the same route is advertised for more
// than one domain.
func distinctRoutes(routes []netip.Prefix) []netip.Prefix {
	routes = slices.Clone(routes)
	slices.SortFunc(routes, func(a, b netip.Prefix) int { return compareAddr(a.Addr(), b.Addr()) })
	return slices.Compact(routes)
}

// newExpiringConnector returns a connector with route expiry enabled, along
// with the clock driving it and the collector recording its advertisements.
//
// Its background expiry loop is stopped before it can do anything: the loop
// ticks off the same clock the tests advance, so leaving it running would have
// it expiring routes concurrently with the assertions. Tests drive expiry by
// calling expireRoutes directly, and pass time with runFor.
func newExpiringConnector(t *testing.T, ri *appctype.RouteInfo) (*AppConnector, *tstest.Clock, *appctest.RouteCollector) {
	t.Helper()
	return newExpiringConnectorAt(t, ri, testEpoch)
}

// newExpiringConnectorAt is newExpiringConnector, with the clock already at
// start when the connector is constructed. Advancing a clock the connector was
// built against by more than a couple of scan intervals instead looks to it
// like the system clock jumped.
func newExpiringConnectorAt(t *testing.T, ri *appctype.RouteInfo, start time.Time) (*AppConnector, *tstest.Clock, *appctest.RouteCollector) {
	t.Helper()
	clock := tstest.NewClock(tstest.ClockOpts{Start: start})
	rc := &appctest.RouteCollector{}
	a := NewAppConnector(Config{
		Logf:            t.Logf,
		EventBus:        eventbustest.NewBus(t),
		RouteAdvertiser: rc,
		RouteInfo:       ri,
		HasStoredRoutes: true,
		RouteMinAge:     testMinAge,
		RouteMaxAge:     testMaxAge,
		Clock:           clock,
	})
	a.stopExpiry()
	t.Cleanup(a.Close)
	return a, clock, rc
}

// runFor advances clock by d the way it passes for a running connector: a scan
// interval at a time, with a scan after each step. Advancing the clock in one
// go instead looks to the connector like the system clock jumped.
func runFor(a *AppConnector, clock *tstest.Clock, d time.Duration) {
	for d > 0 {
		step := min(d, expireInterval(a.routeMinAge))
		clock.Advance(step)
		a.expireRoutes()
		d -= step
	}
}

// expiryFor returns the recorded expiry of addr under domain.
func (e *AppConnector) expiryFor(domain string, addr netip.Addr) (time.Time, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	t, ok := e.expires[domain][addr]
	return t, ok
}

// numExpiries returns how many domains have recorded expiries.
func (e *AppConnector) numExpiries() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.expires)
}

func TestExpiryForTTL(t *testing.T) {
	a, _, _ := newExpiringConnector(t, nil)
	for _, tt := range []struct {
		ttl  uint32
		want time.Duration
	}{
		{0, testMinAge},          // "do not cache" still gets the floor
		{60, testMinAge},         // 20m, raised to the floor
		{3600, 20 * time.Hour},   // 20x an hour-long record lifetime
		{86400, testMaxAge},      // 20d, lowered to the ceiling
		{1 << 31, testMaxAge},    // absurd TTLs must not overflow
		{^uint32(0), testMaxAge}, //
	} {
		if got := a.expiryForTTL(tt.ttl); got != tt.want {
			t.Errorf("expiryForTTL(%d) = %v, want %v", tt.ttl, got, tt.want)
		}
	}
}

func TestExpireRoutesUsesRecordTTL(t *testing.T) {
	ctx := t.Context()
	a, clock, rc := newExpiringConnector(t, nil)

	// long.example.com's records live for an hour, so its addresses are
	// retained for 20 hours; short.example.com's live for a minute, so its
	// addresses only get the floor.
	a.updateDomains([]string{"long.example.com", "short.example.com"})
	if err := a.ObserveDNSResponse(dnsResponseTTL("long.example.com.", "192.0.2.1", 3600)); err != nil {
		t.Fatalf("ObserveDNSResponse: %v", err)
	}
	if err := a.ObserveDNSResponse(dnsResponseTTL("short.example.com.", "192.0.2.2", 60)); err != nil {
		t.Fatalf("ObserveDNSResponse: %v", err)
	}
	a.Wait(ctx)

	runFor(a, clock, testMinAge+time.Minute)
	a.Wait(ctx)
	if got, want := rc.RemovedRoutes(), prefixes("192.0.2.2/32"); !slices.Equal(got, want) {
		t.Errorf("removed routes after the floor elapsed: got %v, want %v", got, want)
	}
	if got, want := rc.Routes(), prefixes("192.0.2.1/32"); !slices.Equal(got, want) {
		t.Errorf("routes after the floor elapsed: got %v, want %v", got, want)
	}

	runFor(a, clock, 20*time.Hour)
	a.Wait(ctx)
	if got, want := rc.RemovedRoutes(), prefixes("192.0.2.1/32", "192.0.2.2/32"); !slices.Equal(distinctRoutes(got), want) {
		t.Errorf("removed routes after 20 record lifetimes: got %v, want %v", got, want)
	}
	if got := rc.Routes(); len(got) != 0 {
		t.Errorf("routes after 20 record lifetimes: got %v, want none", got)
	}
}

func TestExpireRoutesWithdrawsUnresolvedAddrs(t *testing.T) {
	ctx := t.Context()
	a, clock, rc := newExpiringConnector(t, nil)

	a.updateDomains([]string{"example.com"})
	if err := a.ObserveDNSResponse(dnsResponse("example.com.", "192.0.2.1")); err != nil {
		t.Fatalf("ObserveDNSResponse: %v", err)
	}
	a.Wait(ctx)

	// Well before the address expires, nothing is withdrawn.
	runFor(a, clock, testMinAge-time.Minute)
	a.Wait(ctx)
	if got, want := rc.Routes(), prefixes("192.0.2.1/32"); !slices.Equal(got, want) {
		t.Errorf("routes before expiry: got %v, want %v", got, want)
	}

	// A second resolution pushes the expiry back out.
	if err := a.ObserveDNSResponse(dnsResponse("example.com.", "192.0.2.1")); err != nil {
		t.Fatalf("ObserveDNSResponse: %v", err)
	}
	a.Wait(ctx)
	runFor(a, clock, testMinAge-time.Minute)
	a.Wait(ctx)
	if got, want := rc.Routes(), prefixes("192.0.2.1/32"); !slices.Equal(got, want) {
		t.Errorf("routes after refresh: got %v, want %v", got, want)
	}

	// Once the address goes unresolved past its expiry, its route is withdrawn
	// and it is forgotten.
	runFor(a, clock, 2*time.Minute)
	a.Wait(ctx)
	if got := rc.Routes(); len(got) != 0 {
		t.Errorf("routes after expiry: got %v, want none", got)
	}
	if got, want := rc.RemovedRoutes(), prefixes("192.0.2.1/32"); !slices.Equal(got, want) {
		t.Errorf("removed routes: got %v, want %v", got, want)
	}
	if got := a.DomainRoutes()["example.com"]; len(got) != 0 {
		t.Errorf("domain routes after expiry: got %v, want none", got)
	}
	// The domain itself is still configured, so it stays routed.
	if got, want := a.Domains().AsSlice(), []string{"example.com"}; !slices.Equal(got, want) {
		t.Errorf("domains after expiry: got %v, want %v", got, want)
	}
}

func TestExpireRoutesKeepsAddrSharedWithLiveDomain(t *testing.T) {
	ctx := t.Context()
	a, clock, rc := newExpiringConnector(t, nil)

	a.updateDomains([]string{"a.example.com", "b.example.com"})
	for _, d := range []string{"a.example.com.", "b.example.com."} {
		if err := a.ObserveDNSResponse(dnsResponse(d, "192.0.2.1")); err != nil {
			t.Fatalf("ObserveDNSResponse(%s): %v", d, err)
		}
	}
	a.Wait(ctx)

	// Only a.example.com keeps resolving to the shared address.
	runFor(a, clock, testMinAge-time.Minute)
	if err := a.ObserveDNSResponse(dnsResponse("a.example.com.", "192.0.2.1")); err != nil {
		t.Fatalf("ObserveDNSResponse: %v", err)
	}
	a.Wait(ctx)
	runFor(a, clock, 2*time.Minute)
	a.Wait(ctx)

	if got := rc.RemovedRoutes(); len(got) != 0 {
		t.Errorf("removed routes: got %v, want none; the address is still resolved by a.example.com", got)
	}
	// Both domains advertised the same route, and the collector records
	// duplicates, so compare the distinct routes.
	if got, want := distinctRoutes(rc.Routes()), prefixes("192.0.2.1/32"); !slices.Equal(got, want) {
		t.Errorf("routes: got %v, want %v", got, want)
	}
	// b.example.com no longer resolves to it, so it is dropped there.
	dr := a.DomainRoutes()
	if got, want := dr["a.example.com"], []netip.Addr{netip.MustParseAddr("192.0.2.1")}; !slices.Equal(got, want) {
		t.Errorf("a.example.com routes: got %v, want %v", got, want)
	}
	if got := dr["b.example.com"]; len(got) != 0 {
		t.Errorf("b.example.com routes: got %v, want none", got)
	}

	// Once a.example.com stops resolving to it too, the route goes away.
	runFor(a, clock, testMinAge+time.Minute)
	a.Wait(ctx)
	if got, want := distinctRoutes(rc.RemovedRoutes()), prefixes("192.0.2.1/32"); !slices.Equal(got, want) {
		t.Errorf("removed routes: got %v, want %v", got, want)
	}
	if got := distinctRoutes(rc.Routes()); len(got) != 0 {
		t.Errorf("routes after expiry: got %v, want none", got)
	}
}

func TestExpireRoutesForgetsWildcardSubdomains(t *testing.T) {
	ctx := t.Context()
	a, clock, rc := newExpiringConnector(t, nil)

	a.updateDomains([]string{"*.example.com", "example.com"})
	if err := a.ObserveDNSResponse(dnsResponse("foo.example.com.", "192.0.2.1")); err != nil {
		t.Fatalf("ObserveDNSResponse: %v", err)
	}
	if err := a.ObserveDNSResponse(dnsResponse("example.com.", "192.0.2.2")); err != nil {
		t.Fatalf("ObserveDNSResponse: %v", err)
	}
	a.Wait(ctx)

	runFor(a, clock, testMinAge+time.Minute)
	a.Wait(ctx)

	if got, want := rc.RemovedRoutes(), prefixes("192.0.2.1/32", "192.0.2.2/32"); !slices.Equal(got, want) {
		t.Errorf("removed routes: got %v, want %v", got, want)
	}
	// The subdomain was only tracked because it matched the wildcard, so it is
	// forgotten entirely rather than left behind as an empty entry.
	if got, want := slicesx.MapKeys(a.DomainRoutes()), []string{"example.com"}; !slices.Equal(got, want) {
		t.Errorf("domains after expiry: got %v, want %v", got, want)
	}
	// It is routed again as soon as it is looked up.
	if err := a.ObserveDNSResponse(dnsResponse("foo.example.com.", "192.0.2.3")); err != nil {
		t.Fatalf("ObserveDNSResponse: %v", err)
	}
	a.Wait(ctx)
	if got, want := rc.Routes(), prefixes("192.0.2.3/32"); !slices.Equal(got, want) {
		t.Errorf("routes after re-resolution: got %v, want %v", got, want)
	}
}

func TestExpireRoutesLeavesControlRoutesAlone(t *testing.T) {
	ctx := t.Context()
	a, clock, rc := newExpiringConnector(t, nil)

	a.updateRoutes(prefixes("192.0.2.0/24"))
	a.updateDomains([]string{"example.com"})
	// The address is covered by a control route, so no route of its own is
	// advertised for it; it is only recorded to speed up later lookups.
	if err := a.ObserveDNSResponse(dnsResponse("example.com.", "192.0.2.1")); err != nil {
		t.Fatalf("ObserveDNSResponse: %v", err)
	}
	a.Wait(ctx)
	if got, want := rc.Routes(), prefixes("192.0.2.0/24"); !slices.Equal(got, want) {
		t.Fatalf("routes: got %v, want %v", got, want)
	}

	runFor(a, clock, testMinAge+time.Minute)
	a.Wait(ctx)

	if got, want := rc.Routes(), prefixes("192.0.2.0/24"); !slices.Equal(got, want) {
		t.Errorf("routes after expiry: got %v, want %v", got, want)
	}
	if got := rc.RemovedRoutes(); len(got) != 0 {
		t.Errorf("removed routes: got %v, want none", got)
	}
}

func TestExpireRoutesDisabled(t *testing.T) {
	ctx := t.Context()
	rc := &appctest.RouteCollector{}
	a := NewAppConnector(Config{
		Logf:            t.Logf,
		EventBus:        eventbustest.NewBus(t),
		RouteAdvertiser: rc,
		HasStoredRoutes: true,
	})
	t.Cleanup(a.Close)

	if a.stopExpiry != nil {
		t.Error("expiry loop started with RouteMaxAge unset")
	}
	a.updateDomains([]string{"example.com"})
	if err := a.ObserveDNSResponse(dnsResponse("example.com.", "192.0.2.1")); err != nil {
		t.Fatalf("ObserveDNSResponse: %v", err)
	}
	a.Wait(ctx)
	if got := a.numExpiries(); got != 0 {
		t.Errorf("domains with expiries: got %d, want 0 when expiry is disabled", got)
	}

	a.expireRoutes()
	a.Wait(ctx)
	if got, want := rc.Routes(), prefixes("192.0.2.1/32"); !slices.Equal(got, want) {
		t.Errorf("routes: got %v, want %v", got, want)
	}
}

// TestExpireRoutesStoredRoundTrip checks that expiries survive a restart, and
// that addresses restored from a store written before expiry existed get a
// full max age before being withdrawn.
func TestExpireRoutesStoredRoundTrip(t *testing.T) {
	ctx := t.Context()
	addr := netip.MustParseAddr("192.0.2.1")

	// A store from a connector that predates expiry: no recorded expiries, and
	// no remembered TTL to derive one from.
	ri := &appctype.RouteInfo{
		Domains: map[string][]netip.Addr{"example.com": {addr}},
	}
	a, clock, rc := newExpiringConnector(t, ri)
	a.updateDomains([]string{"example.com"})
	got, ok := a.expiryFor("example.com", addr)
	if want := clock.PeekNow().Add(testMaxAge); !ok || !got.Equal(want) {
		t.Errorf("seeded expiry: got %v (ok=%v), want %v", got, ok, want)
	}

	runFor(a, clock, testMaxAge-2*testMinAge)
	a.Wait(ctx)
	if got := rc.RemovedRoutes(); len(got) != 0 {
		t.Errorf("removed routes before the seeded expiry: got %v, want none", got)
	}

	// The expiry is carried into the stored route info.
	stored := a.storedRouteInfoForTest()
	want, _ := a.expiryFor("example.com", addr)
	if got, ok := stored.Expires["example.com"][addr]; !ok {
		t.Fatalf("stored Expires missing %v: %v", addr, stored.Expires)
	} else if !got.Equal(want) {
		t.Errorf("stored Expires: got %v, want %v", got, want)
	}

	// Restart from that store: the address keeps its original expiry rather
	// than having it pushed back out, so it expires on schedule.
	b, bClock, bRC := newExpiringConnectorAt(t, &stored, clock.PeekNow())
	b.updateDomains([]string{"example.com"})
	if err := b.routeAdvertiser.AdvertiseRoute(netip.PrefixFrom(addr, addr.BitLen())); err != nil {
		t.Fatal(err)
	}
	if got, _ := b.expiryFor("example.com", addr); !got.Equal(want) {
		t.Errorf("expiry after restart: got %v, want %v", got, want)
	}
	runFor(b, bClock, 2*testMinAge-time.Minute)
	b.Wait(ctx)
	if got := bRC.RemovedRoutes(); len(got) != 0 {
		t.Errorf("removed routes before the restored expiry: got %v, want none", got)
	}
	runFor(b, bClock, 2*time.Minute)
	b.Wait(ctx)
	if got, want := bRC.RemovedRoutes(), prefixes("192.0.2.1/32"); !slices.Equal(got, want) {
		t.Errorf("removed routes after restart: got %v, want %v", got, want)
	}
}

// TestExpireRoutesCreditsDowntime checks that a connector that was down past
// the stored expiry of an address, when no resolution could be observed, gives
// the address a minimum age to be resolved again rather than withdrawing it as
// soon as it starts.
func TestExpireRoutesCreditsDowntime(t *testing.T) {
	ctx := t.Context()
	addr := netip.MustParseAddr("192.0.2.1")
	ri := &appctype.RouteInfo{
		Domains: map[string][]netip.Addr{"example.com": {addr}},
		Expires: map[string]map[netip.Addr]time.Time{"example.com": {addr: testEpoch.Add(-48 * time.Hour)}},
	}
	a, clock, rc := newExpiringConnector(t, ri)
	a.updateDomains([]string{"example.com"})
	if err := rc.AdvertiseRoute(netip.PrefixFrom(addr, addr.BitLen())); err != nil {
		t.Fatal(err)
	}
	got, ok := a.expiryFor("example.com", addr)
	if want := testEpoch.Add(testMinAge); !ok || !got.Equal(want) {
		t.Errorf("expiry after downtime: got %v (ok=%v), want %v", got, ok, want)
	}

	runFor(a, clock, testMinAge-time.Minute)
	a.Wait(ctx)
	if got := rc.RemovedRoutes(); len(got) != 0 {
		t.Errorf("removed routes within the minimum age of starting: got %v, want none", got)
	}
	runFor(a, clock, 2*time.Minute)
	a.Wait(ctx)
	if got, want := rc.RemovedRoutes(), prefixes("192.0.2.1/32"); !slices.Equal(got, want) {
		t.Errorf("removed routes: got %v, want %v", got, want)
	}
}

// TestExpireRoutesStoresRefreshedExpiries checks that re-resolving a known
// address, which doesn't store by itself, is persisted by the next scan.
func TestExpireRoutesStoresRefreshedExpiries(t *testing.T) {
	ctx := t.Context()
	addr := netip.MustParseAddr("192.0.2.1")
	a, clock, _ := newExpiringConnector(t, nil)

	a.updateDomains([]string{"example.com"})
	if err := a.ObserveDNSResponse(dnsResponse("example.com.", "192.0.2.1")); err != nil {
		t.Fatalf("ObserveDNSResponse: %v", err)
	}
	a.Wait(ctx)
	runFor(a, clock, time.Hour)

	w := eventbustest.NewWatcher(t, a.eventBus)
	if err := a.ObserveDNSResponse(dnsResponse("example.com.", "192.0.2.1")); err != nil {
		t.Fatalf("ObserveDNSResponse: %v", err)
	}
	want := clock.PeekNow().Add(testMinAge)
	a.expireRoutes()
	if err := eventbustest.Expect(w, func(ri appctype.RouteInfo) error {
		if got := ri.Expires["example.com"][addr]; !got.Equal(want) {
			return fmt.Errorf("stored expiry: got %v, want %v", got, want)
		}
		return nil
	}); err != nil {
		t.Error(err)
	}
}

// TestExpireRoutesKeepsLongerExpiry checks that an answer carrying a short
// TTL, such as what is left of a cached record, doesn't shorten the retention
// an address already earned from a long one.
func TestExpireRoutesKeepsLongerExpiry(t *testing.T) {
	ctx := t.Context()
	addr := netip.MustParseAddr("192.0.2.1")
	a, clock, _ := newExpiringConnector(t, nil)

	a.updateDomains([]string{"example.com"})
	if err := a.ObserveDNSResponse(dnsResponseTTL("example.com.", "192.0.2.1", 3600)); err != nil {
		t.Fatalf("ObserveDNSResponse: %v", err)
	}
	a.Wait(ctx)
	want := clock.PeekNow().Add(20 * time.Hour)

	runFor(a, clock, time.Hour)
	if err := a.ObserveDNSResponse(dnsResponseTTL("example.com.", "192.0.2.1", 30)); err != nil {
		t.Fatalf("ObserveDNSResponse: %v", err)
	}
	a.Wait(ctx)
	if got, ok := a.expiryFor("example.com", addr); !ok || !got.Equal(want) {
		t.Errorf("expiry after a short-TTL answer: got %v (ok=%v), want %v", got, ok, want)
	}
}

// TestExpireRoutesKeepsExplicitDomainUnderWildcard checks that a domain
// configured by name stays configured once its addresses expire, even though
// it also matches a wildcard.
func TestExpireRoutesKeepsExplicitDomainUnderWildcard(t *testing.T) {
	ctx := t.Context()
	a, clock, rc := newExpiringConnector(t, nil)

	a.updateDomains([]string{"*.example.com", "foo.example.com"})
	for _, d := range []string{"foo.example.com.", "bar.example.com."} {
		if err := a.ObserveDNSResponse(dnsResponse(d, "192.0.2.1")); err != nil {
			t.Fatalf("ObserveDNSResponse(%s): %v", d, err)
		}
	}
	a.Wait(ctx)

	runFor(a, clock, testMinAge+time.Minute)
	a.Wait(ctx)
	if got, want := distinctRoutes(rc.RemovedRoutes()), prefixes("192.0.2.1/32"); !slices.Equal(got, want) {
		t.Errorf("removed routes: got %v, want %v", got, want)
	}
	if got, want := a.Domains().AsSlice(), []string{"foo.example.com"}; !slices.Equal(got, want) {
		t.Errorf("domains after expiry: got %v, want %v", got, want)
	}
}

// TestExpireRoutesWaitsForQueuedAdvertisements covers the window where one
// domain has just resolved to an address that another domain's entry for it is
// expiring: the advertisement is recorded from the queue, so until it runs the
// address looks unreferenced even though it is about to be referenced again.
func TestExpireRoutesWaitsForQueuedAdvertisements(t *testing.T) {
	ctx := t.Context()
	a, clock, rc := newExpiringConnector(t, nil)

	a.updateDomains([]string{"a.example.com", "b.example.com"})
	if err := a.ObserveDNSResponse(dnsResponse("a.example.com.", "192.0.2.1")); err != nil {
		t.Fatalf("ObserveDNSResponse: %v", err)
	}
	a.Wait(ctx)

	// Let a.example.com's entry for the address go stale, without a scan
	// noticing yet.
	runFor(a, clock, testMinAge-time.Minute)
	clock.Advance(2 * time.Minute)

	// Run expiry from inside b.example.com's advertisement, before it has been
	// recorded: a.example.com no longer resolves to the address and
	// b.example.com does not yet appear to.
	rc.AdvertiseCallback = func() {
		rc.AdvertiseCallback = nil
		a.expireRoutes()
	}
	if err := a.ObserveDNSResponse(dnsResponse("b.example.com.", "192.0.2.1")); err != nil {
		t.Fatalf("ObserveDNSResponse: %v", err)
	}
	a.Wait(ctx)

	if got := rc.RemovedRoutes(); len(got) != 0 {
		t.Errorf("removed routes: got %v, want none; b.example.com resolves to the address", got)
	}
	if got, want := distinctRoutes(rc.Routes()), prefixes("192.0.2.1/32"); !slices.Equal(got, want) {
		t.Errorf("routes: got %v, want %v", got, want)
	}
	// The connector's own view must match: if it thinks b.example.com's route
	// is advertised when it isn't, it will never re-advertise it.
	if got, want := a.DomainRoutes()["b.example.com"], []netip.Addr{netip.MustParseAddr("192.0.2.1")}; !slices.Equal(got, want) {
		t.Errorf("b.example.com routes: got %v, want %v", got, want)
	}
}

// TestExpireRoutesIgnoresClockJump covers a host whose clock starts near the
// epoch and jumps forward once it syncs: every stored expiry is suddenly in the
// past, but no resolution could have happened in between, so the routes must
// not all be withdrawn at once.
func TestExpireRoutesIgnoresClockJump(t *testing.T) {
	testExpireRoutesIgnoresClockJump(t, time.Unix(0, 0), testEpoch)
}

// TestExpireRoutesIgnoresSuspend is the same for a machine that was suspended
// for longer than the minimum age, but nowhere near the maximum.
func TestExpireRoutesIgnoresSuspend(t *testing.T) {
	testExpireRoutesIgnoresClockJump(t, testEpoch, testEpoch.Add(8*time.Hour))
}

// TestExpireRoutesIgnoresClockSetBack covers a clock that was running ahead
// being corrected, which must not leave routes around for the difference.
func TestExpireRoutesIgnoresClockSetBack(t *testing.T) {
	testExpireRoutesIgnoresClockJump(t, testEpoch.Add(365*24*time.Hour), testEpoch)
}

func testExpireRoutesIgnoresClockJump(t *testing.T, from, to time.Time) {
	ctx := t.Context()
	a, clock, rc := newExpiringConnectorAt(t, nil, from)

	a.updateDomains([]string{"example.com"})
	if err := a.ObserveDNSResponse(dnsResponse("example.com.", "192.0.2.1")); err != nil {
		t.Fatalf("ObserveDNSResponse: %v", err)
	}
	a.Wait(ctx)

	if to.After(from) {
		clock.AdvanceTo(to)
	} else {
		// A tstest.Clock won't go backwards, so swap in one that already has.
		clock = tstest.NewClock(tstest.ClockOpts{Start: to})
		a.clock = clock
	}
	a.expireRoutes()
	a.Wait(ctx)

	if got := rc.RemovedRoutes(); len(got) != 0 {
		t.Errorf("removed routes across a clock jump: got %v, want none", got)
	}
	if got, want := rc.Routes(), prefixes("192.0.2.1/32"); !slices.Equal(got, want) {
		t.Errorf("routes across a clock jump: got %v, want %v", got, want)
	}
	// The address has as long left as it had before the jump.
	got, ok := a.expiryFor("example.com", netip.MustParseAddr("192.0.2.1"))
	if want := to.Add(testMinAge); !ok || !got.Equal(want) {
		t.Errorf("expiry after the jump: got %v (ok=%v), want %v", got, ok, want)
	}

	// Once the clock is running normally again, expiry resumes.
	runFor(a, clock, testMinAge-time.Minute)
	a.Wait(ctx)
	if got := rc.RemovedRoutes(); len(got) != 0 {
		t.Errorf("removed routes before the expiry: got %v, want none", got)
	}
	runFor(a, clock, 2*time.Minute)
	a.Wait(ctx)
	if got, want := rc.RemovedRoutes(), prefixes("192.0.2.1/32"); !slices.Equal(got, want) {
		t.Errorf("removed routes after the expiry: got %v, want %v", got, want)
	}
}

func TestExpireInterval(t *testing.T) {
	for _, tt := range []struct {
		minAge time.Duration
		want   time.Duration
	}{
		{time.Second, time.Minute},        // floor
		{time.Hour, 450 * time.Second},    // minAge/8
		{6 * time.Hour, 45 * time.Minute}, // minAge/8
		{24 * time.Hour, time.Hour},       // ceiling
	} {
		if got := expireInterval(tt.minAge); got != tt.want {
			t.Errorf("expireInterval(%v) = %v, want %v", tt.minAge, got, tt.want)
		}
	}
}
