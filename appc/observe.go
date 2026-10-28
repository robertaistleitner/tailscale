// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_appconnectors

package appc

import (
	"math"
	"net/netip"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/util/mak"
)

// ObserveDNSResponse is a callback invoked by the DNS resolver when a DNS
// response is being returned over the PeerAPI. The response is parsed and
// matched against the configured domains, if matched the routeAdvertiser is
// advised to advertise the discovered route.
func (e *AppConnector) ObserveDNSResponse(res []byte) error {
	var p dnsmessage.Parser
	if _, err := p.Start(res); err != nil {
		return err
	}
	if err := p.SkipAllQuestions(); err != nil {
		return err
	}

	// cnameChain tracks a chain of CNAMEs for a given query in order to reverse
	// a CNAME chain back to the original query for flattening. The keys are
	// CNAME record targets, and the value is the name the record answers, so
	// for www.example.com CNAME example.com, the map would contain
	// ["example.com"] = "www.example.com".
	var cnameChain map[string]string

	// addressRecords holds the address records found in the response, by the
	// name they answer.
	var addressRecords map[string]*addrRecords

	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return err
		}

		if h.Class != dnsmessage.ClassINET {
			if err := p.SkipAnswer(); err != nil {
				return err
			}
			continue
		}

		switch h.Type {
		case dnsmessage.TypeCNAME, dnsmessage.TypeA, dnsmessage.TypeAAAA:
		default:
			if err := p.SkipAnswer(); err != nil {
				return err
			}
			continue

		}

		domain := strings.TrimSuffix(strings.ToLower(h.Name.String()), ".")
		if len(domain) == 0 {
			continue
		}

		if h.Type == dnsmessage.TypeCNAME {
			res, err := p.CNAMEResource()
			if err != nil {
				return err
			}
			cname := strings.TrimSuffix(strings.ToLower(res.CNAME.String()), ".")
			if len(cname) == 0 {
				continue
			}
			mak.Set(&cnameChain, cname, domain)
			continue
		}

		switch h.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return err
			}
			recordsFor(&addressRecords, domain).add(netip.AddrFrom4(r.A), h.TTL)
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return err
			}
			recordsFor(&addressRecords, domain).add(netip.AddrFrom16(r.AAAA), h.TTL)
		default:
			if err := p.SkipAnswer(); err != nil {
				return err
			}
			continue
		}
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	for domain, rec := range addressRecords {
		domain, isRouted := e.findRoutedDomainLocked(domain, cnameChain)

		// domain and none of the CNAMEs in the chain are routed
		if !isRouted {
			continue
		}

		// advertise each address we have learned for the routed domain, that
		// was not already known.
		var toAdvertise []netip.Prefix
		for _, addr := range rec.addrs {
			if !e.isAddrKnownLocked(domain, addr) {
				toAdvertise = append(toAdvertise, netip.PrefixFrom(addr, addr.BitLen()))
				// The resolution is recorded once the route is advertised,
				// in scheduleAdvertisement, so that we never hold an expiry
				// for an address we aren't tracking.
				continue
			}
			e.noteAddrResolvedLocked(domain, addr, rec.ttl)
		}

		if len(toAdvertise) > 0 {
			e.logf("[v2] observed new routes for %s: %s", domain, toAdvertise)
			e.scheduleAdvertisement(domain, rec.ttl, toAdvertise...)
		}
	}
	return nil
}

// addrRecords are the address records a DNS response returned for one name.
type addrRecords struct {
	// addrs are the addresses the records resolved to.
	addrs []netip.Addr

	// ttl is the smallest TTL, in seconds, of the records addrs came from. All
	// the records in an RRset share a TTL, so it only differs between a name's
	// A and AAAA records.
	//
	// It is the TTL of the address records themselves, not of the CNAME chain
	// that may lead to them, so a short-lived CNAME pointing at a long-lived
	// address yields the longer lifetime. That errs towards keeping a route
	// longer than strictly needed, which is the safe direction.
	ttl uint32
}

// add records that the name resolved to addr in a record with the given TTL.
func (r *addrRecords) add(addr netip.Addr, ttl uint32) {
	r.addrs = append(r.addrs, addr)
	r.ttl = min(r.ttl, ttl)
}

// recordsFor returns the [addrRecords] for domain in m, adding one if needed.
func recordsFor(m *map[string]*addrRecords, domain string) *addrRecords {
	if r, ok := (*m)[domain]; ok {
		return r
	}
	r := &addrRecords{ttl: math.MaxUint32}
	mak.Set(m, domain, r)
	return r
}
