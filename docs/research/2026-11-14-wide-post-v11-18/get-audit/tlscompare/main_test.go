//go:build linux

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestProfilesUseSamePinnedURLAndHTTP(t *testing.T) {
	var mu sync.Mutex
	var hellos [][]uint16
	var requests []string
	var badALPN bool
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests = append(requests, r.Method+" "+r.Host+" "+r.URL.RequestURI()+" "+r.Proto+" "+
			r.Header.Get("User-Agent")+" "+r.Header.Get("Accept-Encoding"))
		mu.Unlock()
		w.Header().Set("Location", "https://unrelated.invalid/")
		w.WriteHeader(302)
		w.Write([]byte("expected"))
	}))
	server.TLS = &tls.Config{NextProtos: []string{"h2", "http/1.1"},
		GetConfigForClient: func(ch *tls.ClientHelloInfo) (*tls.Config, error) {
			mu.Lock()
			defer mu.Unlock()
			hellos = append(hellos, append([]uint16(nil), ch.CipherSuites...))
			badALPN = badALPN || len(ch.SupportedProtos) != 1 || ch.SupportedProtos[0] != "http/1.1"
			return nil, nil
		}}
	server.StartTLS()
	defer server.Close()
	cert := server.Certificate()
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	target, err := url.Parse("https://" + cert.DNSNames[0] + "/public%2Ftest?x=a%26b")
	if err != nil {
		t.Fatal(err)
	}
	addr := strings.TrimPrefix(server.URL, "https://")
	d := net.Dialer{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	a := probe(ctx, d.DialContext, target, addr, roots, false)
	b := probe(ctx, d.DialContext, target, addr, roots, true)
	for _, point := range []observation{a, b} {
		if !point.Verified || point.Status != 302 || point.ALPN != "http/1.1" || !point.Complete || point.BodyBytes != 8 {
			t.Fatalf("unexpected result: %+v", point)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if badALPN || len(hellos) != 2 || len(hellos[0]) == len(hellos[1]) {
		t.Fatalf("expected two distinct ClientHello profiles with the same ALPN: %v %v", badALPN, hellos)
	}
	if len(requests) != 2 || requests[0] != requests[1] ||
		!strings.Contains(requests[0], " /public%2Ftest?x=a%26b HTTP/1.1 ") ||
		a.BodySHA256 != b.BodySHA256 {
		t.Fatalf("GET, path/query, headers, or digest differ: %v", requests)
	}
}

func TestInvalidCertificatesNeverSendHTTP(t *testing.T) {
	var count atomic.Int32
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { count.Add(1) }))
	defer s.Close()
	d := net.Dialer{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	roots := x509.NewCertPool()
	roots.AddCert(s.Certificate())
	validName := s.Certificate().DNSNames[0]
	for _, tt := range []struct {
		host  string
		roots *x509.CertPool
	}{
		{validName, x509.NewCertPool()}, {"wrong.invalid", roots},
	} {
		u, _ := url.Parse("https://" + tt.host + "/")
		for _, chrome := range []bool{false, true} {
			v := probe(ctx, d.DialContext, u, strings.TrimPrefix(s.URL, "https://"), tt.roots, chrome)
			if v.Verified || v.Status != 0 || v.Stage != "tls_certificate" {
				t.Fatalf("unexpected cert-failure result: %+v", v)
			}
		}
	}
	if count.Load() != 0 {
		t.Fatal("HTTP sent on an unverified TLS connection")
	}
}

func TestPublicIPv4(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "192.168.1.1", "169.254.1.1", "100.64.1.1", "192.0.2.1", "198.18.1.1", "224.0.0.1", "::1"} {
		if publicIPv4(netip.MustParseAddr(ip)) {
			t.Fatalf("accepted nonpublic address %s", ip)
		}
	}
	if !publicIPv4(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("rejected public IPv4")
	}
}
