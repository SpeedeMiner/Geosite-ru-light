//go:build linux

// tlscompare compares two ClientHello profiles for one public HTTPS GET.
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"

	utls "github.com/refraction-networking/utls"
)

const maxBody = 512 * 1024

var tunName = regexp.MustCompile(`^tun[a-zA-Z0-9_.-]{1,12}$`)
var publicName = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
var specialRanges = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"),
}

func publicIPv4(ip netip.Addr) bool {
	if !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false
	}
	for _, prefix := range specialRanges {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

type observation struct {
	Profile     string `json:"profile"`
	Stage       string `json:"stage"`
	Status      int    `json:"status,omitempty"`
	TLS         uint16 `json:"tls_version,omitempty"`
	Verified    bool   `json:"tls_verified"`
	ALPN        string `json:"alpn"`
	HTTPVersion string `json:"http_version,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	BodyBytes   int    `json:"body_bytes"`
	BodySHA256  string `json:"body_sha256,omitempty"`
	Complete    bool   `json:"body_complete"`
}

type dialFunc func(context.Context, string, string) (net.Conn, error)

func probe(ctx context.Context, dial dialFunc, target *url.URL, addr string, roots *x509.CertPool, chrome bool) observation {
	profile, hello := "go", utls.HelloGolang
	if chrome {
		profile, hello = "chrome_auto_http1", utls.HelloChrome_Auto
	}
	result := observation{Profile: profile, Stage: "tcp"}
	raw, err := dial(ctx, "tcp4", addr)
	if err != nil {
		return result
	}
	defer raw.Close()
	if deadline, ok := ctx.Deadline(); ok {
		if err := raw.SetDeadline(deadline); err != nil {
			return result
		}
	}
	result.Stage = "tls"
	conn := utls.UClient(raw, &utls.Config{ServerName: target.Hostname(), RootCAs: roots,
		NextProtos: []string{"http/1.1"}, MinVersion: utls.VersionTLS12}, hello)
	if chrome {
		// Standardize ALPN so HTTP/2 framing cannot explain a difference.
		if err := conn.BuildHandshakeState(); err != nil {
			return result
		}
		for _, extension := range conn.Extensions {
			if alpn, ok := extension.(*utls.ALPNExtension); ok {
				alpn.AlpnProtocols = []string{"http/1.1"}
			}
		}
	}
	if err := conn.HandshakeContext(ctx); err != nil {
		var invalidCert *utls.CertificateVerificationError
		if errors.As(err, &invalidCert) {
			result.Stage = "tls_certificate"
		}
		return result
	}
	state := conn.ConnectionState()
	result.Verified, result.TLS, result.ALPN = len(state.VerifiedChains) > 0, state.Version, state.NegotiatedProtocol
	if !result.Verified || (result.ALPN != "" && result.ALPN != "http/1.1") {
		return result
	}
	result.Stage = "http"
	req := &http.Request{Method: http.MethodGet, URL: target, Host: target.Host,
		Header: http.Header{"User-Agent": {"GeoSite-Reachability/1.0"}, "Accept": {"*/*"}, "Accept-Encoding": {"identity"}}, Close: true}
	if err := req.Write(conn); err != nil {
		return result
	}
	reader := bufio.NewReader(io.LimitReader(conn, maxBody+64*1024))
	var resp *http.Response
	for range 5 {
		resp, err = http.ReadResponse(reader, req)
		if err != nil {
			return result
		}
		if resp.StatusCode >= 200 {
			break
		}
		resp.Body.Close()
	}
	if resp.StatusCode < 200 {
		return result
	}
	defer resp.Body.Close()
	result.Status, result.HTTPVersion, result.ContentType = resp.StatusCode, resp.Proto, resp.Header.Get("Content-Type")
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	result.Complete = err == nil && len(body) <= maxBody
	result.Stage = "body_incomplete"
	if result.Complete {
		result.Stage = "complete"
	}
	if len(body) > maxBody {
		body = body[:maxBody]
	}
	result.BodyBytes = len(body)
	if len(body) > 0 {
		sum := sha256.Sum256(body)
		result.BodySHA256 = hex.EncodeToString(sum[:])
	}
	return result
}

func main() {
	rawURL := flag.String("url", "", "exact public HTTPS URL")
	rawIP := flag.String("ip", "", "public IPv4 address resolved by the caller")
	iface := flag.String("interface", "", "required OpenVPN tunnel interface")
	seconds := flag.Int("timeout", 5, "per-profile timeout in seconds")
	flag.Parse()
	target, urlErr := url.Parse(*rawURL)
	ip, ipErr := netip.ParseAddr(*rawIP)
	if urlErr != nil || ipErr != nil || !publicIPv4(ip) || !tunName.MatchString(*iface) ||
		*seconds < 1 || *seconds > 8 || flag.NArg() != 0 || len(*rawURL) > 4096 || strings.Contains(*rawURL, "#") ||
		target.Scheme != "https" || target.User != nil || target.Host != target.Hostname() ||
		len(target.Host) > 253 || !publicName.MatchString(target.Host) || net.ParseIP(target.Host) != nil {
		fmt.Fprintln(os.Stderr, "expected one exact HTTPS URL, public IPv4, and OpenVPN interface")
		os.Exit(2)
	}
	dialer := &net.Dialer{Control: func(_, _ string, c syscall.RawConn) error {
		var bindErr error
		if err := c.Control(func(fd uintptr) {
			bindErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, *iface)
		}); err != nil {
			return err
		}
		return bindErr
	}}
	addr := net.JoinHostPort(ip.String(), "443")
	points := make([]observation, 0, 2)
	for _, chrome := range []bool{false, true} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*seconds)*time.Second)
		points = append(points, probe(ctx, dialer.DialContext, target, addr, nil, chrome))
		cancel()
	}
	if err := json.NewEncoder(os.Stdout).Encode(points); err != nil {
		os.Exit(1)
	}
}
