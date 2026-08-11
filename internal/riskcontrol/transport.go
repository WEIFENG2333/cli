// Copyright (c) 2026 Lark Technologies Pte. Ltd.
// SPDX-License-Identifier: MIT

package riskcontrol

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/larksuite/cli/internal/core"
	internaltransport "github.com/larksuite/cli/internal/transport"
)

var _ internaltransport.RoundTripperDecorator = (*Transport)(nil)

const (
	HeaderProductModel     = "X-Agent-Device-Type"
	HeaderOSType           = "X-Agent-Os-Type"
	HeaderCredentialSource = "X-Agent-Credential-Source"
)

var restrictedHeaders = [...]string{HeaderProductModel, HeaderOSType, HeaderCredentialSource}

// CredentialSource reports the source of the successfully resolved token.
type CredentialSource interface {
	ResolvedCredentialSource() string
}

// Transport is the feature's final outbound boundary. It removes caller- or
// extension-supplied signal headers first and writes trusted values only after
// authorizing an official SDK origin and authentication state.
type Transport struct {
	next             http.RoundTripper
	source           Source
	credentialSource CredentialSource
}

// NewTransport creates the final SDK outbound policy boundary. Nil sources
// disable their respective header injection while restricted headers are still
// stripped from caller- and extension-supplied requests.
func NewTransport(next http.RoundTripper, source Source, credentialSource CredentialSource) *Transport {
	if next == nil {
		next = internaltransport.Fallback()
	}
	return &Transport{
		next:             next,
		source:           source,
		credentialSource: credentialSource,
	}
}

// BaseRoundTripper exposes the network transport so policy routers can clone
// and rebuild the complete decorator graph without dropping risk control.
func (t *Transport) BaseRoundTripper() http.RoundTripper {
	if t == nil || t.next == nil {
		return internaltransport.Fallback()
	}
	return t.next
}

// WithBaseRoundTripper returns an equivalent risk-control boundary over base.
func (t *Transport) WithBaseRoundTripper(base http.RoundTripper) http.RoundTripper {
	if t == nil {
		return NewTransport(base, nil, nil)
	}
	cloned := *t
	if base == nil {
		base = internaltransport.Fallback()
	}
	cloned.next = base
	return &cloned
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	stripRestrictedHeaders(req.Header)

	if t.routeAllowsSignals(req) {
		if t.credentialSource != nil {
			if source := t.credentialSource.ResolvedCredentialSource(); source != "" {
				req.Header.Set(HeaderCredentialSource, source)
			}
		}
		if t.source != nil {
			snapshot := t.source.Snapshot()
			if isSupportedOSType(snapshot.OSType) {
				req.Header.Set(HeaderOSType, string(snapshot.OSType))
			}
			if model := normalizeDeviceModel(snapshot.ProductModel); model != "" {
				req.Header.Set(HeaderProductModel, model)
			}
		}
	}
	return t.next.RoundTrip(req)
}

func isSupportedOSType(value OSType) bool {
	switch value {
	case OSTypeWindows, OSTypeLinux, OSTypeMacOS:
		return true
	default:
		return false
	}
}

func stripRestrictedHeaders(header http.Header) {
	for name := range header {
		for _, restricted := range restrictedHeaders {
			if strings.EqualFold(name, restricted) {
				delete(header, name)
				break
			}
		}
	}
}

type origin struct {
	scheme string
	host   string
	port   string
}

var officialFeishuOrigins = [...]origin{
	apiOrigin(core.BrandFeishu, core.ResolveEndpoints(core.BrandFeishu).Open),
	apiOrigin(core.BrandLark, core.ResolveEndpoints(core.BrandLark).Open),
	apiOrigin(core.BrandFeishu, core.ResolveEndpoints(core.BrandFeishu).Accounts),
	apiOrigin(core.BrandLark, core.ResolveEndpoints(core.BrandLark).Accounts),
	apiOrigin(core.BrandFeishu, core.ResolveEndpoints(core.BrandFeishu).MCP),
	apiOrigin(core.BrandLark, core.ResolveEndpoints(core.BrandLark).MCP),
}

func (t *Transport) routeAllowsSignals(req *http.Request) bool {
	if req == nil || req.URL == nil {
		return false
	}
	return isOfficialFeishuOrigin(originOf(req.URL))
}

func originOf(value *url.URL) origin {
	if value == nil {
		return origin{}
	}
	scheme := strings.ToLower(value.Scheme)
	port := value.Port()
	if port == "" {
		switch scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		}
	}
	return origin{scheme: scheme, host: strings.ToLower(value.Hostname()), port: port}
}

func apiOrigin(brand core.LarkBrand, endpointURL string) origin {
	endpoint, err := url.Parse(endpointURL)
	if err != nil {
		return origin{}
	}
	return originOf(endpoint)
}

func isOfficialFeishuOrigin(candidate origin) bool {
	if candidate.scheme != "https" || candidate.port != "443" {
		return false
	}
	for _, official := range officialFeishuOrigins {
		if candidate == official {
			return true
		}
	}
	return false
}
