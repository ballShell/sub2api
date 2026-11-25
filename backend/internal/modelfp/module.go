package modelfp

import (
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/google/wire"
)

// ProvideHTTPProbeClient constructs the default SSRF-hardened HTTP ProbeClient for Wire DI.
func ProvideHTTPProbeClient() *HTTPProbeClient {
	return NewHTTPProbeClient()
}

// ProvideAccountLookup adapts service.AccountRepository to the narrow AccountLookup interface.
func ProvideAccountLookup(repo service.AccountRepository) AccountLookup {
	return repo
}

// ProvideProxyLookup adapts service.ProxyRepository to the narrow ProxyLookup interface.
func ProvideProxyLookup(repo service.ProxyRepository) ProxyLookup {
	return repo
}

// ProviderSet wires the modelfp persistence, transport, resolver, services, and admin handler.
var ProviderSet = wire.NewSet(
	NewPostgresStore,
	wire.Bind(new(Store), new(*PostgresStore)),
	ProvideHTTPProbeClient,
	wire.Bind(new(ProbeClient), new(*HTTPProbeClient)),
	ProvideAccountLookup,
	ProvideProxyLookup,
	NewTargetResolver,
	NewOrchestrator,
	NewBaselineService,
	NewService,
	wire.Bind(new(AdminService), new(*Service)),
	NewAdminHandler,
)
