package main

import (
	"os"

	nats "github.com/gabber235/vault-plugin-secrets-nats"
	"github.com/gabber235/vault-plugin-secrets-nats/pkg/resolver"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	args := os.Args[1:]

	natsConfig := &resolver.NatsPluginConfig{}
	natsFlags := natsConfig.FlagSet()

	apiClientMeta := &api.PluginAPIClientMeta{}
	vaultFlags := apiClientMeta.FlagSet()

	natsArgs, vaultArgs := resolver.SeparateFlags(args, natsFlags, vaultFlags)

	_ = natsFlags.Parse(natsArgs)
	natsTLSConfig := natsConfig.GetTLSConfig()
	if natsTLSConfig != nil {
		resolver.SetNatsTLSConfig(natsTLSConfig)
	}

	_ = vaultFlags.Parse(vaultArgs)
	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: nats.Factory,
		TLSProviderFunc:    tlsProviderFunc,
	})
	if err != nil {
		log.Error().Err(err).Msg("plugin shutting down")
		os.Exit(1)
	}
}
