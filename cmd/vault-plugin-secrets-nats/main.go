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

	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:])

	natsConfig := &resolver.NatsPluginConfig{}
	natsFlags := natsConfig.FlagSet()
	_ = natsFlags.Parse(os.Args[1:])

	natsTLSConfig := natsConfig.GetTLSConfig()
	if natsTLSConfig != nil {
		resolver.SetNatsTLSConfig(natsTLSConfig)
	}

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
