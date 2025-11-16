package resolver

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/go-rootcerts"
	"github.com/nats-io/nats.go"
)

// NatsTLSConfig contains the parameters needed to configure TLS for NATS connections
type NatsTLSConfig struct {
	// CACert is the path to a PEM-encoded CA cert file or comma-separated list of files
	// to use to verify the NATS server SSL certificate.
	CACert string

	// CAPath is the path to a directory of PEM-encoded CA cert files to verify
	// the NATS server SSL certificate.
	CAPath string

	// ClientCert is the path to the certificate for NATS communication
	ClientCert string

	// ClientKey is the path to the private key for NATS communication
	ClientKey string

	// TLSServerName, if set, is used to set the SNI host when connecting via TLS.
	TLSServerName string

	// Insecure enables or disables SSL verification
	Insecure bool
}

// NatsPluginConfig is a helper that plugins can use to configure TLS connections
// to NATS servers.
type NatsPluginConfig struct {
	flagCACert        string
	flagCAPath        string
	flagClientCert    string
	flagClientKey     string
	flagTLSServerName string
	flagInsecure      bool
}

// FlagSet returns the flag set for configuring the TLS connection to NATS
func (n *NatsPluginConfig) FlagSet() *flag.FlagSet {
	fs := flag.NewFlagSet("nats plugin settings", flag.ContinueOnError)

	fs.StringVar(&n.flagCACert, "nats-ca-cert", "", "Path to a PEM-encoded CA cert file or comma-separated list of files to use to verify the NATS server SSL certificate")
	fs.StringVar(&n.flagCAPath, "nats-ca-path", "", "Path to a directory of PEM-encoded CA cert files to verify the NATS server SSL certificate")
	fs.StringVar(&n.flagClientCert, "nats-client-cert", "", "Path to the certificate for NATS communication")
	fs.StringVar(&n.flagClientKey, "nats-client-key", "", "Path to the private key for NATS communication")
	fs.StringVar(&n.flagTLSServerName, "nats-tls-server-name", "", "SNI server name to use when connecting via TLS")
	fs.BoolVar(&n.flagInsecure, "nats-tls-skip-verify", false, "Skip TLS verification for NATS connections (not recommended for production)")

	return fs
}

// GetTLSConfig will return a NatsTLSConfig based off the values from the flags
func (n *NatsPluginConfig) GetTLSConfig() *NatsTLSConfig {
	if n.flagCACert != "" || n.flagCAPath != "" || n.flagClientCert != "" || n.flagClientKey != "" || n.flagTLSServerName != "" || n.flagInsecure {
		t := &NatsTLSConfig{
			CACert:        n.flagCACert,
			CAPath:        n.flagCAPath,
			ClientCert:    n.flagClientCert,
			ClientKey:     n.flagClientKey,
			TLSServerName: n.flagTLSServerName,
			Insecure:      n.flagInsecure,
		}

		return t
	}

	return nil
}

var natsTLSConfig *NatsTLSConfig

// SetNatsTLSConfig sets the NATS TLS configuration
func SetNatsTLSConfig(config *NatsTLSConfig) {
	natsTLSConfig = config
}

// buildNatsTLSOptions builds NATS TLS options from the configured TLS config
func buildNatsTLSOptions() ([]nats.Option, error) {
	if natsTLSConfig == nil {
		return nil, nil
	}

	var opts []nats.Option
	var tlsConfig *tls.Config
	needsCustomTLSConfig := natsTLSConfig.Insecure || natsTLSConfig.TLSServerName != "" || natsTLSConfig.CAPath != ""

	if needsCustomTLSConfig {
		tlsConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}

		if natsTLSConfig.Insecure {
			tlsConfig.InsecureSkipVerify = true
		}

		if natsTLSConfig.TLSServerName != "" {
			tlsConfig.ServerName = natsTLSConfig.TLSServerName
		}

		// Handle CAPath - load CA certs from directory
		if natsTLSConfig.CAPath != "" {
			rootConfig := &rootcerts.Config{
				CAPath: natsTLSConfig.CAPath,
			}
			pool, err := rootcerts.LoadCACerts(rootConfig)
			if err != nil {
				return nil, fmt.Errorf("error loading CA certificates from path: %w", err)
			}
			tlsConfig.RootCAs = pool
		}
	}

	if natsTLSConfig.CACert != "" {
		caFiles := strings.Split(natsTLSConfig.CACert, ",")
		for i := range caFiles {
			caFiles[i] = strings.TrimSpace(caFiles[i])
		}

		if tlsConfig != nil {
			if tlsConfig.RootCAs == nil {
				tlsConfig.RootCAs = x509.NewCertPool()
			}
			for _, file := range caFiles {
				if file == "" {
					continue
				}
				pem, err := os.ReadFile(file)
				if err != nil {
					return nil, fmt.Errorf("error reading CA certificate file %s: %w", file, err)
				}
				if !tlsConfig.RootCAs.AppendCertsFromPEM(pem) {
					return nil, fmt.Errorf("error parsing CA certificate from file %s", file)
				}
			}
		} else {
			opts = append(opts, nats.RootCAs(caFiles...))
		}
	}

	if natsTLSConfig.ClientCert != "" || natsTLSConfig.ClientKey != "" {
		if natsTLSConfig.ClientCert == "" || natsTLSConfig.ClientKey == "" {
			return nil, fmt.Errorf("both nats-client-cert and nats-client-key must be provided")
		}

		if tlsConfig != nil {
			cert, err := tls.LoadX509KeyPair(natsTLSConfig.ClientCert, natsTLSConfig.ClientKey)
			if err != nil {
				return nil, fmt.Errorf("error loading client certificate: %w", err)
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		} else {
			opts = append(opts, nats.ClientCert(natsTLSConfig.ClientCert, natsTLSConfig.ClientKey))
		}
	}

	if tlsConfig != nil {
		opts = append(opts, nats.Secure(tlsConfig))
	}

	return opts, nil
}

// buildFlagNameSet builds a map of flag names (with - and -- prefixes) from a FlagSet
func buildFlagNameSet(fs *flag.FlagSet) map[string]bool {
	flagNames := make(map[string]bool)
	fs.VisitAll(func(f *flag.Flag) {
		flagNames["-"+f.Name] = true
		flagNames["--"+f.Name] = true
	})
	return flagNames
}

// extractFlagName extracts the flag name from an argument, handling both -flag and --flag formats
// and -flag=value syntax
func extractFlagName(arg string) string {
	if strings.HasPrefix(arg, "--") {
		parts := strings.SplitN(arg[2:], "=", 2)
		return "--" + parts[0]
	} else if strings.HasPrefix(arg, "-") {
		parts := strings.SplitN(arg[1:], "=", 2)
		return "-" + parts[0]
	}
	return arg
}

// SeparateFlags separates command-line arguments into buckets for different flag sets.
// It takes the full argument list and both flag sets, then routes each flag to the
// appropriate bucket. This allows multiple flag parsers to coexist without conflicts.
func SeparateFlags(args []string, natsFlags, vaultFlags *flag.FlagSet) (natsArgs, vaultArgs []string) {
	natsFlagNames := buildFlagNameSet(natsFlags)
	vaultFlagNames := buildFlagNameSet(vaultFlags)

	natsArgs = make([]string, 0)
	vaultArgs = make([]string, 0)

	i := 0
	for i < len(args) {
		arg := args[i]
		flagName := extractFlagName(arg)

		if natsFlagNames[flagName] {
			natsArgs = append(natsArgs, arg)
			i++
			if !strings.Contains(arg, "=") && i < len(args) && !strings.HasPrefix(args[i], "-") {
				natsArgs = append(natsArgs, args[i])
				i++
			}
		} else if vaultFlagNames[flagName] {
			vaultArgs = append(vaultArgs, arg)
			i++
			if !strings.Contains(arg, "=") && i < len(args) && !strings.HasPrefix(args[i], "-") {
				vaultArgs = append(vaultArgs, args[i])
				i++
			}
		} else {
			i++
		}
	}

	return natsArgs, vaultArgs
}
