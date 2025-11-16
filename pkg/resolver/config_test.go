package resolver

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/stretchr/testify/assert"
)

func TestFlagParsing_AllFlags(t *testing.T) {
	testCases := []struct {
		name     string
		flagName string
		value    string
		check    func(*testing.T, *NatsPluginConfig)
	}{
		{
			name:     "nats-ca-cert",
			flagName: "nats-ca-cert",
			value:    "/path/to/ca.crt",
			check: func(t *testing.T, c *NatsPluginConfig) {
				assert.Equal(t, "/path/to/ca.crt", c.flagCACert)
			},
		},
		{
			name:     "nats-ca-path",
			flagName: "nats-ca-path",
			value:    "/path/to/ca/dir",
			check: func(t *testing.T, c *NatsPluginConfig) {
				assert.Equal(t, "/path/to/ca/dir", c.flagCAPath)
			},
		},
		{
			name:     "nats-client-cert",
			flagName: "nats-client-cert",
			value:    "/path/to/client.crt",
			check: func(t *testing.T, c *NatsPluginConfig) {
				assert.Equal(t, "/path/to/client.crt", c.flagClientCert)
			},
		},
		{
			name:     "nats-client-key",
			flagName: "nats-client-key",
			value:    "/path/to/client.key",
			check: func(t *testing.T, c *NatsPluginConfig) {
				assert.Equal(t, "/path/to/client.key", c.flagClientKey)
			},
		},
		{
			name:     "nats-tls-server-name",
			flagName: "nats-tls-server-name",
			value:    "example.com",
			check: func(t *testing.T, c *NatsPluginConfig) {
				assert.Equal(t, "example.com", c.flagTLSServerName)
			},
		},
		{
			name:     "nats-tls-skip-verify",
			flagName: "nats-tls-skip-verify",
			value:    "true",
			check: func(t *testing.T, c *NatsPluginConfig) {
				assert.True(t, c.flagInsecure)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &NatsPluginConfig{}
			fs := config.FlagSet()
			err := fs.Parse([]string{"-" + tc.flagName, tc.value})
			assert.NoError(t, err)
			tc.check(t, config)
		})
	}
}

func TestGetTLSConfig_ReturnsNilWhenNoFlags(t *testing.T) {
	config := &NatsPluginConfig{}
	result := config.GetTLSConfig()
	assert.Nil(t, result)
}

func TestGetTLSConfig_ReturnsConfigWhenFlagsSet(t *testing.T) {
	config := &NatsPluginConfig{
		flagCACert:        "/path/to/ca.crt",
		flagCAPath:        "/path/to/ca/dir",
		flagClientCert:    "/path/to/client.crt",
		flagClientKey:     "/path/to/client.key",
		flagTLSServerName: "example.com",
		flagInsecure:      true,
	}

	result := config.GetTLSConfig()
	assert.NotNil(t, result)
	assert.Equal(t, "/path/to/ca.crt", result.CACert)
	assert.Equal(t, "/path/to/ca/dir", result.CAPath)
	assert.Equal(t, "/path/to/client.crt", result.ClientCert)
	assert.Equal(t, "/path/to/client.key", result.ClientKey)
	assert.Equal(t, "example.com", result.TLSServerName)
	assert.True(t, result.Insecure)
}

func TestGetTLSConfig_ReturnsConfigWhenAnyFlagSet(t *testing.T) {
	testCases := []struct {
		name   string
		config *NatsPluginConfig
	}{
		{
			name: "only CACert",
			config: &NatsPluginConfig{
				flagCACert: "/path/to/ca.crt",
			},
		},
		{
			name: "only Insecure",
			config: &NatsPluginConfig{
				flagInsecure: true,
			},
		},
		{
			name: "only ServerName",
			config: &NatsPluginConfig{
				flagTLSServerName: "example.com",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.config.GetTLSConfig()
			assert.NotNil(t, result)
		})
	}
}

func TestBuildNatsTLSOptions_InsecureSkipVerify(t *testing.T) {
	SetNatsTLSConfig(&NatsTLSConfig{Insecure: true})
	defer SetNatsTLSConfig(nil)

	opts, err := buildNatsTLSOptions()
	assert.NoError(t, err)
	assert.NotNil(t, opts)
	assert.Len(t, opts, 1)

	var natsOpts nats.Options
	for _, opt := range opts {
		err := opt(&natsOpts)
		assert.NoError(t, err)
	}

	assert.True(t, natsOpts.Secure)
	assert.NotNil(t, natsOpts.TLSConfig)
	assert.True(t, natsOpts.TLSConfig.InsecureSkipVerify)
	assert.Equal(t, tls.VersionTLS12, int(natsOpts.TLSConfig.MinVersion))
}

func createTempCACert(t *testing.T) string {
	t.Helper()

	caCert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	caBytes, err := x509.CreateCertificate(rand.Reader, caCert, caCert, &caKey.PublicKey, caKey)
	assert.NoError(t, err)

	file, err := os.CreateTemp("", "test-ca-*.pem")
	assert.NoError(t, err)
	defer file.Close()

	err = pem.Encode(file, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	assert.NoError(t, err)

	return file.Name()
}

func TestBuildNatsTLSOptions_CACertFile(t *testing.T) {
	caFile := createTempCACert(t)
	defer os.Remove(caFile)

	SetNatsTLSConfig(&NatsTLSConfig{CACert: caFile})
	defer SetNatsTLSConfig(nil)

	opts, err := buildNatsTLSOptions()
	assert.NoError(t, err)
	assert.NotNil(t, opts)
	assert.Len(t, opts, 1)

	var natsOpts nats.Options
	for _, opt := range opts {
		err := opt(&natsOpts)
		assert.NoError(t, err)
	}

	assert.True(t, natsOpts.Secure)
	assert.NotNil(t, natsOpts.TLSConfig)
	assert.NotNil(t, natsOpts.TLSConfig.RootCAs)
}

func createTempClientCert(t *testing.T) (string, string) {
	t.Helper()

	caCert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	_, err = x509.CreateCertificate(rand.Reader, caCert, caCert, &caKey.PublicKey, caKey)
	assert.NoError(t, err)

	clientCert := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Test Client"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	clientBytes, err := x509.CreateCertificate(rand.Reader, clientCert, caCert, &clientKey.PublicKey, caKey)
	assert.NoError(t, err)

	certFile, err := os.CreateTemp("", "test-client-*.crt")
	assert.NoError(t, err)
	defer certFile.Close()

	err = pem.Encode(certFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: clientBytes,
	})
	assert.NoError(t, err)

	keyFile, err := os.CreateTemp("", "test-client-*.key")
	assert.NoError(t, err)
	defer keyFile.Close()

	keyBytes := x509.MarshalPKCS1PrivateKey(clientKey)
	err = pem.Encode(keyFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	})
	assert.NoError(t, err)

	return certFile.Name(), keyFile.Name()
}

func TestBuildNatsTLSOptions_ClientCert(t *testing.T) {
	certFile, keyFile := createTempClientCert(t)
	defer os.Remove(certFile)
	defer os.Remove(keyFile)

	SetNatsTLSConfig(&NatsTLSConfig{
		ClientCert: certFile,
		ClientKey:  keyFile,
	})
	defer SetNatsTLSConfig(nil)

	opts, err := buildNatsTLSOptions()
	assert.NoError(t, err)
	assert.NotNil(t, opts)
	assert.Len(t, opts, 1)

	var natsOpts nats.Options
	for _, opt := range opts {
		err := opt(&natsOpts)
		assert.NoError(t, err)
	}

	assert.True(t, natsOpts.Secure)
	assert.NotNil(t, natsOpts.TLSConfig)
	assert.Len(t, natsOpts.TLSConfig.Certificates, 1)
}

func TestBuildNatsTLSOptions_ErrorMissingCACertFile(t *testing.T) {
	SetNatsTLSConfig(&NatsTLSConfig{
		CACert: "/nonexistent/path/to/ca.crt",
	})
	defer SetNatsTLSConfig(nil)

	opts, err := buildNatsTLSOptions()
	assert.NoError(t, err)
	assert.NotNil(t, opts)
	assert.Len(t, opts, 1)

	// The error occurs when the option is applied, not when it's created
	var natsOpts nats.Options
	err = opts[0](&natsOpts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "error loading or parsing rootCA file")
}

func TestBuildNatsTLSOptions_ErrorClientCertWithoutKey(t *testing.T) {
	testCases := []struct {
		name     string
		config   *NatsTLSConfig
		errorMsg string
	}{
		{
			name: "only ClientCert",
			config: &NatsTLSConfig{
				ClientCert: "/path/to/client.crt",
			},
			errorMsg: "both nats-client-cert and nats-client-key must be provided",
		},
		{
			name: "only ClientKey",
			config: &NatsTLSConfig{
				ClientKey: "/path/to/client.key",
			},
			errorMsg: "both nats-client-cert and nats-client-key must be provided",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			SetNatsTLSConfig(tc.config)
			defer SetNatsTLSConfig(nil)

			opts, err := buildNatsTLSOptions()
			assert.Error(t, err)
			assert.Nil(t, opts)
			assert.Contains(t, err.Error(), tc.errorMsg)
		})
	}
}

func TestBuildNatsTLSOptions_NoConfig(t *testing.T) {
	SetNatsTLSConfig(nil)
	defer SetNatsTLSConfig(nil)

	opts, err := buildNatsTLSOptions()
	assert.NoError(t, err)
	assert.Nil(t, opts)
}
