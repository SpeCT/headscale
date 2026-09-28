package types

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveHTTPSCerts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		dns            DNSConfig
		serverURL      string
		wantErr        error
		wantNameserver string
		wantListenAddr string
	}{
		{
			name:    "disabled is a no-op",
			dns:     DNSConfig{HTTPSCerts: HTTPSCertsConfig{Enabled: false}},
			wantErr: nil,
		},
		{
			name:      "requires magic dns",
			dns:       DNSConfig{MagicDNS: false, BaseDomain: "ts.example.com", HTTPSCerts: HTTPSCertsConfig{Enabled: true}},
			serverURL: "https://headscale.example.com",
			wantErr:   errHTTPSCertsRequiresMagicDNS,
		},
		{
			name:      "requires base domain",
			dns:       DNSConfig{MagicDNS: true, HTTPSCerts: HTTPSCertsConfig{Enabled: true}},
			serverURL: "https://headscale.example.com",
			wantErr:   errHTTPSCertsRequiresBaseDomain,
		},
		{
			name:      "rejects malformed listen address",
			dns:       DNSConfig{MagicDNS: true, BaseDomain: "ts.example.com", HTTPSCerts: HTTPSCertsConfig{Enabled: true, ListenAddr: "53"}},
			serverURL: "https://headscale.example.com",
			wantErr:   errHTTPSCertsInvalidListenAddr,
		},
		{
			name:      "nameserver required when server_url has no host",
			dns:       DNSConfig{MagicDNS: true, BaseDomain: "ts.example.com", HTTPSCerts: HTTPSCertsConfig{Enabled: true}},
			serverURL: "not a url",
			wantErr:   errHTTPSCertsNoNameserver,
		},
		{
			name:      "nameserver required when server_url host is an IP",
			dns:       DNSConfig{MagicDNS: true, BaseDomain: "ts.example.com", HTTPSCerts: HTTPSCertsConfig{Enabled: true}},
			serverURL: "http://203.0.113.10:8080",
			wantErr:   errHTTPSCertsNoNameserver,
		},
		{
			name:           "defaults nameserver to server_url host and listen_addr to :53",
			dns:            DNSConfig{MagicDNS: true, BaseDomain: "ts.example.com", HTTPSCerts: HTTPSCertsConfig{Enabled: true}},
			serverURL:      "https://headscale.example.com:443",
			wantNameserver: "headscale.example.com",
			wantListenAddr: ":53",
		},
		{
			name:           "explicit nameserver is normalised",
			dns:            DNSConfig{MagicDNS: true, BaseDomain: "ts.example.com", HTTPSCerts: HTTPSCertsConfig{Enabled: true, ListenAddr: "0.0.0.0:5353", Nameserver: "NS1.Example.COM."}},
			serverURL:      "https://headscale.example.com",
			wantNameserver: "ns1.example.com",
			wantListenAddr: "0.0.0.0:5353",
		},
		{
			name:           "in-zone nameserver is accepted",
			dns:            DNSConfig{MagicDNS: true, BaseDomain: "ts.example.com", HTTPSCerts: HTTPSCertsConfig{Enabled: true, Nameserver: "ns.ts.example.com"}},
			serverURL:      "https://headscale.example.com",
			wantNameserver: "ns.ts.example.com",
			wantListenAddr: ":53",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dnsCfg := tt.dns
			err := dnsCfg.resolveHTTPSCerts(tt.serverURL)

			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)

				return
			}

			require.NoError(t, err)

			if tt.dns.HTTPSCerts.Enabled {
				assert.Equal(t, tt.wantNameserver, dnsCfg.HTTPSCerts.Nameserver)
				assert.Equal(t, tt.wantListenAddr, dnsCfg.HTTPSCerts.ListenAddr)
			}
		})
	}
}

// TestLoadConfigHTTPSCerts verifies the YAML keys map onto the config struct
// and that the defaults apply when the section is absent.
func TestLoadConfigHTTPSCerts(t *testing.T) {
	tmpDir := t.TempDir()
	configYAML := []byte(`
server_url: https://headscale.example.com
listen_addr: 0.0.0.0:8080
noise:
  private_key_path: ` + filepath.Join(tmpDir, "noise.key") + `
database:
  type: sqlite3
prefixes:
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48
dns:
  magic_dns: true
  base_domain: ts.example.com
  override_local_dns: false
  https_certs:
    enabled: true
    listen_addr: ":5353"
    nameserver: ns1.example.com
`)
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "config.yaml"), configYAML, 0o600))

	viper.Reset()
	require.NoError(t, LoadConfig(tmpDir, false))

	dnsCfg, err := dns()
	require.NoError(t, err)

	assert.True(t, dnsCfg.HTTPSCerts.Enabled)
	assert.Equal(t, ":5353", dnsCfg.HTTPSCerts.ListenAddr)
	assert.Equal(t, "ns1.example.com", dnsCfg.HTTPSCerts.Nameserver)

	cfg, err := LoadServerConfig()
	require.NoError(t, err)
	assert.True(t, cfg.DNSConfig.HTTPSCerts.Enabled)
	assert.Equal(t, "ns1.example.com", cfg.DNSConfig.HTTPSCerts.Nameserver)

	// Defaults when the section is missing.
	viper.Reset()
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "config.yaml"), []byte(`
server_url: https://headscale.example.com
listen_addr: 0.0.0.0:8080
noise:
  private_key_path: `+filepath.Join(tmpDir, "noise.key")+`
database:
  type: sqlite3
prefixes:
  v4: 100.64.0.0/10
dns:
  magic_dns: true
  base_domain: ts.example.com
  override_local_dns: false
`), 0o600))
	require.NoError(t, LoadConfig(tmpDir, false))

	dnsCfg, err = dns()
	require.NoError(t, err)

	assert.False(t, dnsCfg.HTTPSCerts.Enabled)
	assert.Empty(t, dnsCfg.HTTPSCerts.ListenAddr, "defaults apply only once the feature is enabled")
	assert.Empty(t, dnsCfg.HTTPSCerts.Nameserver)

	cfg, err = LoadServerConfig()
	require.NoError(t, err)
	assert.False(t, cfg.DNSConfig.HTTPSCerts.Enabled)
	assert.Empty(t, cfg.DNSConfig.HTTPSCerts.ListenAddr)
}
