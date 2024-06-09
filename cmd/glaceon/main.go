package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"

	"github.com/caarlos0/env/v11"
	_ "github.com/joho/godotenv/autoload"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"gopkg.in/gcfg.v1"
)

type config struct {
	ProxyTo              *url.URL `env:"PROXY_TO,required"`
	WireguardConfigFname string   `env:"WIREGUARD_CONFIG_FNAME,required"`
	Listen               string   `env:"LISTEN" envDefault:":8080"`
}

func init() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", flag.CommandLine.Name())
		flag.PrintDefaults()
		fmt.Fprintln(flag.CommandLine.Output())
		fmt.Fprintln(flag.CommandLine.Output(), "Environment variables:")
		fmt.Fprintln(flag.CommandLine.Output(), "  PROXY_TO: URL to proxy to")
		fmt.Fprintln(flag.CommandLine.Output(), "  WIREGUARD_CONFIG_FNAME: path to WireGuard config file")
		fmt.Fprintln(flag.CommandLine.Output(), "  LISTEN: address to listen on")
	}
}

func main() {
	flag.Parse()

	var cfg config
	if err := env.Parse(&cfg); err != nil {
		log.Fatalf("failed to read envvars: %v", err)
	}

	slog.Debug("starting up", "proxyTo", cfg.ProxyTo.String(), "wireguardConfigFname", cfg.WireguardConfigFname, "listen", cfg.Listen)

	var wgc WireGuardConfig

	if err := gcfg.FatalOnly(gcfg.ReadFileInto(&wgc, cfg.WireguardConfigFname)); err != nil {
		log.Fatalf("failed to read wireguard config: %v", err)
	}

	addrRange, err := netip.ParsePrefix(wgc.Interface.Address)
	if err != nil {
		log.Fatalf("failed to parse address: %v", err)
	}

	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{addrRange.Addr()},
		[]netip.Addr{netip.MustParseAddr(wgc.Interface.DNS)},
		1280,
	)
	if err != nil {
		log.Fatalf("failed to create tun: %v", err)
	}

	var confBuf bytes.Buffer
	if err := wgc.UAPI(&confBuf); err != nil {
		log.Fatalf("failed to write UAPI: %v", err)
	}

	dev := device.NewDevice(tun, conn.NewStdNetBind(), device.NewLogger(device.LogLevelError, "wireguard: "))
	if err := dev.IpcSetOperation(&confBuf); err != nil {
		log.Fatalf("failed to set config: %v", err)
	}

	if err := dev.Up(); err != nil {
		log.Fatalf("failed to bring up device: %v", err)
	}

	slog.Info("starting app", "listen", cfg.Listen, "proxyTo", cfg.ProxyTo.String())

	switch cfg.ProxyTo.Scheme {
	case "http":
		tunCli := &http.Client{
			Transport: &http.Transport{
				DialContext: tnet.DialContext,
			},
		}
		rp := httputil.NewSingleHostReverseProxy(cfg.ProxyTo)
		rp.Transport = tunCli.Transport

		log.Fatal(http.ListenAndServe(cfg.Listen, rp))
	default:
		log.Fatalf("unsupported scheme: %s", cfg.ProxyTo.Scheme)
	}
}

// WireguardConfig is a struct that represents a fly.io WireGuard configuration.
//
// XXX: This is simplified so gcfg can parse it.
type WireGuardConfig struct {
	Interface WireGuardInterface
	Peer      WireGuardPeer
}

// UAPI writes the WireGuardConfig to the given io.Writer in UAPI format.
//
// I figured this out by reverse engineering what the `wg-quick` command does
// with strace. It's not documented anywhere.
func (wc WireGuardConfig) UAPI(out io.Writer) error {
	pkey, err := key2hex(wc.Interface.PrivateKey)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "private_key=%s\n", pkey)
	fmt.Fprintln(out, "listen_port=0")
	fmt.Fprintln(out, "replace_peers=true")

	pkey, err = key2hex(wc.Peer.PublicKey)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "public_key=%s\n", pkey)

	endpointHost, endpointPort, err := net.SplitHostPort(wc.Peer.Endpoint)
	if err != nil {
		return err
	}

	hosts, err := net.LookupHost(endpointHost)
	if err != nil {
		return err
	}

	for _, host := range hosts {
		fmt.Fprintf(out, "endpoint=%s:%s\n", host, endpointPort)
	}

	for _, aip := range strings.Split(wc.Peer.AllowedIPs, ",") {
		fmt.Fprintf(out, "allowed_ip=%s\n", aip)
	}
	fmt.Fprintf(out, "persistent_keepalive_interval=%d\n", wc.Peer.PersistentKeepalive)
	return nil
}

// WireGuardInterface is a struct that represents a WireGuard interface.
//
// Realistically, this should have more fields, but this is enough to represent
// fly.io WireGuard configurations.
type WireGuardInterface struct {
	PrivateKey string
	Address    string
	DNS        string
}

// WireGuardPeer is a struct that represents a WireGuard peer.
//
// Again, this is incomplete, but sufficient.
type WireGuardPeer struct {
	PublicKey           string
	AllowedIPs          string
	Endpoint            string
	PersistentKeepalive int
}

func key2hex(data string) (string, error) {
	buf := make([]byte, base64.StdEncoding.DecodedLen(len(data))-1)
	_, err := base64.StdEncoding.Decode(buf, []byte(data))
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(buf), nil
}
