package conf

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

func (conf *Config) ToWgQuick() string {
	var output strings.Builder
	output.WriteString("[Interface]\n")

	output.WriteString(fmt.Sprintf("PrivateKey = %s\n", conf.Interface.PrivateKey.String()))

	if conf.Interface.ListenPort > 0 {
		output.WriteString(fmt.Sprintf("ListenPort = %d\n", conf.Interface.ListenPort))
	}

	if len(conf.Interface.Addresses) > 0 {
		var addrStrings [len(conf.Interface.Addresses)]string
		for i, address := range conf.Interface.Addresses {
			addrStrings[i] = address.String()
		}
		output.WriteString(fmt.Sprintf("Address = %s\n", strings.Join(addrStrings[:], ", ")))
	}

	if len(conf.Interface.Dns) > 0 {
		var addrStrings [len(conf.Interface.Dns)]string
		for i, address := range conf.Interface.Dns {
			addrStrings[i] = address.String()
		}
		output.WriteString(fmt.Sprintf("DNS = %s\n", strings.Join(addrStrings[:], ", ")))
	}

	if conf.Interface.Mtu > 0 {
		output.WriteString(fmt.Sprintf("MTU = %d\n", conf.Interface.Mtu))
	}

	for _, peer := range conf.Peers {
		output.WriteString("\n[Peer]\n")

		output.WriteString(fmt.Sprintf("PublicKey = %s\n", peer.PublicKey.String()))

		if !peer.PresharedKey.IsZero() {
			output.WriteString(fmt.Sprintf("PresharedKey = %s\n", peer.PresharedKey.String()))
		}

		if len(peer.AllowedIPs) > 0 {
			var addrStrings [len(peer.AllowedIPs)]string
			for i, address := range peer.AllowedIPs {
				addrStrings[i] = address.String()
			}
			output.WriteString(fmt.Sprintf("AllowedIPs = %s\n", strings.Join(addrStrings[:], ", ")))
		}

		if !peer.Endpoint.IsEmpty() {
			output.WriteString(fmt.Sprintf("Endpoint = %s\n", peer.Endpoint.String()))
		}

		if peer.PersistentKeepalive > 0 {
			output.WriteString(fmt.Sprintf("PersistentKeepalive = %d\n", peer.PersistentKeepalive))
		}
	}
	return output.String()
}

func (conf *Config) ToUAPI() (string, error) {
	var output strings.Builder
	output.WriteString(fmt.Sprintf("private_key=%s\n", conf.Interface.PrivateKey.HexString()))

	if conf.Interface.ListenPort > 0 {
		output.WriteString(fmt.Sprintf("listen_port=%d\n", conf.Interface.ListenPort))
	}

	if len(conf.Peers) > 0 {
		output.WriteString("replace_peers=true\n")
	}

	for _, peer := range conf.Peers {
		output.WriteString(fmt.Sprintf("public_key=%s\n", peer.PublicKey.HexString()))

		if !peer.PresharedKey.IsZero() {
			output.WriteString(fmt.Sprintf("preshared_key = %s\n", peer.PresharedKey.String()))
		}

		if !peer.Endpoint.IsEmpty() {
			ips, err := net.LookupIP(peer.Endpoint.Host)
			if err != nil {
				return "", err
			}
			var ip net.IP
			for _, iterip := range ips {
				iterip = iterip.To4()
				if iterip != nil {
					ip = iterip
					break
				}
				if ip == nil {
					ip = iterip
				}
			}
			if ip == nil {
				return "", errors.New("Unable to resolve IP address of endpoint")
			}
			resolvedEndpoint := Endpoint{ip.String(), peer.Endpoint.Port}
			output.WriteString(fmt.Sprintf("endpoint=%s\n", resolvedEndpoint.String()))
		}

		output.WriteString(fmt.Sprintf("persistent_keepalive_interval=%d\n", peer.PersistentKeepalive))

		if len(peer.AllowedIPs) > 0 {
			output.WriteString("replace_allowed_ips=true\n")
			for _, address := range peer.AllowedIPs {
				output.WriteString(fmt.Sprintf("allowed_ip=%s\n", address.String()))
			}
		}
	}
	return output.String(), nil
}
