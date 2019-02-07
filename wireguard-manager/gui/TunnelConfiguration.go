package main

import (
	b64 "encoding/base64"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type ParserState int

const KeyLength = 32

const (
	inInterfaceSection ParserState = iota
	inPeerSection
	notInASection
)

type TunnelConfiguration struct {
	name        string
	wginterface InterfaceConfiguration
	peers       []PeerConfiguration
}
type PeerConfiguration struct {
	publicKey           []byte
	preSharedKey        *[]byte
	allowedIPs          []IPAddressRange
	endpoint            *Endpoint
	persistentKeepAlive uint16
	rxBytes             uint64
	txBytes             uint64
	lastHandshakeTime   time.Time
}
type InterfaceConfiguration struct {
	privateKey []byte
	addresses  []IPAddressRange
	listenPort uint16
	mtu        uint16
	dns        []DNSServer
}
type IPAddressRange struct {
	address             net.IP
	networkPrefixLength uint8
}

type DNSServer net.IP
type Endpoint struct {
	host   string
	iphost net.IP
	port   uint16
}

const (
	invalidLine                       = "Invalid line: ‘%v’."
	noInterface                       = "Configuration must have an ‘Interface’ section."
	multipleInterfaces                = "Configuration must have only one ‘Interface’ section."
	interfaceHasNoPrivateKey          = "Interface’s private key is required"
	interfaceHasInvalidPrivateKey     = "Private key is invalid."
	interfaceHasInvalidListenPort     = "Listen port ‘%v’ is invalid."
	interfaceHasInvalidAddress        = "Address ‘%v’ is invalid."
	interfaceHasInvalidDNS            = "DNS ‘%v’ is invalid."
	interfaceHasInvalidMTU            = "MTU ‘%v’ is invalid."
	interfaceHasUnrecognizedKey       = "Interface contains unrecognized key ‘%v’"
	peerHasNoPublicKey                = "Peer’s public key is required"
	peerHasInvalidPublicKey           = "Public key is invalid"
	peerHasInvalidPreSharedKey        = "Preshared key is invalid"
	peerHasInvalidAllowedIP           = "Allowed IP ‘%v’ is invalid"
	peerHasInvalidEndpoint            = "Endpoint ‘%v’ is invalid"
	peerHasInvalidPersistentKeepAlive = "Persistent keepalive value ‘%v’ is invalid"
	peerHasUnrecognizedKey            = "Peer contains unrecognized key ‘%v’"
	peerHasInvalidTransferBytes       = "Invalid line: ‘%v’."
	peerHasInvalidLastHandshakeTime   = "Invalid line: ‘%v’."
	multiplePeersWithSamePublicKey    = "Two or more peers cannot have the same public key"
	multipleEntriesForKey             = "There should be only one entry per section for key ‘%v’"
)

func (r IPAddressRange) String() string {
	return fmt.Sprintf("%v/%v", r.address, r.networkPrefixLength)
}

func (d DNSServer) String() string {
	return net.IP(d).String()
}

func (e Endpoint) String() string {
	if e.host != "" {
		return fmt.Sprintf("%v:%v", e.host, e.port)
	}
	if p4 := e.iphost.To4(); len(p4) == net.IPv4len {
		return fmt.Sprintf("%v:%v", e.host, e.port)
	}
	return fmt.Sprintf("[%v]:%v", e.host, e.port)
}

func (conf TunnelConfiguration) asWgQuickConfig() string {
	var output strings.Builder
	output.WriteString("[Interface]\n")
	output.WriteString("PrivateKey = " + b64.StdEncoding.EncodeToString(conf.wginterface.privateKey) + "\n")
	if conf.wginterface.listenPort > 0 {
		output.WriteString(fmt.Sprintf("ListenPort = %v\n", conf.wginterface.listenPort))
	}

	if len(conf.wginterface.addresses) > 0 {

		for i, address := range conf.wginterface.addresses {
			if i == 0 {
				output.WriteString("Address = " + address.String())
			} else {
				output.WriteString(", ")
				output.WriteString(address.String())
			}
		}
		output.WriteString("\n")
	}

	if len(conf.wginterface.dns) > 0 {

		for i, dns := range conf.wginterface.dns {
			if i == 0 {
				output.WriteString("DNS = " + dns.String())
			} else {
				output.WriteString(", ")
				output.WriteString(dns.String())
			}
		}
		output.WriteString("\n")
	}
	if conf.wginterface.mtu > 0 {
		output.WriteString(fmt.Sprintf("MTU = %v\n", conf.wginterface.mtu))
	}

	for _, peer := range conf.peers {
		output.WriteString("\n[Peer]\n")
		output.WriteString("PublicKey = " + b64.StdEncoding.EncodeToString(peer.publicKey) + "\n")
		if peer.preSharedKey != nil {
			output.WriteString("PresharedKey = " + b64.StdEncoding.EncodeToString(*peer.preSharedKey) + "\n")
		}

		if len(peer.allowedIPs) > 0 {

			for i, allowedIP := range peer.allowedIPs {
				if i == 0 {
					output.WriteString("AllowedIPs = " + allowedIP.String())
				} else {
					output.WriteString(", ")
					output.WriteString(allowedIP.String())
				}
			}
			output.WriteString("\n")
		}
		if peer.endpoint != nil {
			output.WriteString("Endpoint = " + peer.endpoint.String() + "\n")
		}
		if peer.persistentKeepAlive > 0 {
			output.WriteString(fmt.Sprintf("PersistentKeepalive = %v\n", peer.persistentKeepAlive))
		}
	}
	return output.String()
}

func readTunnelConfiguration(wgQuickConfig string, called string) (TunnelConfiguration, error) {
	lines := strings.Split(wgQuickConfig, "\n")
	parserState := notInASection
	conf := TunnelConfiguration{}
	attributes := make(map[string]string)
	peers := make([]PeerConfiguration, 0)
	for lineIndex, line := range lines {
		trimmedLine := strings.TrimSpace(strings.Split(line, "#")[0])
		trimmedLineLower := strings.ToLower(trimmedLine)
		if len(trimmedLine) > 0 {
			equalsIndex := strings.Index(trimmedLine, "=")
			if equalsIndex > 0 {
				keyWithCase := strings.TrimSpace(trimmedLine[:equalsIndex])
				key := strings.ToLower(keyWithCase)
				value := strings.TrimSpace(trimmedLine[equalsIndex+1:])
				presentValue, haskey := attributes[key]
				if haskey {
					switch key {
					case "address", "allowedips", "dns":
						attributes[key] = presentValue + ", " + value
					default:
						return conf, fmt.Errorf(multipleEntriesForKey, key)
					}
				} else {
					attributes[key] = value
				}
				switch parserState {
				case inPeerSection:
					switch key {
					case "publickey", "presharedkey", "allowedips", "endpoint", "persistentkeepalive":
					default:
						return conf, fmt.Errorf(peerHasUnrecognizedKey, key)
					}
				case inInterfaceSection:
					switch key {
					case "privatekey", "listenport", "address", "dns", "mtu":
					default:
						return conf, fmt.Errorf(interfaceHasUnrecognizedKey, key)
					}
				}

			} else if trimmedLineLower != "[interface]" && trimmedLineLower != "[peer]" {
				return conf, fmt.Errorf(invalidLine, line)
			}
		}

		isLastLine := lineIndex == len(lines)-1
		if isLastLine || trimmedLineLower == "[interface]" || trimmedLineLower == "[peer]" {
			// Previous section has ended; process the attributes collected so far
			if parserState == inInterfaceSection {
				interfaceConf, err := collateInterfaceAttributes(attributes)
				if err != nil {
					return conf, err
				}
				conf.wginterface = interfaceConf
				//todo: check for multiple
			} else if parserState == inPeerSection {
				peer, err := collatePeerAttributes(attributes)
				if err != nil {
					return conf, err
				}
				peers = append(peers, peer)
			}
		}

		if trimmedLineLower == "[interface]" {
			parserState = inInterfaceSection
			attributes = make(map[string]string)
		} else if trimmedLineLower == "[peer]" {
			parserState = inPeerSection
			attributes = make(map[string]string)
		}

	}
	conf.peers = peers
	return conf, nil

}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func collateInterfaceAttributes(attributes map[string]string) (InterfaceConfiguration, error) {
	conf := InterfaceConfiguration{}
	//conf.addresses = make([]IPAddressRange, 0)
	//conf.dns = make([]DNSServer, 0)
	privateKeyString, c := attributes["privatekey"]
	if !c {
		return conf, fmt.Errorf(interfaceHasNoPrivateKey)
	}

	if privateKey, err := b64.StdEncoding.DecodeString(privateKeyString); err != nil || len(privateKey) != KeyLength {
		return conf, fmt.Errorf(interfaceHasInvalidPrivateKey)
	} else {
		conf.privateKey = privateKey
	}

	if listenPortString, c := attributes["listenport"]; c {
		if listenPort, err := strconv.Atoi(listenPortString); err == nil {
			conf.listenPort = uint16(listenPort)
		} else {
			return conf, fmt.Errorf(interfaceHasInvalidListenPort, listenPortString)
		}
	}

	if addressesString, c := attributes["address"]; c {
		for _, addressString := range strings.Split(addressesString, ",") {
			conf.addresses = append(conf.addresses, parseIPAddressRange(addressString))
		}
	}

	if dnsStrings, c := attributes["dns"]; c {
		for _, dnsString := range strings.Split(dnsStrings, ",") {
			ip := net.ParseIP(strings.TrimSpace(dnsString))
			if ip == nil {
				fmt.Errorf(interfaceHasInvalidDNS, dnsString)
			}
			dns := DNSServer(ip)
			conf.dns = append(conf.dns, dns)
		}
	}

	if mtuString, c := attributes["mtu"]; c {
		if mtu, err := strconv.Atoi(mtuString); err == nil {
			conf.mtu = uint16(mtu)
		} else {
			return conf, fmt.Errorf(interfaceHasInvalidMTU, mtuString)
		}
	}

	return conf, nil
}

func collatePeerAttributes(attributes map[string]string) (PeerConfiguration, error) {
	conf := PeerConfiguration{}
	//conf.allowedIPs = make([]IPAddressRange, 0)
	publicKeyString, c := attributes["publickey"]
	if !c {
		return conf, fmt.Errorf(peerHasNoPublicKey)
	}

	publicKey, err := b64.StdEncoding.DecodeString(publicKeyString)
	if err != nil || len(publicKey) != KeyLength {
		return conf, fmt.Errorf(peerHasInvalidPublicKey)
	}
	conf.publicKey = publicKey

	if preSharedKeyString, c := attributes["presharedkey"]; c {
		if preSharedKey, err := b64.StdEncoding.DecodeString(preSharedKeyString); err == nil && len(preSharedKey) == KeyLength {
			conf.preSharedKey = &preSharedKey
		} else {
			return conf, fmt.Errorf(peerHasInvalidPreSharedKey)
		}
	}

	if allowedIPsString, c := attributes["allowedips"]; c {
		for _, allowedIPString := range strings.Split(allowedIPsString, ",") {
			conf.allowedIPs = append(conf.allowedIPs, parseIPAddressRange(allowedIPString))
		}
	}

	if endpointString, c := attributes["endpoint"]; c {
		if endpoint, err := parseEndpoint(endpointString); err == nil {
			conf.endpoint = &endpoint
		} else {
			return conf, fmt.Errorf(peerHasInvalidEndpoint, endpointString)
		}
	}
	if persistentKeepAliveString, c := attributes["persistentkeepalive"]; c {
		if persistentKeepAlive, err := strconv.Atoi(persistentKeepAliveString); err == nil {
			conf.persistentKeepAlive = uint16(persistentKeepAlive)
		} else {
			return conf, fmt.Errorf(peerHasInvalidPersistentKeepAlive, persistentKeepAliveString)
		}
	}
	return conf, nil
}

func parseIPAddressRange(addressString string) IPAddressRange {
	addressrange := IPAddressRange{}
	addressSplit := strings.Split(strings.TrimSpace(addressString), "/")
	addressrange.address = net.ParseIP(addressSplit[0]) //test for nil?

	maxNetworkPrefixLength := 128
	if addressrange.address.To4() != nil {
		maxNetworkPrefixLength = 32
	}
	addressrange.networkPrefixLength = uint8(maxNetworkPrefixLength)
	if len(addressSplit) == 2 {
		if networkPrefixLength, err := strconv.Atoi(addressSplit[1]); err == nil {
			addressrange.networkPrefixLength = uint8(min(networkPrefixLength, maxNetworkPrefixLength))
		}
	}
	return addressrange
}

func parseEndpoint(s string) (Endpoint, error) {
	endpoint := Endpoint{}
	if len(s) == 0 {
		return endpoint, errors.New("emptyEndpoint")
	}
	endOfHostIndex := strings.LastIndex(s, ":")
	if port, err := strconv.Atoi(s[endOfHostIndex+1:]); err != nil {
		return endpoint, errors.New("Problem parsing port")
	} else {
		endpoint.port = uint16(port)
	}
	if s[0] == '[' { //assume ipv6
		if s[endOfHostIndex-1] != ']' {
			return endpoint, errors.New("Unable to find matching brace of IPv6 endpoint")
		}
		if endpoint.iphost = net.ParseIP(s[1 : endOfHostIndex-1]); endpoint.iphost == nil {
			return endpoint, errors.New("Invalid IPv6")
		}
	}
	if host := net.ParseIP(s[:endOfHostIndex]); host == nil {
		endpoint.host = s[:endOfHostIndex]
	} else {
		endpoint.iphost = host
	}
	return endpoint, nil

}
