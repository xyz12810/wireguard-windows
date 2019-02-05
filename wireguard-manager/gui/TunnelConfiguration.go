package main

import (
	b64 "encoding/base64"
	"errors"
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
	preSharedKey        []byte
	allowedIPs          []IPAddressRange
	endpoint            Endpoint
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
						return conf, errors.New("multipleEntriesForKey")
					}
				} else {
					attributes[key] = value
				}

			} else if trimmedLineLower != "[interface]" && trimmedLineLower != "[peer]" {
				return conf, errors.New("invalidLine")
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
		return conf, errors.New("interfaceHasNoPrivateKey")
	}

	if privateKey, err := b64.StdEncoding.DecodeString(privateKeyString); err != nil {
		return conf, errors.New("interfaceHasInvalidPrivateKey")
	} else {
		conf.privateKey = privateKey
	}

	if listenPortString, c := attributes["listenport"]; c {
		if listenPort, err := strconv.Atoi(listenPortString); err == nil {
			conf.listenPort = uint16(listenPort)
		} else {
			return conf, errors.New("interfaceHasInvalidListenPort")
		}
	}

	if addressesString, c := attributes["address"]; c {
		for _, addressString := range strings.Split(addressesString, ",") {
			conf.addresses = append(conf.addresses, parseIPAddressRange(addressString))
		}
	}

	if dnsStrings, c := attributes["dns"]; c {
		for _, dnsString := range strings.Split(dnsStrings, ",") {
			dns := DNSServer(net.ParseIP(strings.TrimSpace(dnsString)))
			conf.dns = append(conf.dns, dns)
		}
	}

	if mtuString, c := attributes["mtu"]; c {
		if mtu, err := strconv.Atoi(mtuString); err == nil {
			conf.mtu = uint16(mtu)
		} else {
			return conf, errors.New("interfaceHasInvalidMTU")
		}
	}

	return conf, nil
}

func collatePeerAttributes(attributes map[string]string) (PeerConfiguration, error) {
	conf := PeerConfiguration{}
	//conf.allowedIPs = make([]IPAddressRange, 0)
	publicKeyString, c := attributes["publickey"]
	if !c {
		return conf, errors.New("peerHasNoPublicKey")
	}

	publicKey, err := b64.StdEncoding.DecodeString(publicKeyString)
	if err != nil || len(publicKey) != KeyLength {
		return conf, errors.New("peerHasInvalidPublicKey")
	}
	conf.publicKey = publicKey

	if preSharedKeyString, c := attributes["presharedkey"]; c {
		if preSharedKey, err := b64.StdEncoding.DecodeString(preSharedKeyString); err == nil && len(preSharedKey) == KeyLength {
			conf.preSharedKey = preSharedKey
		} else {
			return conf, errors.New("peerHasInvalidPreSharedKey")
		}
	}

	if allowedIPsString, c := attributes["allowedips"]; c {
		for _, allowedIPString := range strings.Split(allowedIPsString, ",") {
			conf.allowedIPs = append(conf.allowedIPs, parseIPAddressRange(allowedIPString))
		}
	}

	if endpointString, c := attributes["endpoint"]; c {
		if endpoint, err := parseEndpoint(endpointString); err == nil {
			conf.endpoint = endpoint
		} else {
			return conf, errors.New("peerHasInvalidEndpoint")
		}
	}
	if persistentKeepAliveString, c := attributes["persistentkeepalive"]; c {
		if persistentKeepAlive, err := strconv.Atoi(persistentKeepAliveString); err == nil {
			conf.persistentKeepAlive = uint16(persistentKeepAlive)
		} else {
			return conf, errors.New("peerHasInvalidPersistentKeepAlive")
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

	if host := net.ParseIP(strings.Trim(s[:endOfHostIndex], "[]")); host == nil {
		endpoint.host = s[:endOfHostIndex]
	} else {
		endpoint.iphost = host
	}
	return endpoint, nil

}
