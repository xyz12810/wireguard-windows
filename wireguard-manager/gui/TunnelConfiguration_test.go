package main

import (
	"net"
	"testing"

	b64 "encoding/base64"

	"github.com/stretchr/testify/assert"
)

const TestInput = `
[Interface] 
Address = 10.192.122.1/24 
Address = 10.10.0.1/16 
SaveConfig = true 
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk= 
ListenPort = 51820  #comments don't matter

[Peer] 
PublicKey   =   xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=    
Endpoint = 192.95.5.67:1234 
AllowedIPs = 10.192.122.3/32, 10.192.124.1/24

[Peer] 
PublicKey = TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0= 
Endpoint = [2607:5300:60:6b0::c05f:543]:2468 
AllowedIPs = 10.192.122.4/32, 192.168.0.0/16
PersistentKeepalive = 100

[Peer] 
PublicKey = gN65BkIKy1eCE9pP1wdc8ROUtkHLF2PfAqYdyYBz6EA= 
PresharedKey = TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0= 
Endpoint = test.wireguard.com:18981 
AllowedIPs = 10.10.10.230/32`

func NoError(t *testing.T, err error) bool {
	if err == nil {
		return true
	}
	t.Error(err)
	return false
}

func Equal(t *testing.T, expected, actual interface{}) bool {
	if expected == actual {
		return true
	}
	t.Errorf("Invalid operation: %#v != %#v (%s)", expected, actual, actual)
	// exp, ok := expected.([]byte)
	// if !ok {
	// 	return reflect.DeepEqual(expected, actual)
	// }
	// act, ok := actual.([]byte)
	// if !ok {
	// 	return false
	// }
	// if exp == nil || act == nil {
	// 	return exp == nil && act == nil
	// }
	// return bytes.Equal(exp, act)
	return false
}

func TestReadTunnelConfiguration(t *testing.T) {
	conf, err := readTunnelConfiguration(TestInput, "test")
	if assert.NoError(t, err) {

		assert.Len(t, conf.wginterface.addresses, 2)
		assert.Contains(t, conf.wginterface.addresses, IPAddressRange{net.IPv4(10, 10, 0, 1), uint8(16)})
		assert.Contains(t, conf.wginterface.addresses, IPAddressRange{net.IPv4(10, 192, 122, 1), uint8(24)})
		Equal(t, "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=", b64.StdEncoding.EncodeToString(conf.wginterface.privateKey))
		Equal(t, uint16(51820), conf.wginterface.listenPort)

		assert.Len(t, conf.peers, 3)
		assert.Len(t, conf.peers[0].allowedIPs, 2)
		Equal(t, Endpoint{iphost: net.IPv4(192, 95, 5, 67), port: 1234}, conf.peers[0].endpoint)
		Equal(t, "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=", b64.StdEncoding.EncodeToString(conf.peers[0].publicKey))

		assert.Len(t, conf.peers[1].allowedIPs, 2)
		Equal(t, Endpoint{iphost: net.IP{0x26, 0x07, 0x53, 0, 0, 0x60, 0x6, 0xb0, 0, 0, 0, 0, 0xc0, 0x5f, 0x5, 0x43}, port: 2468}, conf.peers[1].endpoint)
		Equal(t, "TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0=", b64.StdEncoding.EncodeToString(conf.peers[1].publicKey))
		Equal(t, uint16(100), conf.peers[1].persistentKeepAlive)

		assert.Len(t, conf.peers[2].allowedIPs, 1)
		Equal(t, Endpoint{host: "test.wireguard.com", port: 18981}, conf.peers[2].endpoint)
		Equal(t, "gN65BkIKy1eCE9pP1wdc8ROUtkHLF2PfAqYdyYBz6EA=", b64.StdEncoding.EncodeToString(conf.peers[2].publicKey))
		Equal(t, "TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0=", b64.StdEncoding.EncodeToString(conf.peers[2].preSharedKey))
	}
}

func TestParseIPAddressRange(t *testing.T) {
	ip := parseIPAddressRange("10.10.10.230/32")

	Equal(t, uint8(32), ip.networkPrefixLength)
	Equal(t, net.IPv4(10, 10, 10, 230), ip.address)
	Equal(t, ip, IPAddressRange{net.IPv4(10, 10, 10, 230), uint8(32)})
}

func TestParseEndpoint(t *testing.T) {
	e, err := parseEndpoint("192.168.42.0:51880")
	if assert.NoError(t, err) {
		Equal(t, net.IPv4(192, 168, 42, 0), e.iphost)
		Equal(t, "", e.host)
		Equal(t, uint16(51880), e.port)
	}
	e, err = parseEndpoint("test.wireguard.com:18981")
	if assert.NoError(t, err) {
		Equal(t, net.IP(nil), e.iphost)
		Equal(t, "test.wireguard.com", e.host)
		Equal(t, uint16(18981), e.port)
	}

}
