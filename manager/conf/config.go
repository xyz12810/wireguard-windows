package conf

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

const KeyLength = 32

type IPCidr struct {
	IP   net.IP
	Cidr uint8
}

type Endpoint struct {
	Host string
	Port uint16
}

type Key [KeyLength]byte
type HandshakeTime time.Duration

type Config struct {
	Name      string
	Interface Interface
	Peers     []Peer
}

type Interface struct {
	PrivateKey Key
	Addresses  []IPCidr
	ListenPort uint16
	Mtu        uint16
	Dns        []net.IP
}

type Peer struct {
	PublicKey           Key
	PresharedKey        Key
	AllowedIPs          []IPCidr
	Endpoint            Endpoint
	PersistentKeepalive uint16

	RxBytes           uint64
	TxBytes           uint64
	LastHandshakeTime HandshakeTime
}

func (r *IPCidr) String() string {
	return fmt.Sprintf("%s/%d", r.IP.String(), r.Cidr)
}

func (e *Endpoint) String() string {
	if strings.IndexByte(e.Host, ':') > 0 {
		return fmt.Sprintf("[%s]:%d", e.Host, e.Port)
	}
	return fmt.Sprintf("%s:%d", e.Host, e.Port)
}

func (e *Endpoint) IsEmpty() bool {
	return len(e.Host) == 0
}

func (k *Key) String() string {
	return base64.StdEncoding.EncodeToString(k[:])
}

func (k *Key) HexString() string {
	return hex.EncodeToString(k[:])
}

func (k *Key) IsZero() bool {
	var zeros Key
	return subtle.ConstantTimeCompare(zeros[:], k[:]) == 1
}

func formatInterval(i int64, n string, l int) string {
	r := ""
	if l > 0 {
		r += ", "
	}
	r += fmt.Sprintf("%d %s", i, n)
	if i != 1 {
		r += "s"
	}
	return r
}

func (t HandshakeTime) String() string {
	u := time.Unix(0, 0).Add(time.Duration(t)).Unix()
	n := time.Now().Unix()
	if u == n {
		return "Now"
	} else if u > n {
		return "System clock wound backward!"
	}
	left := n - u
	years := left / (365 * 24 * 60 * 60)
	left = left % (365 * 24 * 60 * 60)
	days := left / (24 * 60 * 60)
	left = left % (24 * 60 * 60)
	hours := left / (60 * 60)
	left = left % (60 * 60)
	minutes := left / 60
	seconds := left % 60
	s := ""
	if years > 0 {
		s += formatInterval(years, "year", len(s))
	}
	if days > 0 {
		s += formatInterval(days, "day", len(s))
	}
	if hours > 0 {
		s += formatInterval(hours, "hour", len(s))
	}
	if minutes > 0 {
		s += formatInterval(minutes, "minute", len(s))
	}
	if seconds > 0 {
		s += formatInterval(seconds, "second", len(s))
	}
	s += " ago"
	return s
}
