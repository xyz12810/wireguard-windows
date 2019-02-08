/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package winipcfg

import (
	"golang.org/x/sys/windows"
	"net"
	"os"
	"syscall"
	"unsafe"
)

// I've had to extend the original windows.IpAdapterAddresses because it doesn't contain Luid field.
type IpAdapterAddressesEx struct {
	IpAdapterAddresses windows.IpAdapterAddresses
	offset1 [ipAdapterAddressesExOffset1Size]byte
	Luid uint64
	offset2 [ipAdapterAddressesExOffset2Size]byte
}

const expectedNumberOfInterfaces uint32 = 50

// Based on function with the same name in 'net' module, in file interface_windows.go
func adapterAddresses() ([]*IpAdapterAddressesEx, error) {
	var b []byte
	size := expectedNumberOfInterfaces * ipAdapterAddressesExSize //uint32(15000) // recommended initial size
	for {
		b = make([]byte, size)
		result := getAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_INCLUDE_PREFIX, 0,
			(*IpAdapterAddressesEx)(unsafe.Pointer(&b[0])), &size)
		if result == 0 {
			if size == 0 {
				return nil, nil
			}
			break
		}
		if result != uint32(syscall.ERROR_BUFFER_OVERFLOW) {
			return nil, os.NewSyscallError("getadaptersaddresses", syscall.Errno(result))
		}
		if size <= uint32(len(b)) {
			return nil, os.NewSyscallError("getadaptersaddresses", syscall.Errno(result))
		}
	}
	var aas []*IpAdapterAddressesEx
	for aa := (*IpAdapterAddressesEx)(unsafe.Pointer(&b[0])); aa != nil; aa = aa.next() {
		aas = append(aas, aa)
	}
	return aas, nil
}

func (aa *IpAdapterAddressesEx) next() *IpAdapterAddressesEx {
	return (*IpAdapterAddressesEx) (unsafe.Pointer(aa.IpAdapterAddresses.Next))
}

// Created based on interfaceTable method from 'net' module, interface_windows.go file.
func (aa *IpAdapterAddressesEx) toInterfaceEx() *InterfaceEx {
	if aa == nil {
		return nil
	}
	index := aa.IpAdapterAddresses.IfIndex
	if index == 0 { // ipv6IfIndex is a substitute for ifIndex
		index = aa.IpAdapterAddresses.Ipv6IfIndex
	}
	ifi := InterfaceEx{
		Interface: net.Interface{
			Index: int(index),
			Name: syscall.UTF16ToString((*(*[10000]uint16)(unsafe.Pointer(aa.IpAdapterAddresses.FriendlyName)))[:]),
		},
		Luid: aa.Luid,
	}
	if aa.IpAdapterAddresses.OperStatus == windows.IfOperStatusUp {
		ifi.Interface.Flags |= net.FlagUp
	}
	// For now we need to infer link-layer service
	// capabilities from media types.
	// TODO: use MIB_IF_ROW2.AccessType now that we no longer support
	// Windows XP.
	switch aa.IpAdapterAddresses.IfType {
	case windows.IF_TYPE_ETHERNET_CSMACD, windows.IF_TYPE_ISO88025_TOKENRING, windows.IF_TYPE_IEEE80211, windows.IF_TYPE_IEEE1394:
		ifi.Interface.Flags |= net.FlagBroadcast | net.FlagMulticast
	case windows.IF_TYPE_PPP, windows.IF_TYPE_TUNNEL:
		ifi.Interface.Flags |= net.FlagPointToPoint | net.FlagMulticast
	case windows.IF_TYPE_SOFTWARE_LOOPBACK:
		ifi.Interface.Flags |= net.FlagLoopback | net.FlagMulticast
	case windows.IF_TYPE_ATM:
		ifi.Interface.Flags |= net.FlagBroadcast | net.FlagPointToPoint | net.FlagMulticast // assume all services available; LANE, point-to-point and point-to-multipoint
	}
	if aa.IpAdapterAddresses.Mtu == 0xffffffff {
		ifi.Interface.MTU = -1
	} else {
		ifi.Interface.MTU = int(aa.IpAdapterAddresses.Mtu)
	}
	if aa.IpAdapterAddresses.PhysicalAddressLength > 0 {
		ifi.Interface.HardwareAddr = make(net.HardwareAddr, aa.IpAdapterAddresses.PhysicalAddressLength)
		copy(ifi.Interface.HardwareAddr, aa.IpAdapterAddresses.PhysicalAddress[:])
	}
	return &ifi
}