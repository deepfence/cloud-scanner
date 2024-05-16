package cloud_metadata

import (
	"errors"
	"net"
)

func RoutedInterface(network string, flags net.Flags) *net.Interface {
	switch network {
	case "ip", "ip4", "ip6":
	default:
		return nil
	}
	ift, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, ifi := range ift {
		if ifi.Flags&flags != flags {
			continue
		}
		if _, ok := hasRoutableIP(network, &ifi); !ok {
			continue
		}
		return &ifi
	}
	return nil
}

func hasRoutableIP(network string, ifi *net.Interface) (net.IP, bool) {
	ifat, err := ifi.Addrs()
	if err != nil {
		return nil, false
	}
	for _, ifa := range ifat {
		switch ifa := ifa.(type) {
		case *net.IPAddr:
			if ip := routableIP(network, ifa.IP); ip != nil {
				return ip, true
			}
		case *net.IPNet:
			if ip := routableIP(network, ifa.IP); ip != nil {
				return ip, true
			}
		}
	}
	return nil, false
}

func routableIP(network string, ip net.IP) net.IP {
	if !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsGlobalUnicast() {
		return nil
	}
	switch network {
	case "ip4":
		if ip := ip.To4(); ip != nil {
			return ip
		}
	case "ip6":
		if ip.IsLoopback() { // addressing scope of the loopback address depends on each implementation
			return nil
		}
		if ip := ip.To16(); ip != nil && ip.To4() == nil {
			return ip
		}
	default:
		if ip := ip.To4(); ip != nil {
			return ip
		}
		if ip := ip.To16(); ip != nil {
			return ip
		}
	}
	return nil
}

func GetDefaultRouteIPAddress() (ipaddr string, interfaceName string, err error) {
	// get ip address of default route
	routedInterfaces := RoutedInterface("ip4", net.FlagUp|net.FlagBroadcast)
	if routedInterfaces != nil {
		interfaceAddrs, err := routedInterfaces.Addrs()
		if err != nil {
			return "", "", err
		}
		for _, interfaceAddr := range interfaceAddrs {
			switch addr := interfaceAddr.(type) {
			case *net.IPNet:
				if addr.IP.To4() != nil {
					return addr.IP.String(), routedInterfaces.Name, nil
				}
			case *net.IPAddr:
				if addr.IP.To4() != nil {
					return addr.IP.String(), routedInterfaces.Name, nil
				}
			}
		}
	}
	return "", "", errors.New("no interfaces found")
}

func RemoveLastCharacter(s string) string {
	r := []rune(s)
	return string(r[:len(r)-1])
}
