package networking

import (
	"fmt"
	"net"

	"github.com/grandcat/zeroconf"
)

type MdnsServer struct {
	server *zeroconf.Server
	Name   string
	PubKey string
	Port   int
}

func NewMdnsServer(host string, port int) *MdnsServer {
	return &MdnsServer{
		Port:   port,
		Name:   host,
		PubKey: "TODO",
	}
}

// GetLocalIPAddress attempts to determine the default local IP address by creating a dummy connection.
func GetLocalIPAddress() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		fmt.Printf("Error obtaining local IP address: %v\n", err)
		return "127.0.0.1", err // Fallback to localhost
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String(), err
}

func (s *MdnsServer) Start() error {
	localIP, err := GetLocalIPAddress()
	if err != nil {
		return fmt.Errorf("failed to fetch local IP address: %v", err)
	}

	// Preparing information for zeroconf registration
	info := []string{s.Name, s.PubKey}
	ips := []string{localIP} // Assuming the service is bound to this IP

	// Register the service using zeroconf
	server, err := zeroconf.RegisterProxy(
		s.Name,              // instance
		"_closecircle._tcp", // service
		"local.",            // domain
		s.Port,              // port
		s.Name,              // host
		ips,                 // list of IPs
		info,                // text records
		nil)                 // nil to use all available network interfaces
	if err != nil {
		return fmt.Errorf("failed to register mDNS service: %v", err)
	}

	s.server = server
	//fmt.Println("mDNS service registered successfully.")
	return nil
}

func (s *MdnsServer) Stop() {
	if s.server != nil {
		s.server.Shutdown()
	}
}
