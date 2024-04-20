package networking

import (
	"fmt"
	"net"
)

type TcpServer struct {
	listener    net.Listener
	stopChan    chan struct{}
	Connections chan net.Conn
	port        int
}

func NewTcpServer(port int) *TcpServer {
	return &TcpServer{
		port:        port,
		stopChan:    make(chan struct{}),
		Connections: make(chan net.Conn),
	}
}

func (s *TcpServer) handleConnection(conn net.Conn) {
	if conn == nil {
		fmt.Println("Connection is nil")
		return
	}
	s.Connections <- conn
}

func (s *TcpServer) Start() {
	var err error
	// Create listener
	// get local IP address
	localIP, err := GetLocalIPAddress()
	if err != nil {
		fmt.Println("Error getting local IP address:", err)
		return
	}
	s.listener, err = net.Listen("tcp", localIP+":"+fmt.Sprintf("%d", s.port))
	if err != nil {
		fmt.Println("Error listening:", err.Error())
		return
	}
	go func() {
		for {
			// Wait for incoming connection
			conn, err := s.listener.Accept()
			if err != nil {
				select {
				// Check if the server was stopped
				case <-s.stopChan:
					//fmt.Println("TCP Server stopped")
					return

				default:
					// Error with the connection but server not stopped
					fmt.Println("Error accepting:", err)
				}
				continue
			}
			go s.handleConnection(conn)
		}
	}()
}

func (s *TcpServer) Stop() {
	close(s.stopChan)
	if s.listener != nil {
		s.listener.Close()
	}
}
