package networking

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
)

type TcpConnection struct {
	Conn            net.Conn
	inMessageQueue  chan []byte
	outMessageQueue chan []byte
	address         string
}

func (c *TcpConnection) GetConnection() *net.Conn {
	return &c.Conn
}

func NewTcpConnection(address string, port int) *TcpConnection {
	fmt.Println("Creating new TCP connection to", address, "on port", port)
	return &TcpConnection{
		address:         address + fmt.Sprintf(":%d", port),
		inMessageQueue:  make(chan []byte),
		outMessageQueue: make(chan []byte),
	}
}

func NewTcpConnectionFromConn(conn net.Conn) *TcpConnection {
	fmt.Println("Creating new TCP connection from existing connection")
	if conn == nil {
		fmt.Println("Error creating new connection from existing connection: connection is nil")
		return nil
	}
	address := conn.RemoteAddr().String()
	// check if address is nil
	if address == "" {
		fmt.Println("Error creating new connection from existing connection: address is nil")
		return nil
	}
	fmt.Println("Address:", address)
	host, portS, _ := net.SplitHostPort(address)
	port, err := strconv.Atoi(portS)
	if err != nil {
		fmt.Println("Error converting port to int", err)
		return nil
	}
	tc := NewTcpConnection(host, port)
	if tc == nil {
		fmt.Println("Error: NewTcpConnection returned nil")
		return nil
	}
	tc.Conn = conn
	return tc
}

func (c *TcpConnection) Connect() error {
	var err error
	c.Conn, err = net.Dial("tcp", c.address)
	if err != nil {
		fmt.Printf("Error connecting to server at %s: %v\n", c.address, err)
		return err
	}

	fmt.Println("Connected to the server.")
	return nil
}

func (c *TcpConnection) Send(message string) {
	fmt.Fprint(c.Conn, message)
	// Reading the response
	response, err := bufio.NewReader(c.Conn).ReadString('\n')
	if err != nil {
		fmt.Println("Error reading response from server:", err)
		return
	}

	fmt.Printf("Received response: %s", response)
}

func (c *TcpConnection) Close() {
	if c.Conn != nil {
		c.Conn.Close()
	}
}
