package peer

import (
	"encoding/base64"
	"errors"
	"net"
	"os"
	"path"
	"path/filepath"

	"go-client/internal/networking"
)

type Peer struct {
	Connection *networking.TcpConnection
	Name       string
	PubKey     string
	Addr       net.IP
	SessionKey []byte
	Port       int
	Connected  bool
}

func NewPeer(name string, pubKey string, addr net.IP, port int) *Peer {
	return &Peer{
		Name:      name,
		PubKey:    pubKey,
		Addr:      addr,
		Port:      port,
		Connected: false,
	}
}

func (p *Peer) SetConnection(conn *networking.TcpConnection) {
	p.Connection = conn
}

func (p *Peer) Connect(password string) error {
	p.Connection = networking.NewTcpConnection(p.Addr.String(), 3000)
	p.Connection.Connect()
	k := make([]byte, 32)
	ver, err := VerifyOutgoingConnection(p.Connection.Conn, password, &k)
	if !ver || err != nil {
		p.Close()
		return errors.New("Handshake failed. Connection could not be verified.")
	}
	p.Connected = true
	p.SessionKey = k
	return nil
}

func (p *Peer) Close() {
	p.Connection.Close()
}

func (p *Peer) SendMessage(message string, isFile bool) error {
	if !isFile {
		c1, iv1, hash, err := AesEncrypt([]byte(message), p.SessionKey)
		if err != nil {
			return err
		}
		m := NewMessage(c1, iv1, hash)
		data, err := encodePacket([]Message{*m})
		if err != nil {
			return err
		}
		err = send(p.Connection.Conn, data)
		if err != nil {
			return err
		}
	} else {
		b, err := os.ReadFile(message)
		if err != nil {
			return err
		}
		c1, iv1, hash, err := AesEncrypt(b, p.SessionKey)
		if err != nil {
			return err
		}

		// Extract the filename from the path
		fileName := filepath.Base(message)

		c2, iv2, hash2, err := AesEncrypt([]byte(fileName), p.SessionKey)
		if err != nil {
			return err
		}
		m1 := NewMessage(c1, iv1, hash)
		m2 := NewMessage(c2, iv2, hash2)
		data, err := encodePacket([]Message{*m1, *m2})
		if err != nil {
			return err
		}
		err = send(p.Connection.Conn, data)
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *Peer) ReceiveMessage() (string, error) {
	buf, err := receive(p.Connection.Conn)
	if err != nil {
		return "", err
	}
	messages, err := decodePacket(buf)
	if err != nil {
		return "", err
	}
	if len(messages) == 2 {
		m1 := messages[0]
		data, _ := base64.StdEncoding.DecodeString(m1.Data)
		iv, _ := base64.StdEncoding.DecodeString(m1.IV)
		hash, _ := base64.StdEncoding.DecodeString(m1.Hash)
		fileContent, err := AesDecrypt(data, p.SessionKey, iv, hash)
		if err != nil {
			return "", err
		}
		m2 := messages[1]
		data, _ = base64.StdEncoding.DecodeString(m2.Data)
		iv, _ = base64.StdEncoding.DecodeString(m2.IV)
		hash, _ = base64.StdEncoding.DecodeString(m2.Hash)
		fileName, err := AesDecrypt(data, p.SessionKey, iv, hash)
		if err != nil {
			return "", err
		}

		// Prepend the folder path to the filename
		filePath := path.Join("received_files", string(fileName))

		// Create the directory if it doesn't exist
		if err := os.MkdirAll(path.Dir(filePath), 0755); err != nil {
			return "", err
		}

		file, err := os.OpenFile(filePath, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			return "", err
		}
		defer file.Close()
		_, err = file.Write(fileContent)
		if err != nil {
			return "", err
		}
		return "File received: " + filePath, nil
	} else {
		m := messages[0]
		data, _ := base64.StdEncoding.DecodeString(m.Data)
		iv, _ := base64.StdEncoding.DecodeString(m.IV)
		hash, _ := base64.StdEncoding.DecodeString(m.Hash)
		dec, err := AesDecrypt(data, p.SessionKey, iv, hash)
		if err != nil {
			return "", err
		}
		return string(dec), nil
	}
}
