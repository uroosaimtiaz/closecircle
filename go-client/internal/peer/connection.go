package peer

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/grandcat/zeroconf"
	"go-client/internal/peer"
)

// DiscoverPeers searches for mDNS services and returns a slice of discovered peers.
func DiscoverPeers(host string) []Peer {
	peers := make([]Peer, 0)
	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		fmt.Println("Failed to initialize resolver:", err)
		return peers
	}

	entries := make(chan *zeroconf.ServiceEntry)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = resolver.Browse(ctx, "_closecircle._tcp", "local.", entries)
	if err != nil {
		fmt.Println("Failed to browse:", err)
		return peers
	}

	go func() {
		for entry := range entries {
			if entry.Instance == host { // Skip self, adjust this check as per actual implementation details
				continue
			}
			// Assuming the first text entry might be the public key, adjust as per your actual setup.
			pubKey := ""
			if len(entry.Text) > 0 {
				pubKey = entry.Text[0]
			}
			// Collect the first IPv4 address; adjust as needed if multiple addresses should be handled.
			var ip net.IP
			if len(entry.AddrIPv4) > 0 {
				ip = entry.AddrIPv4[0]
			}
			// Append the peer if a valid IP address is found.
			if ip != nil {
				p := Peer{
					Name:   entry.Instance,
					PubKey: pubKey,
					Addr:   ip,
					Port:   entry.Port,
				}
				peers = append(peers, p)
			}
		}
	}()

	// Wait for the browsing to complete
	<-ctx.Done()
	//fmt.Println("Finished browsing services.")
	return peers
}

type Message struct {
	Data string `json:"data"`
	IV   string `json:"iv"`
	Hash string `json:"hash"`
}

func NewMessage(data, iv, hash []byte) *Message {
	new := Message{
		Data: base64.StdEncoding.EncodeToString(data),
		IV:   base64.StdEncoding.EncodeToString(iv),
		Hash: base64.StdEncoding.EncodeToString(hash),
	}
	return &new
}

func encodePacket(messages []Message) ([]byte, error) {
	new, err := json.Marshal(messages)
	return new, err
}

func decodePacket(data []byte) ([]Message, error) {
	var messages []Message
	err := json.Unmarshal(data, &messages)
	if err != nil {
		return nil, err
	}

	for i, message := range messages {
		data, err := base64.StdEncoding.DecodeString(message.Data)
		if err != nil {
			return nil, err
		}
		iv, err := base64.StdEncoding.DecodeString(message.IV)
		if err != nil {
			return nil, err
		}
		hash, err := base64.StdEncoding.DecodeString(message.Hash)
		if err != nil {
			return nil, err
		}
		messages[i] = *NewMessage(data, iv, hash)
	}

	return messages, nil
}

func VerifyIncomingConnection(conn net.Conn, password string, keyBuffer *[]byte) (bool, error) {
	c1, err := receive(conn)
	if err != nil {
		return false, err
	}
	p, err := decodePacket(c1)
	if err != nil || len(p) != 1 {
		return false, err
	}
	w := KDFKeygen(password)
	privk, pubk, err := EcdhKeygen()
	if err != nil {
		return false, err
	}
	data, _ := base64.StdEncoding.DecodeString(p[0].Data)
	iv, _ := base64.StdEncoding.DecodeString(p[0].IV)
	hash, _ := base64.StdEncoding.DecodeString(p[0].Hash)
	rpubkBytes, err := AesDecrypt(data, w, iv, hash)
	if err != nil {
		return false, err
	}
	rpubk, err := ecdh.P256().NewPublicKey(rpubkBytes)
	if err != nil {
		return false, err
	}
	// K is the shared secret
	k, err := privk.ECDH(rpubk)
	if err != nil {
		return false, err
	}
	c2, iv2, h2, err := AesEncrypt(pubk, w)
	if err != nil {
		return false, err
	}
	m2 := NewMessage(c2, iv2, h2)
	challenge, err := generateChallenge()
	if err != nil {
		return false, err
	}
	// print challenge to error check formatting
	c3, iv3, h3, err := AesEncrypt(challenge, k)
	if err != nil {
		return false, err
	}
	m3 := NewMessage(c3, iv3, h3)
	data, err = encodePacket([]Message{*m2, *m3})
	if err != nil {
		return false, err
	}

	response, err := sendAndReceive(conn, data)
	if err != nil {
		return false, err
	}
	p, err = decodePacket(response)
	if err != nil || len(p) != 1 {
		return false, err
	}
	data, _ = base64.StdEncoding.DecodeString(p[0].Data)
	iv, _ = base64.StdEncoding.DecodeString(p[0].IV)
	hash, _ = base64.StdEncoding.DecodeString(p[0].Hash)

	pt, err := AesDecrypt(data, k, iv, hash)
	if err != nil {
		return false, err
	}

	remoteChallenge := pt[:8]
	localChallenge := pt[8:]

	if !bytes.Equal(challenge, localChallenge) {
		return false, errors.New("challenge mismatch")
	}

	c5, iv5, h5, err := AesEncrypt(remoteChallenge, k)
	if err != nil {
		return false, err
	}

	m5 := NewMessage(c5, iv5, h5)
	data, err = encodePacket([]Message{*m5})
	if err != nil {
		return false, err
	}
	err = send(conn, data)
	if err != nil {
		return false, err
	}

	copy(*keyBuffer, k)
	return true, nil
}

func VerifyOutgoingConnection(conn net.Conn, password string, keyBuffer *[]byte) (bool, error) {
	w := KDFKeygen(password)
	privk, pubk, err := EcdhKeygen()
	if err != nil {
		return false, err
	}

	// Encrypt public key with w, send to peer
	c1, iv1, h1, err := AesEncrypt(pubk, w)
	if err != nil {
		return false, err
	}
	m1 := NewMessage(c1, iv1, h1)
	data, err := encodePacket([]Message{*m1})
	if err != nil {
		return false, err
	}

	response, err := sendAndReceive(conn, data)
	if err != nil {
		fmt.Println("Handshake failed. Ensure the password is correct.")
		return false, err
	}
	p, err := decodePacket(response)
	if err != nil || len(p) != 2 {
		return false, err
	}

	// Decode the public key from the first message
	data, _ = base64.StdEncoding.DecodeString(p[0].Data)
	iv, _ := base64.StdEncoding.DecodeString(p[0].IV)
	hash, _ := base64.StdEncoding.DecodeString(p[0].Hash)

	rpubkBytes, err := AesDecrypt(data, w, iv, hash)
	if err != nil {
		return false, err
	}
	rpubk, err := ecdh.P256().NewPublicKey(rpubkBytes)
	if err != nil {
		return false, err
	}

	// K is the shared secret
	k, err := privk.ECDH(rpubk)
	if err != nil {
		return false, err
	}

	// Decode the challenge from the second message
	data, _ = base64.StdEncoding.DecodeString(p[1].Data)
	iv, _ = base64.StdEncoding.DecodeString(p[1].IV)
	hash, _ = base64.StdEncoding.DecodeString(p[1].Hash)

	pt, err := AesDecrypt(data, k, iv, hash)
	if err != nil {
		return false, err
	}

	remoteChallenge := pt // the peer's challenge is the entire message, decrypted

	// Generate and encrypt a new challenge
	challenge, err := generateChallenge()
	if err != nil {
		return false, err
	}

	// concatenate my challenge and the peer's challenge
	pt = append(challenge, remoteChallenge...)


	c4, iv4, h4, err := AesEncrypt(pt, k)
	if err != nil {
		return false, err
	}

	m4 := NewMessage(c4, iv4, h4)
	data, err = encodePacket([]Message{*m4})
	if err != nil {
		return false, err
	}

	err = send(conn, data)
	if err != nil {
		return false, err
	}

	// Receive the response to the challenge
	response, err = receive(conn)
	if err != nil {
		return false, err
	}
	p, err = decodePacket(response)
	if err != nil || len(p) != 1 {
		return false, err
	}

	// Decode the challenge from the response
	data, _ = base64.StdEncoding.DecodeString(p[0].Data)
	iv, _ = base64.StdEncoding.DecodeString(p[0].IV)
	hash, _ = base64.StdEncoding.DecodeString(p[0].Hash)

	localChallenge, err := AesDecrypt(data, k, iv, hash)
	if err != nil {
		return false, err
	}

	// now we have the peer's response challenge, compare it to the local challenge
	if !bytes.Equal(challenge, localChallenge) {
		return false, errors.New("challenge mismatch")
	}

	copy(*keyBuffer, k)
	return true, nil
}

func generateChallenge() ([]byte, error) {
	challenge := make([]byte, 8)
	_, err := rand.Read(challenge)
	if err != nil {
		return nil, err
	}

	return challenge, nil
}

func send(conn net.Conn, data []byte) error {
	_, err := conn.Write(data)
	if err != nil {
		return err
	}
	return nil
}

func receive(conn net.Conn) ([]byte, error) {
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func sendAndReceive(conn net.Conn, data []byte) ([]byte, error) {
	err := send(conn, data)
	if err != nil {
		return nil, err
	}
	buf, err := receive(conn)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func FindPassword(rName string, state *AppState) (string, error) {
	var password string
	for _, contact := range state.Profile.Contacts {
		if contact.Name == rName {
			password = contact.Password
			return password, nil
		}
	}
	return "", errors.New("unrecognized peer")
}

func ReceiveConnections(host string, ts *networking.TcpServer, a *AppState) {
    for {
        conn := <-ts.Connections

        peers := a.DiscoverAndFilter()
        if len(peers) == 0 {
			//fmt.Println("No contacts are online.")
            conn.Close()
            continue
        }

        var peer *Peer
        for _, p := range peers {
            if strings.Contains(conn.RemoteAddr().String(), p.Addr.String()) {
                //fmt.Println("Found peer")

                if conn.RemoteAddr().(*net.TCPAddr).Port != p.Port {
                    p.Port = conn.RemoteAddr().(*net.TCPAddr).Port
                }

                peer = &p
                fmt.Println("Peer: ", peer)
                break
            }
        }
		if peer == nil {
			fmt.Println("Contact not found")
			conn.Close()
			// remove from connections
			continue
		}

        tc := networking.NewTcpConnectionFromConn(conn)
        peer.SetConnection(tc)
        k := make([]byte, 32)

        rName := peer.Name
        password, err := FindPassword(rName, a)
        if err != nil {
            fmt.Println("Error finding password: ", err)
            continue
        }

        ver, err := VerifyIncomingConnection(conn, password, &k)
        if !ver || err != nil {
            fmt.Println("Verification failed: ", err)
            continue
        }

        peer.Connected = true
        peer.SessionKey = k

        a.CurrentPeer = peer

        if !a.InChat {
            fmt.Println(a.CurrentPeer.Name, " has started a chat with you. You may open the chat from the main menu.")
        } else {
            a.MessageChan <- fmt.Sprintf("%s has entered the chat.\n", a.CurrentPeer.Name)
        }
    }
}

func ReceiveMessages(a *AppState) {
	for {
		p := a.CurrentPeer
		if p != nil {
			message, err := p.ReceiveMessage()
			// If the err is io.EOF, the connection was closed by the peer.
			if err != nil {
				//a.Disconnect()
				//a.MessageChan <- "Peer disconnected."
				if err == io.EOF || strings.Contains(err.Error(), "connection reset by peer") {
					a.Disconnect()
					a.MessageChan <- "Peer may be disconnected."
				} else {
					//fmt.Println("Error receiving message: ", err)
					a.Disconnect()
					a.MessageChan <- "Error receiving message."
				}
			} else {
				message = fmt.Sprintf("%s: %s", p.Name, message)
				a.MessageChan <- message
			}
		}

	}
}
