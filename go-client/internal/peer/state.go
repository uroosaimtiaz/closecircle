package peer

import (
	"fmt"
	"go-client/internal/peer"
)

type AppState struct {
	CurrentPeer        *Peer
	CurrentPeerChanged chan bool
	NetworkState       *networking.NetworkingState
	Profile            *Profile
	MessageChan        chan string
	InChat             bool
	Password           string
}

func NewAppState(p *Profile, password string) *AppState {
	return &AppState{
		Profile:            p,
		NetworkState:       networking.NewNetworkingState(p.Name, 3000),
		CurrentPeerChanged: make(chan bool),
		MessageChan:        make(chan string),
		InChat:             false,
		Password:           password,
	}
}

func (a *AppState) Start() {
	a.NetworkState.Start()
	go ReceiveConnections(a.Profile.Name, a.NetworkState.TcpServer, a)
	go ReceiveMessages(a)
	// go DisplayMessages(a)
}

func (a *AppState) SaveMessage(message string) {
	if a.CurrentPeer == nil {
		return
	}
	for i, contact := range a.Profile.Contacts {
		if contact.Name == a.CurrentPeer.Name {
			a.Profile.Contacts[i].Messages = append(contact.Messages, message)
		}
	}
}

func DisplayMessages(a *AppState) {
	for {
		message := <-a.MessageChan
		if !a.InChat {
			message = ""
			continue
		}
		fmt.Println(message)
		// message = ""
	}
}

func (a *AppState) DiscoverAndFilter() []Peer {
	peers := DiscoverPeers(a.Profile.Name)
	contacts := a.Profile.Contacts
	contactPeers := make([]Peer, 0)
	for _, p := range peers {
		for _, c := range contacts {
			if p.Name == c.Name {
				contactPeers = append(contactPeers, p)
				fmt.Println("Contact peer: ", p)
			}
		}
	}
	return contactPeers
}

func (a *AppState) SendMessage(message string, isFile bool) {
	if a.CurrentPeer != nil {
		err := a.CurrentPeer.SendMessage(message, isFile)
		if err != nil {
			fmt.Println("Error sending message: ", err)
		}
	}
}

func (a *AppState) Stop() {
	//fmt.Println("Stopping app state")
	a.NetworkState.Stop()
	a.Disconnect()
}

func (a *AppState) Disconnect() {
	a.CurrentPeer = nil
}
