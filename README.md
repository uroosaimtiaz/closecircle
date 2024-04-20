# Closecircle - CISC 468 Final Project

### Python Client
#### Structure

```plaintext
.
├── requirements.txt
├── src
│   ├── app.py
│   ├── auth
│   │   ├── __init__.py
│   │   ├── login.py
│   │   ├── register.py
│   │   └── test.py
│   ├── chat
│   │   ├── __init__.py
│   │   ├── chat_ui.py
│   │   ├── connection.py
│   │   ├── handshake.py
│   │   └── zeroconf_service.py
│   ├── user
│   │   ├── __init__.py
│   │   ├── contacts.py
│   │   ├── messages.py
│   │   └── user.py
│   └── util
│       ├── __init__.py
│       └── file_encryption.py
└── vault
    └── __init__.py
```
#### Python Set-Up Instructions
  ```bash
  cd python-client
  python3 -m venv venv
  source venv/bin/activate
  pip install -r requirements.txt
  python src/app.py
  ```

### Go Client

#### Structure

```plaintext
.
├── cmd
│   └── go-client
│       └── main.go
├── go.mod
├── go.sum
└── internal
    ├── networking
    │   ├── mdns_server.go
    │   ├── state.go
    │   ├── tcp_client.go
    │   └── tcp_server.go
    └── peer
        ├── connection.go
        ├── crypto.go
        ├── peer.go
        ├── peer_test.go
        ├── profile.go
        └── state.go
```

#### Go Set-Up Instructions
  ```bash
cd go-client
go mod download
go run ./cmd/go-client/main.go
  ```

