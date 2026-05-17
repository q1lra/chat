# chat

## Features
Decentralized Node Swapping  
Zero reliance on a central backend provider. The client acts as an independent routing terminal, letting users establish or hot-swap network links on the fly using the connect command.

Zero-Knowledge Architecture  
Host nodes function strictly as blind routers. Real user credentials, hardware profiles, and communication parameters are never tracked or dumped into server-side storage loops.

End-to-End Encryption  
Symmetric chat room keys are derived entirely client-side using PBKDF2 with 100,000 iterations from user-defined passphrases. The server only sees and stores unreadable ciphertext blocks.

Metadata Footprint Protection  
Normalizes all raw network traffic signatures by automatically padding every over-the-wire payload frame with null bytes to exactly 4096 bytes, rendering payload sizing and traffic analysis metrics useless to eavesdroppers.

Anti-Forensic Plausible Deniability  
Consolidated security vaults store dual keys securely stretched via PBKDF2. Logging in with a pre-configured Panic Password unlocks the interface normally while silently executing an instantaneous database purging routine at the host level.

Ghost Session Orchestration  
Strips all public broadcast hooks. Users enter, communicate in, and leave channel loops silently without throwing visibility updates or leaving active structural footprints for other network participants.

Optimized CLI Footprint  
Pure terminal-based implementation using native Go socket concurrency, maintaining minimal RAM allocation profiles and instant thread execution loops.

## Requirements
Go minimum version 1.26.3  
Git

## Installation
```bash
git clone https://github.com/q1lra/chat.git
cd chat/client
go run main.go crypto.go
```

## Build
```bash
cd client
go build -ldflags="-s -w" -o chat main.go crypto.go

cd ../server
go build -ldflags="-s -w" -o server main.go protocol.go database.go crypto.go
```
