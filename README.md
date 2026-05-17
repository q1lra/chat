# chat

## Features

## Requirements
* Go minimum version go1.26.3 
* Git

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
