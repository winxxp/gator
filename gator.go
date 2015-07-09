package main

import (
	"flag"
	"fmt"
	"log"
	"net"
)

func main() {
	port := flag.Int("port", 10080, "port to listen for connections on")

	flag.Parse()

	address := fmt.Sprintf(":%d", *port)

	ln, err := net.Listen("tcp", address)
	if err != nil {
		log.Printf("Failed to listen on \"%s\" - error: %s", address, err.Error())
		return
	}

	log.Printf("Listening for new connections on %s", address)

	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %s", err.Error())
			continue
		}
		go handleConnection(c)
	}
}

type SockProxy interface {
	Proxy(client net.Conn) error
}

func handleConnection(client net.Conn) {
	defer client.Close()

	// sock version
	ver := make([]byte, 1)
	if n, _ := client.Read(ver); n != 1 {
		log.Println("MethodRequest packet is too short")
		return
	}

	var proxy SockProxy

	switch ver[0] {
	case 0x04:
		proxy = new(Sock4)
	case 0x05:
		proxy = new(Sock5)
	default:
		log.Println("invalid socks version:", ver)
		return
	}

	if err := proxy.Proxy(client); err != nil {
		log.Println("Proxy error:", err)
		return
	}

	return
}
