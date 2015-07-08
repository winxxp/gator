package main

import (
	"flag"
	"fmt"
	"log"
	"net"
)

func main() {
	port := flag.Int("port", 80, "port to listen for connections on")

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
	}

	if err := proxy.Proxy(client); err != nil {
		log.Println("Proxy error:", err)
		return
	}

	// mr := new(MethodRequest)
	// if err := mr.ReadBinary(client); err != nil {
	// 	log.Printf(err.Error())
	// 	return
	// }

	// hasAnonAuth := false

	// for _, method := range mr.methods {
	// 	if method == 0x00 {
	// 		hasAnonAuth = true
	// 	}
	// }

	// if hasAnonAuth {
	// 	rep := new(MethodReply)
	// 	rep.version = mr.version
	// 	rep.method = 0x00 //No auth required
	// 	rep.WriteBinary(client)
	// } else {
	// 	rep := new(MethodReply)
	// 	rep.version = mr.version
	// 	rep.method = 0xFF //No method available
	// 	rep.WriteBinary(client)
	// 	return
	// }

	// sr := new(SocksRequest)
	// if err := sr.ReadBinary(client); err != nil {
	// 	log.Printf(err.Error())
	// 	return
	// }

	// log.Printf("cmd: %d, port: %d, ip: %d, domain: %s\n", sr.command, sr.port, sr.address, sr.domain)

	// if sr.command != 1 {
	// 	log.Printf("Unimplemented command: %d", sr.command)
	// 	srep := new(SocksReply)
	// 	srep.version = mr.version
	// 	srep.reply = 0x07 //Command not supported
	// 	srep.addressType = sr.addressType
	// 	srep.address = sr.address
	// 	srep.port = sr.port
	// 	srep.WriteBinary(client)
	// 	return
	// }

	// //Let's try to connect to the target
	// address := ""
	// if sr.addressType == 3 {
	// 	address = fmt.Sprintf("%s:%d", sr.domain, sr.port)
	// } else if sr.addressType == 1 {
	// 	address = fmt.Sprintf("%s:%d", sr.address, sr.port)
	// } else if sr.addressType == 4 {
	// 	address = fmt.Sprintf("%s[:]%d", sr.address, sr.port)
	// } else {
	// 	log.Printf("Unknown address type in socks request struct")
	// 	return
	// }

	// server, err := net.Dial("tcp", address)
	// if err != nil {
	// 	log.Printf("Failed to connect: %s", err.Error())
	// 	srep := new(SocksReply)
	// 	srep.version = mr.version
	// 	srep.reply = 0x01 //General error
	// 	srep.addressType = sr.addressType
	// 	srep.address = sr.address
	// 	srep.port = sr.port
	// 	srep.WriteBinary(client)
	// 	return
	// }
	// defer server.Close()

	// //Success
	// srep := new(SocksReply)
	// srep.version = mr.version
	// srep.reply = 0x00
	// srep.addressType = sr.addressType
	// srep.address = sr.address
	// srep.domain = sr.domain
	// srep.port = sr.port
	// srep.WriteBinary(client)

	// //Buffered so that the other goroutine doesn't deadlock
	// stopChan := make(chan bool, 1)
	// go func() {
	// 	io.Copy(client, server)
	// 	stopChan <- true
	// }()
	// go func() {
	// 	io.Copy(server, client)
	// 	stopChan <- true
	// }()

	// //Wait for either of the copies to stop
	// <-stopChan

	return
}
