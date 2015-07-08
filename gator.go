package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
)

func main() {
	port := flag.Int("port", 1080, "port to listen for connections on")

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
		log.Println(c.RemoteAddr())
		go handleConnection(c)
	}
}

func handleConnection(client net.Conn) {
	defer client.Close()

	mr := new(MethodRequest)
	if err := mr.ReadBinary(client); err != nil {
		log.Printf(err.Error())
		return
	}

	hasAnonAuth := false

	for _, method := range mr.methods {
		log.Printf("method: %d", method)
		if method == 0x00 {
			hasAnonAuth = true
		}
	}

	if hasAnonAuth {
		rep := new(MethodReply)
		rep.version = 0x05
		rep.method = 0x00 //No auth required
		rep.WriteBinary(client)
	} else {
		rep := new(MethodReply)
		rep.version = 0x05
		rep.method = 0xFF //No method available
		rep.WriteBinary(client)
		return
	}

	sr := new(SocksRequest)
	if err := sr.ReadBinary(client); err != nil {
		log.Printf(err.Error())
		return
	}

	log.Printf("cmd: %d\nport: %d\nip: %d\ndomain: %s", sr.command, sr.port, sr.address, sr.domain)

	if sr.command != 1 {
		log.Printf("Unimplemented command: %d", sr.command)
		srep := new(SocksReply)
		srep.version = 0x05
		srep.reply = 0x07 //Command not supported
		srep.addressType = sr.addressType
		srep.address = sr.address
		srep.port = sr.port
		srep.WriteBinary(client)
		return
	}

	//Let's try to connect to the target
	address := ""
	if sr.addressType == 3 {
		address = fmt.Sprintf("%s:%d", sr.domain, sr.port)
	} else if sr.addressType == 1 {
		address = fmt.Sprintf("%s:%d", sr.address, sr.port)
	} else if sr.addressType == 4 {
		address = fmt.Sprintf("%s[:]%d", sr.address, sr.port)
	} else {
		log.Printf("Unknown address type in socks request struct")
		return
	}

	server, err := net.Dial("tcp", address)
	if err != nil {
		log.Printf("Failed to connect: %s", err.Error())
		srep := new(SocksReply)
		srep.version = 0x05
		srep.reply = 0x01 //General error
		srep.addressType = sr.addressType
		srep.address = sr.address
		srep.port = sr.port
		srep.WriteBinary(client)
		return
	}
	defer server.Close()

	//Success
	srep := new(SocksReply)
	srep.version = 0x05
	srep.reply = 0x00
	srep.addressType = sr.addressType
	srep.address = sr.address
	srep.domain = sr.domain
	srep.port = sr.port
	srep.WriteBinary(client)

	//Buffered so that the other goroutine doesn't deadlock
	stopChan := make(chan bool, 1)
	go func() {
		io.Copy(client, server)
		stopChan <- true
	}()
	go func() {
		io.Copy(server, client)
		stopChan <- true
	}()

	//Wait for either of the copies to stop
	<-stopChan

	return
}
