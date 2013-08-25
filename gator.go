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
		go handleConnection(c)
	}
}

func handleConnection(client net.Conn) {
	defer client.Close()

	//Maximum length the packet can be is 2 + 255
	buf := make([]byte, 257)

	//First we get the method request
	_, err := client.Read(buf)
	if err != nil {
		log.Printf("Error reading version header: %s", err.Error())
		return
	}

	mr := new(MethodRequest)
	if err := mr.Read(buf); err != nil {
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
		client.Write(rep.bytes())
	} else {
		rep := new(MethodReply)
		rep.version = 0x05
		rep.method = 0xFF //No method available
		client.Write(rep.bytes())
		return
	}

	//Read their socks request
	_, err = client.Read(buf)
	if err != nil {
		log.Printf("Error reading socks request: %s", err.Error())
		return
	}

	sr := new(SocksRequest)
	if err := sr.Read(buf); err != nil {
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
		client.Write(srep.bytes())
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
		client.Write(srep.bytes())
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
	client.Write(srep.bytes())

	stopChan := make(chan bool)
	go func() {
		io.Copy(client, server)
		stopChan <- true
	}()
	go func() {
		io.Copy(server, client)
		stopChan <- true
	}()

	<-stopChan

	//Collect the other goroutine's bool from the channel
	//This is so the channel and goroutine get cleaned up
	go func() {
		<-stopChan
	}()

	return
}

type gatorError struct {
	what string
}

func (e *gatorError) Error() string {
	return e.what
}

type MethodRequest struct {
	version byte
	methods []byte
}

type MethodReply struct {
	version byte
	method  byte
}

type SocksRequest struct {
	version     byte
	command     byte
	addressType byte
	address     net.IP
	domain      string
	port        int
}

type SocksReply struct {
	version     byte
	reply       byte
	addressType byte
	address     net.IP
	domain      string
	port        int
}

func (s MethodRequest) Read(b []byte) error {
	if len(b) < 3 || len(b) < int(2+b[1]) {
		return &gatorError{"method request is too short"}
	} else if b[0] != 0x05 {
		return &gatorError{fmt.Sprintf("Invalid version: %d", b[0])}
	} else {
		s.version = b[0]
	}

	if b[1] == 0 {
		return &gatorError{"Invalid number of methods: 0"}
	} else {
		s.methods = make([]byte, b[1])
	}

	methodBytes := b[2 : 2+b[1]]
	copy(s.methods, methodBytes)

	return nil
}

func (s MethodReply) bytes() []byte {
	return []byte{s.version, s.method}
}

func (s SocksRequest) Read(b []byte) error {
	if len(b) < 5 {
		return &gatorError{"socks request is too short"}
	}

	if b[0] != 0x05 {
		return &gatorError{fmt.Sprintf("Invalid version: %d", b[0])}
	} else {
		s.version = b[0]
	}

	if b[1] < 1 || b[1] > 3 {
		return &gatorError{fmt.Sprintf("Invalid command: %d", b[1])}
	} else {
		s.command = b[1]
	}

	//b[2] == 0x00 and is reserved

	if b[3] == 0 || b[3] == 2 || b[3] > 4 {
		return &gatorError{fmt.Sprintf("Invalid address type: %d", b[3])}
	} else {
		s.addressType = b[3]
	}

	offset := 0

	if s.addressType == 1 {
		if len(b) < 10 {
			return &gatorError{"socks request is too short"}
		}
		s.address = b[4:8]
		offset = 8
	} else if s.addressType == 4 {
		if len(b) < 22 {
			return &gatorError{"socks request is too short"}
		}
		s.address = b[4:20]
		offset = 20
	} else if s.addressType == 3 {
		domainLength := b[4]
		if len(b) < int(7)+int(domainLength) {
			return &gatorError{"socks request is too short"}
		}
		s.domain = string(b[5 : 5+domainLength])
		offset = int(5) + int(domainLength)
	}

	s.port = (int(b[offset]) << 8) + int(b[offset+1])

	return nil
}

func (s SocksReply) bytes() []byte {
	var b []byte
	if s.addressType == 0 || s.addressType == 1 {
		b = make([]byte, 0, 10)
		b = append(b, s.version, s.reply, 0x00, s.addressType)
		b = append(b, s.address[0:4]...)
		b = append(b, byte((s.port&0xFF00)>>8), byte(s.port&0xFF))
	} else if s.addressType == 4 {
		b = make([]byte, 0, 22)
		b = append(b, s.version, s.reply, 0x00, s.addressType)
		b = append(b, s.address[0:16]...)
		b = append(b, byte((s.port&0xFF00)>>8), byte(s.port&0xFF))
	} else if s.addressType == 3 {
		b = make([]byte, 0, 7+len(s.domain))
		b = append(b, s.version, s.reply, 0x00, s.addressType, byte(len(s.domain)))
		b = append(b, s.domain...)
		b = append(b, byte((s.port&0xFF00)>>8), byte(s.port&0xFF))
	} else {
		return nil
	}

	return b
}
