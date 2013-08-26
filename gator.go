package main

import (
	"errors"
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

func (s MethodRequest) ReadBinary(r io.Reader) error {
	b := make([]byte, 2)
	if n, _ := r.Read(b); n != 2 {
		return errors.New("method request is too short")
	}

	if s.version = b[0]; s.version != 0x05 {
		return errors.New(fmt.Sprintf("Invalid version: %d", b[0]))
	}

	if b[1] == 0 {
		return errors.New("Invalid number of methods: 0")
	} else {
		s.methods = make([]byte, b[1])
	}

	if _, err := r.Read(s.methods); err != nil {
		return fmt.Errorf("Error reading MethodRequest: %v", err)
	}

	return nil
}

func (s MethodReply) WriteBinary(w io.Writer) error {
	out := []byte{s.version, s.method}
	if _, err := w.Write(out); err != nil {
		return fmt.Errorf("Error writing MethodReply: %v", err)
	}

	return nil
}

func (s SocksRequest) ReadBinary(r io.Reader) error {
	b := make([]byte, 4)

	n, err := r.Read(b)
	if n < 4 {
		return errors.New("SocksRequest input too short")
	}

	if err != nil {
		return fmt.Errorf("Error reading SocksRequest: %v", err)
	}

	if s.version = b[0]; s.version != 0x05 {
		return fmt.Errorf("Invalid version: %d", b[0])
	}

	if s.command = b[1]; b[1] == 0 || b[1] > 3 {
		return fmt.Errorf("Invalid command: %d", s.command)
	}

	if s.addressType = b[3]; b[3] != 1 && b[3] != 3 && b[3] != 4 {
		return fmt.Errorf("Invalid address type: %d", b[3])
	}

	if s.addressType == 1 {
		address := make([]byte, 4)
		if n, err = r.Read(address); n < 4 {
			return errors.New("SocksRequest address is too short")
		}

		if err != nil {
			return fmt.Errorf("Error reading SockRequest.Address: %v", err)
		}

		s.address = address

	} else if s.addressType == 4 {
		address := make([]byte, 16)
		if n, err = r.Read(address); n < 16 {
			return errors.New("SocksRequest address is too short")
		}

		if err != nil {
			return fmt.Errorf("Error reading SockRequest.Address: %v", err)
		}

		s.address = address

	} else if s.addressType == 3 {
		length := make([]byte, 1)

		if _, err = r.Read(length); err != nil {
			return fmt.Errorf("Error reading SockRequest domain length: %v", err)
		}

		domain := make([]byte, int(length[0]))
		n, err = r.Read(domain)
		if n < int(length[0]) {
			return errors.New("SocksRequest domain too short")
		}

		s.domain = string(domain)

		if err != nil {
			return fmt.Errorf("Error reading SockRequest domain: %v", err)
		}
	}

	//TODO
	//s.port = (int(b[offset]) << 8) + int(b[offset+1])

	return nil
}

func (s SocksReply) WriteBinary(w io.Writer) error {
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
		return errors.New("Cannot write SocksReply, Invalid address type")
	}

	if _, err := w.Write(b); err != nil {
		return fmt.Errorf("Error writing SocksReply: %v", err)
	}

	return nil
}
