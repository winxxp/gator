package main

import (
	"errors"
	"fmt"
	"io"
	"net"
)

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
		return errors.New("MethodRequest packet is too short")
	}

	if s.version = b[0]; s.version != 0x05 {
		return fmt.Errorf("Invalid version: %d", s.version)
	}

	numMethods := int(b[1])

	if numMethods == 0 {
		return errors.New("Invalid number of methods: 0")
	} else {
		s.methods = make([]byte, numMethods)
	}

	if n, _ := r.Read(s.methods); n != numMethods {
		return errors.New("MethodRequest packet is too short")
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

	if n, _ := r.Read(b); n != 4 {
		return errors.New("SocksRequest input too short")
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
		if n, _ := r.Read(address); n != 4 {
			return errors.New("SocksRequest address is too short")
		}

		s.address = address

	} else if s.addressType == 4 {
		address := make([]byte, 16)
		if n, _ := r.Read(address); n != 16 {
			return errors.New("SocksRequest address is too short")
		}

		s.address = address

	} else if s.addressType == 3 {
		length := make([]byte, 1)

		if n, _ := r.Read(length); n != 1 {
			return errors.New("SocksRequest domain length missing")
		}

		domainLength := int(length[0])

		domain := make([]byte, domainLength)
		if n, _ := r.Read(domain); n < domainLength {
			return errors.New("SocksRequest domain too short")
		}

		s.domain = string(domain)
	}

	portBytes := make([]byte, 2)
	if n, _ := r.Read(portBytes); n != 2 {
		return errors.New("SocksRequest missing port")
	}

	//Horrible, but it works
	s.port = (int(portBytes[0]) << 8) + int(portBytes[1])

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
