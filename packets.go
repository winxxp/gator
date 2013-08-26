package main

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
