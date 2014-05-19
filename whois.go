package whois

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
)

var Parsers = map[string]Parser{
	"whois.iana.org":   &RPSL{},
	"whois.arin.net":   &RPSL{},
	"whois.ripe.net":   &RPSL{},
	"whois.lacnic.net": &RPSL{},
}

// Lookup ip on IANA, then on `refer`
func Lookup(query string) (*Record, error) {
	record, err := lookup(query, "whois.iana.org")
	if err != nil {
		return nil, err
	}

	if refer := record.Get("refer"); refer != "" {
		return lookup(query, refer)
	}

	return record, nil
}

func lookup(query, host string) (*Record, error) {
	parser, ok := Parsers[host]
	if !ok {
		return nil, fmt.Errorf("no parser for %s", host)
	}

	conn, err := net.Dial("tcp", net.JoinHostPort(host, "43"))
	if err != nil {
		return nil, err
	}

	if _, err := conn.Write(append([]byte(query), '\r', '\n')); err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, conn); err != nil {
		return nil, err
	}

	return &Record{Parser: parser, Data: buf.Bytes()}, nil
}

type Parser interface {
	Get(io.Reader, string) string
}

type Record struct {
	Parser Parser
	Data   []byte
}

func (r *Record) Get(key string) string {
	return r.Parser.Get(bytes.NewReader(r.Data), key)
}

type RPSL struct{}

func (_ RPSL) Get(rd io.Reader, key string) string {
	buf := bufio.NewReader(rd)
	re := regexp.MustCompile(fmt.Sprintf("(?i:%s):\\s+(.*)", key))

	for {
		line, err := buf.ReadString('\n')
		if err == io.EOF {
			return ""
		} else if err != nil {
			panic(fmt.Errorf("ReadString: %s", err))
		}

		if ms := re.FindStringSubmatch(line); len(ms) > 1 {
			return strings.Trim(ms[1], "\r")
		}
	}
}
