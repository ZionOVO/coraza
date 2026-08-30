// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo

package operators

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/miekg/dns"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

func TestRbl(t *testing.T) {
	opts := plugintypes.OperatorOptions{
		Arguments: "xbl.spamhaus.org",
	}
	op, err := newRBL(opts)
	if err != nil {
		t.Fatal("Cannot init rbl operator")
	}

	op.(*rbl).resolver = newRBLTestResolver(t)

	t.Run("Valid hostname with no TXT record", func(t *testing.T) {
		if op.Evaluate(nil, "valid_no_txt") {
			t.Errorf("Unexpected result for valid hostname with no TXT record")
		}
	})

	t.Run("Valid hostname with TXT record", func(t *testing.T) {
		tx := newRBLTestTransaction(t)
		if !op.Evaluate(tx, "valid_txt") {
			t.Errorf("Unexpected result for valid hostname")
		}
		if want, have := "not blocked", tx.Variables().TX().Get("httpbl_msg")[0]; want != have {
			t.Errorf("Unexpected result for valid hostname: want %q, have %q", want, have)
		}
	})

	t.Run("Invalid hostname", func(t *testing.T) {
		if op.Evaluate(nil, "invalid") {
			t.Errorf("Unexpected result for invalid hostname")
		}
	})

	t.Run("Blocked hostname", func(t *testing.T) {
		tx := newRBLTestTransaction(t)
		if !op.Evaluate(tx, "blocked") {
			t.Fatal("Unexpected result for blocked hostname")
		}
		t.Log(tx.Variables().TX().Get("httpbl_msg"))
		if want, have := "blocked", tx.Variables().TX().Get("httpbl_msg")[0]; want != have {
			t.Errorf("Unexpected result for valid hostname: want %q, have %q", want, have)
		}
	})
}

func newRBLTestResolver(t *testing.T) *net.Resolver {
	t.Helper()
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for test DNS server: %v", err)
	}

	records := map[string]struct {
		address string
		text    string
	}{
		"valid_no_txt.xbl.spamhaus.org.": {address: "1.2.3.4"},
		"valid_txt.xbl.spamhaus.org.":    {address: "1.2.3.5", text: "not blocked"},
		"blocked.xbl.spamhaus.org.":      {address: "1.2.3.6", text: "blocked"},
	}
	handler := dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		response.RecursionAvailable = true
		if len(request.Question) != 1 {
			response.Rcode = dns.RcodeFormatError
			_ = writer.WriteMsg(response)
			return
		}

		question := request.Question[0]
		record, found := records[question.Name]
		if !found {
			response.Rcode = dns.RcodeNameError
			_ = writer.WriteMsg(response)
			return
		}
		header := dns.RR_Header{Name: question.Name, Class: dns.ClassINET, Ttl: 60}
		switch question.Qtype {
		case dns.TypeA:
			header.Rrtype = dns.TypeA
			response.Answer = append(response.Answer, &dns.A{Hdr: header, A: net.ParseIP(record.address).To4()})
		case dns.TypeTXT:
			if record.text != "" {
				header.Rrtype = dns.TypeTXT
				response.Answer = append(response.Answer, &dns.TXT{Hdr: header, Txt: []string{record.text}})
			}
		}
		_ = writer.WriteMsg(response)
	})

	server := &dns.Server{PacketConn: packet, Handler: handler}
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- server.ActivateAndServe()
	}()
	t.Cleanup(func() {
		if err := packet.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close test DNS listener: %v", err)
		}
		if err := <-serveErr; err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("serve test DNS: %v", err)
		}
	})

	address := packet.LocalAddr().String()
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "udp4", address)
		},
	}
}

func newRBLTestTransaction(t *testing.T) *corazawaf.Transaction {
	t.Helper()
	waf := corazawaf.NewWAF()
	t.Cleanup(func() {
		if err := waf.Close(); err != nil {
			t.Error(err)
		}
	})
	tx := waf.NewTransaction()
	t.Cleanup(func() {
		if err := tx.Close(); err != nil {
			t.Error(err)
		}
	})
	return tx
}
