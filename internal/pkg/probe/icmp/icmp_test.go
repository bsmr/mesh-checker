package icmp

import (
	"bytes"
	"testing"
)

func TestBuildAndParseEchoRequest(t *testing.T) {
	pkt, err := buildEcho(0x4242, 7, []byte("ping"))
	if err != nil {
		t.Fatal(err)
	}
	id, seq, payload, err := parseEchoReply(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if id != 0x4242 {
		t.Errorf("id = %x", id)
	}
	if seq != 7 {
		t.Errorf("seq = %d", seq)
	}
	if !bytes.Equal(payload, []byte("ping")) {
		t.Errorf("payload = %q", payload)
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	if _, _, _, err := parseEchoReply([]byte{0, 1, 2}); err == nil {
		t.Error("expected error on garbage input")
	}
}
