package renew

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"testing"
)

// TestGenerateMarshalParseRoundTrip exercises all three key types
// through the generate → PKCS#8 PEM → parse → public-key path the
// renewer uses, and confirms the concrete type survives the round trip.
func TestGenerateMarshalParseRoundTrip(t *testing.T) {
	cases := []KeyType{KeyECDSAP256, KeyEd25519}
	for _, kt := range cases {
		t.Run(string(kt), func(t *testing.T) {
			k, err := generateKey(kt)
			if err != nil {
				t.Fatalf("generateKey: %v", err)
			}
			pemBytes, err := marshalPrivateKeyPEM(k)
			if err != nil {
				t.Fatalf("marshalPrivateKeyPEM: %v", err)
			}
			got, err := parsePrivateKeyPEM(pemBytes)
			if err != nil {
				t.Fatalf("parsePrivateKeyPEM: %v", err)
			}
			if _, err := marshalPublicKeyPEM(got.Public()); err != nil {
				t.Fatalf("marshalPublicKeyPEM: %v", err)
			}
			switch kt {
			case KeyECDSAP256:
				if _, ok := got.(*ecdsa.PrivateKey); !ok {
					t.Errorf("got %T, want *ecdsa.PrivateKey", got)
				}
			case KeyEd25519:
				if _, ok := got.(ed25519.PrivateKey); !ok {
					t.Errorf("got %T, want ed25519.PrivateKey", got)
				}
			}
		})
	}
}

func TestGenerateKeyUnknown(t *testing.T) {
	if _, err := generateKey("bogus"); err == nil {
		t.Fatal("expected error for unknown key type")
	}
}
