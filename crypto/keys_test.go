package crypto

import (
	"crypto/ed25519"
	"fmt"
	"testing"
)

func TestKey(t *testing.T) {
	privKey := GeneratePrivateKey()
	pubKey := privKey.Public()
	fmt.Printf("the private key is: %v\n", privKey)
	fmt.Printf("the pubkey key is: %v\n", pubKey)

	//test sign the message
	message := []byte("this is a test message")
	signature := privKey.Sign(message)
	fmt.Printf("Signature(HEX):%v\n", signature)

	//test verify the message
	isValid := ed25519.Verify(pubKey.key, message, signature)
	if isValid {
		t.Logf("verify ok %v is a valid message:\n", message)
	} else {
		t.Logf("verify faild %v isn't a valid message\n", message)
	}
}
