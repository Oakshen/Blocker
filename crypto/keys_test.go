package crypto

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKey(t *testing.T) {
	privKey := GeneratePrivateKey()
	pubKey := privKey.Public()
	fmt.Printf("the private key is: %v\n", privKey)
	fmt.Printf("the pubkey key is: %v\n", pubKey)

	//test sign the message
	message := []byte("this is a test message")
	sig := privKey.Sign(message)
	fmt.Printf("Signature(HEX):%v\n", sig)

	//test verify the message
	assert.True(t, sig.Verify(pubKey, message))

	//test invalid message
	falseMsg := []byte("ni hao")
	assert.False(t, sig.Verify(pubKey, falseMsg))

	//test invalid public key
	invalidPrivateKey := GeneratePrivateKey()
	invalidPublicKey := invalidPrivateKey.Public()
	assert.False(t, sig.Verify(invalidPublicKey, message))
}
