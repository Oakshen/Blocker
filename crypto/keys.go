package crypto

import (
	"crypto/ed25519"
	"fmt"
)

const (
	PrivKeyLen = 64
	PubKeyLen  = 32
)

type PrivateKey struct {
	key ed25519.PrivateKey
}
type PublicKey struct {
	key ed25519.PublicKey
}

func GeneratePrivateKey() *PrivateKey {
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		fmt.Errorf("generate error:%w", err)
	}
	return &PrivateKey{
		key: privateKey,
	}
}

func (p *PrivateKey) Sign(msg []byte) []byte {
	return ed25519.Sign(p.key, msg)
}

func (p *PrivateKey) Public() *PublicKey {
	pub := make([]byte, PubKeyLen)
	copy(pub, p.key[32:])
	return &PublicKey{
		key: pub,
	}
}
