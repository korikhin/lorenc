package lorenz

import (
	"crypto/cipher"
	"strconv"
)

const BlockSize = 16

type lorenzCipher struct {
	key []byte
}

type KeySizeError int

func (k KeySizeError) Error() string {
	return "lorenz: invalid key size " + strconv.Itoa(int(k))
}

func NewCipher(key []byte) (cipher.Block, error) {
	if k := len(key); k != 18 {
		return nil, KeySizeError(k)
	}
	return &lorenzCipher{key: key}, nil
}

func (c *lorenzCipher) BlockSize() int { return BlockSize }

func (c *lorenzCipher) Encrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("lorenz: input not full block")
	}
	if len(dst) < BlockSize {
		panic("lorenz: output not full block")
	}
	if inexactOverlap(dst[:BlockSize], src[:BlockSize]) {
		panic("lorenz: invalid buffer overlap")
	}
	state := newState(c.key)
	cryptBlock(dst, src, state, true /* encrypt */)
}

func (c *lorenzCipher) Decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("lorenz: input not full block")
	}
	if len(dst) < BlockSize {
		panic("lorenz: output not full block")
	}
	if inexactOverlap(dst[:BlockSize], src[:BlockSize]) {
		panic("lorenz: invalid buffer overlap")
	}
	state := newState(c.key)
	cryptBlock(dst, src, state, false /* encrypt */)
}
