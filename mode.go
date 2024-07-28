package lorenz

import (
	"crypto/cipher"
)

type lorenzMode struct {
	key []byte
	enc bool
}

func NewChainEnctypter(key []byte) (cipher.BlockMode, error) {
	if k := len(key); k != 18 {
		return nil, KeySizeError(k)
	}
	return &lorenzMode{key: key, enc: true}, nil
}

func NewChainDectypter(key []byte) (cipher.BlockMode, error) {
	if k := len(key); k != 18 {
		return nil, KeySizeError(k)
	}
	return &lorenzMode{key: key, enc: false}, nil
}

func (m *lorenzMode) BlockSize() int { return BlockSize }

func (m *lorenzMode) CryptBlocks(dst, src []byte) {
	if len(src)%BlockSize != 0 {
		panic("lorenz: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("lorenz: output smaller than input")
	}
	if inexactOverlap(dst[:BlockSize], src[:BlockSize]) {
		panic("lorenz: invalid buffer overlap")
	}

	state := newState(m.key)
	for len(src) > 0 {
		cryptBlock(dst[:BlockSize], src[:BlockSize], state, m.enc)
		src = src[BlockSize:]
		dst = dst[BlockSize:]
	}
}
