package lorenz

import (
	"crypto/sha256"
	"encoding/binary"
)

const (
	dt    = 0.01
	sigma = 10.0
	rho   = 28.0
	beta  = 8.0 / 3.0
)

func cryptBlock(dst, src []byte, s *lorenzState, encrypt bool) {
	var p, d int
	for i := range BlockSize {
		d = r(s.a[0], s.o[0]) + r(s.a[1], s.o[1])
		if encrypt {
			p = (int(src[i]) + d) % 256
		} else {
			p = (int(src[i]) - d) % 256
		}
		dst[i] = byte(p)
		s.update()
	}
}

type lorenzState struct {
	m [3]int
	o [3]int
	r [3]float64
	a [3]float64
}

func newState(key []byte) *lorenzState {
	var (
		a = getA(key)
		m = getMu(a)
		o = getOmega(a)
		r = getR(a)
	)
	return &lorenzState{
		m: m,
		o: o,
		r: r,
		a: getAlpha(r, m),
	}
}

func (s *lorenzState) update() {
	// keep this order
	s.updateMu()
	s.updateOmega()
	s.step()
	s.updateAlpha()
}

func (s *lorenzState) updateMu() {
	for i := range s.m {
		s.m[i] = (s.m[i] + r(s.a[i], s.o[i])) % 3
	}
}

func (s *lorenzState) updateOmega() {
	for i := range s.o {
		s.o[i] = (s.o[i] + r(s.a[i], s.o[i])) % 4
	}
}

func (s *lorenzState) step() {
	x, y, z := s.r[0], s.r[1], s.r[2]

	f := [3]float64{
		(1-sigma)*x + sigma*y,
		rho*x - 2*y - x*z,
		x*y + (1-beta)*z,
	}

	for i := range s.r {
		s.r[i] += f[i] * dt
	}
}

func (s *lorenzState) updateAlpha() {
	for i, m := range s.m {
		s.a[i] = s.r[m]
	}
}

func r(alpha float64, omega int) int {
	// nu = 13

	_0 := int(alpha * 1e14)
	_1 := 255 << (8 * omega)

	return (_0 & _1) >> (8 * omega)
}

func int6(b []byte) int {
	_ = b[5]
	return int(b[0]) | int(b[1])<<8 | int(b[2])<<16 |
		int(b[3])<<24 | int(b[4])<<32 | int(b[5])<<40
}

func getA(key []byte) [3]int {
	return [3]int{
		int6(key[:6]),
		int6(key[6:12]),
		int6(key[12:]),
	}
}

func getR(a [3]int) [3]float64 {
	return [3]float64{
		float64(a[0])/1e16 + 1,
		float64(a[1])/1e16 + 3,
		float64(a[2])/1e16 + 30,
	}
}

func getMu(a [3]int) [3]int {
	x, y, z := a[0]%3, a[1]%3, a[2]%3
	return [3]int{
		(x + y + z) % 3,
		(x*y + z) % 3,
		(x + y*z) % 3,
	}
}

func getAlpha(r [3]float64, mu [3]int) [3]float64 {
	alpha := [3]float64{}
	for i, m := range mu {
		alpha[i] = r[m]
	}
	return alpha
}

func getOmega(a [3]int) [3]int {
	omega := [3]int{}
	for i := 0; i < 3; i++ {
		h := sha256.New()
		binary.Write(h, binary.LittleEndian, int64((i+1)*a[0]))
		binary.Write(h, binary.LittleEndian, int64((i+1)*a[1]))
		binary.Write(h, binary.LittleEndian, int64((i+1)*a[2]))
		sum := h.Sum(nil)
		omega[i] = int(binary.LittleEndian.Uint32(sum)) % 4
	}
	return omega
}
