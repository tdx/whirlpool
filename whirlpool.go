// Copyright 2012 Jimmy Zelinskie. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package whirlpool implements the ISO/IEC 10118-3:2004 whirlpool
// cryptographic hash. Whirlpool is defined in
// http://www.larc.usp.br/~pbarreto/WhirlpoolPage.html
package whirlpool

import (
	"encoding/binary"
	"hash"
)

// whirlpool represents the partial evaluation of a checksum.
type whirlpool struct {
	bitLength  [lengthBytes]byte       // Number of hashed bits.
	buffer     [wblockBytes]byte       // Buffer of data to be hashed.
	bufferBits int                     // Current number of bits on the buffer.
	bufferPos  int                     // Current byte location on buffer.
	hash       [digestBytes / 8]uint64 // Hash state.
}

// New returns a new hash.Hash computing the whirlpool checksum.
func New() hash.Hash {
	return new(whirlpool)
}

// NewRaw ...
func NewRaw() *whirlpool {
	return new(whirlpool)
}

func (w *whirlpool) Reset() {
	// Cleanup the buffer.
	w.buffer = [wblockBytes]byte{}
	w.bufferBits = 0
	w.bufferPos = 0

	// Cleanup the digest.
	w.hash = [digestBytes / 8]uint64{}

	// Clean up the number of hashed bits.
	w.bitLength = [lengthBytes]byte{}
}

func (w *whirlpool) Size() int {
	return digestBytes
}

func (w *whirlpool) BlockSize() int {
	return wblockBytes
}

func (w *whirlpool) transform() {
	var (
		K     [8]uint64 // Round key.
		block [8]uint64 // μ(buffer).
		state [8]uint64 // Cipher state.
		L     [8]uint64
	)

	// Map the buffer to a block.
	block[0] = binary.BigEndian.Uint64(w.buffer[0:])
	block[1] = binary.BigEndian.Uint64(w.buffer[8:])
	block[2] = binary.BigEndian.Uint64(w.buffer[16:])
	block[3] = binary.BigEndian.Uint64(w.buffer[24:])
	block[4] = binary.BigEndian.Uint64(w.buffer[32:])
	block[5] = binary.BigEndian.Uint64(w.buffer[40:])
	block[6] = binary.BigEndian.Uint64(w.buffer[48:])
	block[7] = binary.BigEndian.Uint64(w.buffer[56:])

	// Compute & apply K^0 to the cipher state.
	K[0] = w.hash[0]
	K[1] = w.hash[1]
	K[2] = w.hash[2]
	K[3] = w.hash[3]
	K[4] = w.hash[4]
	K[5] = w.hash[5]
	K[6] = w.hash[6]
	K[7] = w.hash[7]

	state[0] = block[0] ^ K[0]
	state[1] = block[1] ^ K[1]
	state[2] = block[2] ^ K[2]
	state[3] = block[3] ^ K[3]
	state[4] = block[4] ^ K[4]
	state[5] = block[5] ^ K[5]
	state[6] = block[6] ^ K[6]
	state[7] = block[7] ^ K[7]

	// Iterate over all the rounds.
	for r := 1; r <= rounds; r++ {
		// Compute K^rounds from K^(rounds-1).
		L[0] = _C0[byte(K[0%8]>>56)] ^
			_C1[byte(K[(0+7)%8]>>48)] ^
			_C2[byte(K[(0+6)%8]>>40)] ^
			_C3[byte(K[(0+5)%8]>>32)] ^
			_C4[byte(K[(0+4)%8]>>24)] ^
			_C5[byte(K[(0+3)%8]>>16)] ^
			_C6[byte(K[(0+2)%8]>>8)] ^
			_C7[byte(K[(0+1)%8])]
		L[1] = _C0[byte(K[1%8]>>56)] ^
			_C1[byte(K[(1+7)%8]>>48)] ^
			_C2[byte(K[(1+6)%8]>>40)] ^
			_C3[byte(K[(1+5)%8]>>32)] ^
			_C4[byte(K[(1+4)%8]>>24)] ^
			_C5[byte(K[(1+3)%8]>>16)] ^
			_C6[byte(K[(1+2)%8]>>8)] ^
			_C7[byte(K[(1+1)%8])]
		L[2] = _C0[byte(K[2%8]>>56)] ^
			_C1[byte(K[(2+7)%8]>>48)] ^
			_C2[byte(K[(2+6)%8]>>40)] ^
			_C3[byte(K[(2+5)%8]>>32)] ^
			_C4[byte(K[(2+4)%8]>>24)] ^
			_C5[byte(K[(2+3)%8]>>16)] ^
			_C6[byte(K[(2+2)%8]>>8)] ^
			_C7[byte(K[(2+1)%8])]
		L[3] = _C0[byte(K[3%8]>>56)] ^
			_C1[byte(K[(3+7)%8]>>48)] ^
			_C2[byte(K[(3+6)%8]>>40)] ^
			_C3[byte(K[(3+5)%8]>>32)] ^
			_C4[byte(K[(3+4)%8]>>24)] ^
			_C5[byte(K[(3+3)%8]>>16)] ^
			_C6[byte(K[(3+2)%8]>>8)] ^
			_C7[byte(K[(3+1)%8])]
		L[4] = _C0[byte(K[4%8]>>56)] ^
			_C1[byte(K[(4+7)%8]>>48)] ^
			_C2[byte(K[(4+6)%8]>>40)] ^
			_C3[byte(K[(4+5)%8]>>32)] ^
			_C4[byte(K[(4+4)%8]>>24)] ^
			_C5[byte(K[(4+3)%8]>>16)] ^
			_C6[byte(K[(4+2)%8]>>8)] ^
			_C7[byte(K[(4+1)%8])]
		L[5] = _C0[byte(K[5%8]>>56)] ^
			_C1[byte(K[(5+7)%8]>>48)] ^
			_C2[byte(K[(5+6)%8]>>40)] ^
			_C3[byte(K[(5+5)%8]>>32)] ^
			_C4[byte(K[(5+4)%8]>>24)] ^
			_C5[byte(K[(5+3)%8]>>16)] ^
			_C6[byte(K[(5+2)%8]>>8)] ^
			_C7[byte(K[(5+1)%8])]
		L[6] = _C0[byte(K[6%8]>>56)] ^
			_C1[byte(K[(6+7)%8]>>48)] ^
			_C2[byte(K[(6+6)%8]>>40)] ^
			_C3[byte(K[(6+5)%8]>>32)] ^
			_C4[byte(K[(6+4)%8]>>24)] ^
			_C5[byte(K[(6+3)%8]>>16)] ^
			_C6[byte(K[(6+2)%8]>>8)] ^
			_C7[byte(K[(6+1)%8])]
		L[7] = _C0[byte(K[7%8]>>56)] ^
			_C1[byte(K[(7+7)%8]>>48)] ^
			_C2[byte(K[(7+6)%8]>>40)] ^
			_C3[byte(K[(7+5)%8]>>32)] ^
			_C4[byte(K[(7+4)%8]>>24)] ^
			_C5[byte(K[(7+3)%8]>>16)] ^
			_C6[byte(K[(7+2)%8]>>8)] ^
			_C7[byte(K[(7+1)%8])]
		L[0] ^= rc[r]

		K[0] = L[0]
		K[1] = L[1]
		K[2] = L[2]
		K[3] = L[3]
		K[4] = L[4]
		K[5] = L[5]
		K[6] = L[6]
		K[7] = L[7]

		// Apply r-th round transformation.
		L[0] = _C0[byte(state[0%8]>>56)] ^
			_C1[byte(state[(0+7)%8]>>48)] ^
			_C2[byte(state[(0+6)%8]>>40)] ^
			_C3[byte(state[(0+5)%8]>>32)] ^
			_C4[byte(state[(0+4)%8]>>24)] ^
			_C5[byte(state[(0+3)%8]>>16)] ^
			_C6[byte(state[(0+2)%8]>>8)] ^
			_C7[byte(state[(0+1)%8])] ^ K[0%8]
		L[1] = _C0[byte(state[1%8]>>56)] ^
			_C1[byte(state[(1+7)%8]>>48)] ^
			_C2[byte(state[(1+6)%8]>>40)] ^
			_C3[byte(state[(1+5)%8]>>32)] ^
			_C4[byte(state[(1+4)%8]>>24)] ^
			_C5[byte(state[(1+3)%8]>>16)] ^
			_C6[byte(state[(1+2)%8]>>8)] ^
			_C7[byte(state[(1+1)%8])] ^ K[1%8]
		L[2] = _C0[byte(state[2%8]>>56)] ^
			_C1[byte(state[(2+7)%8]>>48)] ^
			_C2[byte(state[(2+6)%8]>>40)] ^
			_C3[byte(state[(2+5)%8]>>32)] ^
			_C4[byte(state[(2+4)%8]>>24)] ^
			_C5[byte(state[(2+3)%8]>>16)] ^
			_C6[byte(state[(2+2)%8]>>8)] ^
			_C7[byte(state[(2+1)%8])] ^ K[2%8]
		L[3] = _C0[byte(state[3%8]>>56)] ^
			_C1[byte(state[(3+7)%8]>>48)] ^
			_C2[byte(state[(3+6)%8]>>40)] ^
			_C3[byte(state[(3+5)%8]>>32)] ^
			_C4[byte(state[(3+4)%8]>>24)] ^
			_C5[byte(state[(3+3)%8]>>16)] ^
			_C6[byte(state[(3+2)%8]>>8)] ^
			_C7[byte(state[(3+1)%8])] ^ K[3%8]
		L[4] = _C0[byte(state[4%8]>>56)] ^
			_C1[byte(state[(4+7)%8]>>48)] ^
			_C2[byte(state[(4+6)%8]>>40)] ^
			_C3[byte(state[(4+5)%8]>>32)] ^
			_C4[byte(state[(4+4)%8]>>24)] ^
			_C5[byte(state[(4+3)%8]>>16)] ^
			_C6[byte(state[(4+2)%8]>>8)] ^
			_C7[byte(state[(4+1)%8])] ^ K[4%8]
		L[5] = _C0[byte(state[5%8]>>56)] ^
			_C1[byte(state[(5+7)%8]>>48)] ^
			_C2[byte(state[(5+6)%8]>>40)] ^
			_C3[byte(state[(5+5)%8]>>32)] ^
			_C4[byte(state[(5+4)%8]>>24)] ^
			_C5[byte(state[(5+3)%8]>>16)] ^
			_C6[byte(state[(5+2)%8]>>8)] ^
			_C7[byte(state[(5+1)%8])] ^ K[5%8]
		L[6] = _C0[byte(state[6%8]>>56)] ^
			_C1[byte(state[(6+7)%8]>>48)] ^
			_C2[byte(state[(6+6)%8]>>40)] ^
			_C3[byte(state[(6+5)%8]>>32)] ^
			_C4[byte(state[(6+4)%8]>>24)] ^
			_C5[byte(state[(6+3)%8]>>16)] ^
			_C6[byte(state[(6+2)%8]>>8)] ^
			_C7[byte(state[(6+1)%8])] ^ K[6%8]
		L[7] = _C0[byte(state[7%8]>>56)] ^
			_C1[byte(state[(7+7)%8]>>48)] ^
			_C2[byte(state[(7+6)%8]>>40)] ^
			_C3[byte(state[(7+5)%8]>>32)] ^
			_C4[byte(state[(7+4)%8]>>24)] ^
			_C5[byte(state[(7+3)%8]>>16)] ^
			_C6[byte(state[(7+2)%8]>>8)] ^
			_C7[byte(state[(7+1)%8])] ^ K[7%8]

		state[0] = L[0]
		state[1] = L[1]
		state[2] = L[2]
		state[3] = L[3]
		state[4] = L[4]
		state[5] = L[5]
		state[6] = L[6]
		state[7] = L[7]
	}

	// Apply the Miyaguchi-Preneel compression function.
	w.hash[0] ^= state[0] ^ block[0]
	w.hash[1] ^= state[1] ^ block[1]
	w.hash[2] ^= state[2] ^ block[2]
	w.hash[3] ^= state[3] ^ block[3]
	w.hash[4] ^= state[4] ^ block[4]
	w.hash[5] ^= state[5] ^ block[5]
	w.hash[6] ^= state[6] ^ block[6]
	w.hash[7] ^= state[7] ^ block[7]
}

func (w *whirlpool) Write(source []byte) (int, error) {
	var (
		sourcePos  int                                     // Index of the leftmost source.
		nn         = len(source)                           // Num of bytes to process.
		sourceBits = uint64(nn * 8)                        // Num of bits to process.
		sourceGap  = uint((8 - (int(sourceBits & 7))) & 7) // Space on source[sourcePos].
		bufferRem  = uint(w.bufferBits & 7)                // Occupied bits on buffer[bufferPos].
		b          uint32                                  // Current byte.
	)

	// Tally the length of the data added.
	for i, carry, value := 31, uint32(0), uint64(sourceBits); i >= 0 && (carry != 0 || value != 0); i-- {
		carry += uint32(w.bitLength[i]) + (uint32(value & 0xff))
		w.bitLength[i] = byte(carry)
		carry >>= 8
		value >>= 8
	}

	// Process data in chunks of 8 bits.
	for sourceBits > 8 {
		// Take a byte form the source.
		b = uint32(((source[sourcePos] << sourceGap) & 0xff) |
			((source[sourcePos+1] & 0xff) >> (8 - sourceGap)))

		// Process this byte.
		w.buffer[w.bufferPos] |= uint8(b >> bufferRem)
		w.bufferPos++
		w.bufferBits += int(8 - bufferRem)

		if w.bufferBits == digestBits {
			// Process this block.
			w.transform()
			// Reset the buffer.
			w.bufferBits = 0
			w.bufferPos = 0
		}
		w.buffer[w.bufferPos] = byte(b << (8 - bufferRem))
		w.bufferBits += int(bufferRem)

		// Proceed to remaining data.
		sourceBits -= 8
		sourcePos++
	}

	// 0 <= sourceBits <= 8; All data leftover is in source[sourcePos].
	if sourceBits > 0 {
		b = uint32((source[sourcePos] << sourceGap) & 0xff) // The bits are left-justified.

		// Process the remaining bits.
		w.buffer[w.bufferPos] |= byte(b) >> bufferRem
	} else {
		b = 0
	}

	if uint64(bufferRem)+sourceBits < 8 {
		// The remaining data fits on the buffer[bufferPos].
		w.bufferBits += int(sourceBits)
	} else {
		// The buffer[bufferPos] is full.
		w.bufferPos++
		w.bufferBits += 8 - int(bufferRem) // bufferBits = 8*bufferPos
		sourceBits -= uint64(8 - bufferRem)

		// Now, 0 <= sourceBits <= 8; all data leftover is in source[sourcePos].
		if w.bufferBits == digestBits {
			// Process this data block.
			w.transform()
			// Reset buffer.
			w.bufferBits = 0
			w.bufferPos = 0
		}
		w.buffer[w.bufferPos] = byte(b << (8 - bufferRem))
		w.bufferBits += int(sourceBits)
	}
	return nn, nil
}

func (w *whirlpool) Sum(in []byte) []byte {
	// Copy the whirlpool so that the caller can keep summing.
	n := *w

	// Append a 1-bit.
	n.buffer[n.bufferPos] |= 0x80 >> (uint(n.bufferBits) & 7)
	n.bufferPos++

	// The remaining bits should be 0. Pad with 0s to be complete.
	if n.bufferPos > wblockBytes-lengthBytes {
		if n.bufferPos < wblockBytes {
			for i := 0; i < wblockBytes-n.bufferPos; i++ {
				n.buffer[n.bufferPos+i] = 0
			}
		}
		// Process this data block.
		n.transform()
		// Reset the buffer.
		n.bufferPos = 0
	}

	if n.bufferPos < wblockBytes-lengthBytes {
		for i := 0; i < (wblockBytes-lengthBytes)-n.bufferPos; i++ {
			n.buffer[n.bufferPos+i] = 0
		}
	}
	n.bufferPos = wblockBytes - lengthBytes

	// Append the bit length of the hashed data.
	for i := 0; i < lengthBytes; i++ {
		n.buffer[n.bufferPos+i] = n.bitLength[i]
	}

	// Process this data block.
	n.transform()

	// Return the final digest as []byte.
	var digest [digestBytes]byte
	for i := 0; i < digestBytes/8; i++ {
		digest[i*8] = byte(n.hash[i] >> 56)
		digest[i*8+1] = byte(n.hash[i] >> 48)
		digest[i*8+2] = byte(n.hash[i] >> 40)
		digest[i*8+3] = byte(n.hash[i] >> 32)
		digest[i*8+4] = byte(n.hash[i] >> 24)
		digest[i*8+5] = byte(n.hash[i] >> 16)
		digest[i*8+6] = byte(n.hash[i] >> 8)
		digest[i*8+7] = byte(n.hash[i])
	}

	return append(in, digest[:digestBytes]...)
}
