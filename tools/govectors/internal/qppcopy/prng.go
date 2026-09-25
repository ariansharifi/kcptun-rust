// Provenance: verbatim copy of qpp.go and prng.go of github.com/xtaci/qpp v1.1.25
// (reference/kcptun/vendor/github.com/xtaci/qpp/prng.go). Unchanged below the marker,
// including the GPL-3.0 license header and the package name, so the vectors describe the
// real implementation. The generator needs seedToChunks, the pads and the PRNG state, which
// the module does not export; export.go (not copied) exposes them. Do not edit; re-copy
// instead (internal/qppcopy/copy_test.go checks this file against the pinned source and the
// copy as a whole against the linked module).
//
// This file is GPL-3.0, like its original. See crates/qpp/LICENSE.

// ---- verbatim below ----
// # Copyright (c) 2024 xtaci
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package qpp

// xorshift64star is a pseudo-random number generator that is part of the xorshift family of PRNGs.
func xorshift64star(state uint64) uint64 {
	state ^= state >> 12
	state ^= state << 25
	state ^= state >> 27
	return state * 2685821657736338717
}

// xorshift32
func xorshift32(state uint32) uint32 {
	state ^= state << 13
	state ^= state >> 17
	state ^= state << 5
	return state
}

// xorshift16
func xorshift16(state uint16) uint16 {
	state ^= state << 7
	state ^= state >> 9
	state ^= state << 8
	return state
}

func rol64(x uint64, k int) uint64 {
	return (x << k) | (x >> (64 - k))
}

func xoshiro256ss(s *[4]uint64) uint64 {
	result := rol64(s[1]*5, 7) * 9
	t := s[1] << 17

	s[2] ^= s[0]
	s[3] ^= s[1]
	s[1] ^= s[2]
	s[0] ^= s[3]

	s[2] ^= t
	s[3] = rol64(s[3], 45)

	return result
}
