// Package qpp (directory internal/qppcopy) is a verbatim copy of github.com/xtaci/qpp v1.1.25
// (qpp.go, prng.go; see the header of each file) plus this file, which is NOT copied: it
// exposes the few unexported things the vector generator has to record — seedToChunks, the pad
// tables and the PRNG state. The package keeps qpp's own name (qpp) so the copied files are
// byte-identical; import it as qppcopy.
//
// copy_test.go checks the copied files against the pinned source and the behaviour of this copy
// against the linked github.com/xtaci/qpp, so the vectors cannot drift from the real library.
//
// Original copyright: GNU General Public License v3.0, Copyright (c) 2024 xtaci. This file is
// GPL-3.0 as part of that derived work.
package qpp

// SeedToChunks exposes seedToChunks: the 32-byte chunks a seed is split into.
func SeedToChunks(seed []byte, qubits uint8) [][]byte { return seedToChunks(seed, qubits) }

// Pads exposes the encryption pads, numPads permutation matrices of 256 bytes each.
func (qpp *QuantumPermutationPad) Pads() []byte { return qpp.pads }

// RPads exposes the decryption pads, the inverse permutations.
func (qpp *QuantumPermutationPad) RPads() []byte { return qpp.rpads }

// EncRand exposes the default encryption generator (the one Encrypt drives).
func (qpp *QuantumPermutationPad) EncRand() *Rand { return qpp.encRand }

// DecRand exposes the default decryption generator (the one Decrypt drives).
func (qpp *QuantumPermutationPad) DecRand() *Rand { return qpp.decRand }

// State exposes the generator's xoshiro256** state, its latest output and the number of bytes
// of that output already consumed.
func (rd *Rand) State() ([4]uint64, uint64, uint8) { return rd.xoshiro, rd.seed64, rd.count }

// Next advances the xoshiro256** state and returns its output, as the encryption loop does when
// it crosses an eight-byte boundary. It leaves seed64 and count alone.
func (rd *Rand) Next() uint64 { return xoshiro256ss(&rd.xoshiro) }
