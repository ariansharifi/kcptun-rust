package main

// Area "rs" (plan step 04.1): the Reed-Solomon codec kcp-go v5.6.66 uses, klauspost/reedsolomon
// v1.13.0 created with reedsolomon.New(ds, ps) and default options (for ds+ps <= 256 that is
// the buildMatrix encoding matrix: vandermonde(total, ds) x inverse(top ds x ds), GF(2^8) with
// polynomial 0x11D). Everything is produced through the exported API: the GF tables come from
// LowLevel.GalMulSlice and Inv, the encoding matrix from Encode on unit vectors. Case groups
// and fields are documented in README.md.

import (
	"bytes"
	"errors"
	"fmt"
	"slices"

	"github.com/klauspost/reedsolomon"
)

// RNG streams of the rs area (see newRNG).
const (
	streamRsPatterns = 1       // + config index: the erasure patterns of one config
	streamRsData     = 1 << 16 // + config index << 12 + shard length: the data shards
	streamRsErrors   = 3 << 16 // + case index: the shard contents of the error group
)

// rsConfigs are the (ds, ps) pairs of the matrix, encode and reconstruct groups, in file order.
var rsConfigs = [][2]int{
	{1, 1}, {2, 1}, {3, 2}, {4, 4}, {10, 3}, {20, 5}, {30, 10}, {70, 30}, {128, 128}, {200, 56},
}

// rsShardLens are the shard lengths of the encode and reconstruct groups.
var rsShardLens = []int{1, 17, 64, 1370, 1500}

// rsPatternNames are the erasure patterns of each config, in file order (see rsPatterns).
var rsPatternNames = []string{"first_data", "all_parity", "data_max", "mixed"}

// rsFullMax is the largest byte string stored in full (hex); longer ones are stored as a Blob
// under the same key with a "_blob" suffix, which keeps rs.json well below 1 MB.
const rsFullMax = 4096

// rsBytes stores b in full or as a Blob, depending on its length (rsFullMax).
func rsBytes(b []byte) (full string, blob *Blob) {
	if len(b) <= rsFullMax {
		return hx(b), nil
	}
	bl := newBlob(b)
	return "", &bl
}

// rsGaloisCase is the "galois" case: GF(2^8) tables of the library.
type rsGaloisCase struct {
	Name     string `json:"name"`
	Exp      string `json:"exp"`       // 2^i for i = 0..255 (klauspost expTable)
	Log      string `json:"log"`       // log2(x) for x = 0..255, with log(0) = 0 (klauspost logTable)
	Inv      string `json:"inv"`       // Inv(x) for x = 0..255 (klauspost invTable, Inv(0) = 0)
	MulTable Blob   `json:"mul_table"` // mulTable[a][b] = a*b, row-major, 65536 bytes
	MulRow   string `json:"mul_row_2"` // row a = 2 of the multiplication table, in full
}

func (c rsGaloisCase) CaseName() string { return c.Name }

// rsMatrixCase is one "matrix/ds=D,ps=P" case: the parity rows of the encoding matrix.
type rsMatrixCase struct {
	Name       string `json:"name"`
	Ds         int    `json:"ds"`
	Ps         int    `json:"ps"`
	Parity     string `json:"parity_rows,omitempty"`      // rows ds..ds+ps, row-major (ps*ds bytes)
	ParityBlob *Blob  `json:"parity_rows_blob,omitempty"` // same, as a Blob, when longer than rsFullMax
}

func (c rsMatrixCase) CaseName() string { return c.Name }

// rsEncodeCase is one "encode/ds=D,ps=P/len=N" case.
type rsEncodeCase struct {
	Name       string `json:"name"`
	Ds         int    `json:"ds"`
	Ps         int    `json:"ps"`
	Len        int    `json:"len"`
	Stream     uint64 `json:"stream"`      // data = randBytes(newRNG("rs", stream), ds*len)
	DataSHA256 string `json:"data_sha256"` // SHA-256 of all data shards (to check the generator)
	Parity     string `json:"parity,omitempty"`
	ParityBlob *Blob  `json:"parity_blob,omitempty"`
}

func (c rsEncodeCase) CaseName() string { return c.Name }

// rsReconstructCase is one "reconstruct/ds=D,ps=P/len=N/<pattern>" case.
type rsReconstructCase struct {
	Name      string `json:"name"`
	Ds        int    `json:"ds"`
	Ps        int    `json:"ps"`
	Len       int    `json:"len"`
	Stream    uint64 `json:"stream"`    // same data as the encode case
	Missing   []int  `json:"missing"`   // shard indices set to nil before ReconstructData
	Recovered []int  `json:"recovered"` // the missing data shards ReconstructData filled in
	Out       string `json:"out,omitempty"`
	OutBlob   *Blob  `json:"out_blob,omitempty"`
}

func (c rsReconstructCase) CaseName() string { return c.Name }

// rsErrorCase is one "error/<label>" case: the result of New, Encode or ReconstructData on
// invalid (or borderline) input.
type rsErrorCase struct {
	Name      string `json:"name"`
	Op        string `json:"op"` // new, encode or reconstruct_data
	Ds        int    `json:"ds"`
	Ps        int    `json:"ps"`
	ShardLens []int  `json:"shard_lens,omitempty"` // lengths of the shards passed (0 = nil)
	Err       string `json:"err"`                  // "" when the call succeeded
	Impl      string `json:"impl,omitempty"`       // op new only: the %T of the Encoder
}

func (c rsErrorCase) CaseName() string { return c.Name }

func genRs() ([]any, error) {
	var cases []any
	g, err := genRsGalois()
	if err != nil {
		return nil, err
	}
	cases = append(cases, g)
	for _, cfg := range rsConfigs {
		c, err := genRsMatrix(cfg[0], cfg[1])
		if err != nil {
			return nil, err
		}
		cases = append(cases, c)
	}
	for ci, cfg := range rsConfigs {
		cs, err := genRsConfig(ci, cfg[0], cfg[1])
		if err != nil {
			return nil, err
		}
		cases = append(cases, cs...)
	}
	es, err := genRsErrors()
	if err != nil {
		return nil, err
	}
	return append(cases, es...), nil
}

func genRsGalois() (rsGaloisCase, error) {
	var ll reedsolomon.LowLevel
	all := make([]byte, 256)
	for i := range all {
		all[i] = byte(i)
	}
	mul := make([]byte, 0, 256*256)
	for a := range 256 {
		row := make([]byte, 256)
		ll.GalMulSlice(byte(a), all, row)
		mul = append(mul, row...)
	}
	// Cross-check the xor variant and the table's basic field properties.
	for a := range 256 {
		out := bytes.Repeat([]byte{0x5a}, 256)
		ll.GalMulSliceXor(byte(a), all, out)
		for b := range 256 {
			if out[b] != mul[a*256+b]^0x5a {
				return rsGaloisCase{}, fmt.Errorf("GalMulSliceXor(%d)[%d] mismatch", a, b)
			}
			if mul[a*256+b] != mul[b*256+a] {
				return rsGaloisCase{}, fmt.Errorf("mulTable not symmetric at %d,%d", a, b)
			}
		}
	}
	exp := make([]byte, 256)
	logt := make([]byte, 256)
	x := byte(1)
	for i := range 256 {
		exp[i] = x
		if i < 255 {
			logt[x] = byte(i)
		}
		x = mul[int(x)*256+2]
	}
	if exp[255] != 1 || exp[0] != 1 {
		return rsGaloisCase{}, errors.New("2 is not a generator of order 255")
	}
	// 0x11D: 2^8 = 0x1D.
	if exp[8] != 0x1d {
		return rsGaloisCase{}, fmt.Errorf("2^8 = %#x, want 0x1d (polynomial 0x11D)", exp[8])
	}
	inv := make([]byte, 256)
	for i := range inv {
		inv[i] = reedsolomon.Inv(byte(i))
		if i != 0 && mul[i*256+int(inv[i])] != 1 {
			return rsGaloisCase{}, fmt.Errorf("Inv(%d) = %d is not an inverse", i, inv[i])
		}
	}
	return rsGaloisCase{
		Name: "galois", Exp: hx(exp), Log: hx(logt), Inv: hx(inv),
		MulTable: newBlob(mul), MulRow: hx(mul[2*256 : 3*256]),
	}, nil
}

// genRsMatrix reads the parity rows of the encoding matrix back through Encode: with data
// shard j equal to the unit vector e_j (length ds), byte j of parity shard k is m[ds+k][j].
func genRsMatrix(ds, ps int) (rsMatrixCase, error) {
	enc, err := reedsolomon.New(ds, ps)
	if err != nil {
		return rsMatrixCase{}, err
	}
	shards := make([][]byte, ds+ps)
	for i := range shards {
		shards[i] = make([]byte, ds)
		if i < ds {
			shards[i][i] = 1
		}
	}
	if err := enc.Encode(shards); err != nil {
		return rsMatrixCase{}, err
	}
	rows := bytes.Join(shards[ds:], nil)
	c := rsMatrixCase{Name: fmt.Sprintf("matrix/ds=%d,ps=%d", ds, ps), Ds: ds, Ps: ps}
	c.Parity, c.ParityBlob = rsBytes(rows)
	return c, nil
}

// rsData returns the data shards of config ci with shard length n, and their stream.
func rsData(ci, ds, n int) ([][]byte, uint64) {
	stream := uint64(streamRsData + ci<<12 + n)
	data := randBytes(newRNG("rs", stream), ds*n)
	shards := make([][]byte, ds)
	for i := range shards {
		shards[i] = data[i*n : (i+1)*n : (i+1)*n]
	}
	return shards, stream
}

// rsPatterns returns the erasure patterns of one config (sorted indices, at most ps missing):
//   - first_data: shard 0 plus ps-1 random other shards (data or parity);
//   - all_parity: every parity shard (the data is complete, ReconstructData has nothing to do);
//   - data_max:   min(ds, ps) random data shards (uses the most parity rows);
//   - mixed:      k in [1, ps] random shards with at least one data shard and, for k >= 2,
//     at least one parity shard.
func rsPatterns(ci, ds, ps int) [][]int {
	r := newRNG("rs", streamRsPatterns+uint64(ci))
	total := ds + ps
	pick := func(set map[int]bool, from, to, n int) { // add n random new indices in [from, to)
		for added := 0; added < n; {
			i := from + r.IntN(to-from)
			if !set[i] {
				set[i] = true
				added++
			}
		}
	}
	sorted := func(set map[int]bool) []int {
		out := make([]int, 0, len(set))
		for i := range set {
			out = append(out, i)
		}
		slices.Sort(out)
		return out
	}

	firstData := map[int]bool{0: true}
	pick(firstData, 1, total, ps-1)

	allParity := map[int]bool{}
	for i := ds; i < total; i++ {
		allParity[i] = true
	}

	dataMax := map[int]bool{}
	pick(dataMax, 0, ds, min(ds, ps))

	k := 1 + r.IntN(ps)
	mixed := map[int]bool{}
	pick(mixed, 0, ds, 1)
	if k >= 2 {
		pick(mixed, ds, total, 1)
		pick(mixed, 0, total, k-2)
	}
	return [][]int{sorted(firstData), sorted(allParity), sorted(dataMax), sorted(mixed)}
}

func genRsConfig(ci, ds, ps int) ([]any, error) {
	enc, err := reedsolomon.New(ds, ps)
	if err != nil {
		return nil, err
	}
	patterns := rsPatterns(ci, ds, ps)
	var encCases, recCases []any
	for _, n := range rsShardLens {
		data, stream := rsData(ci, ds, n)
		shards := make([][]byte, ds+ps)
		copy(shards, data)
		for i := ds; i < ds+ps; i++ {
			shards[i] = make([]byte, n)
		}
		if err := enc.Encode(shards); err != nil {
			return nil, err
		}
		if ok, err := enc.Verify(shards); err != nil || !ok {
			return nil, fmt.Errorf("ds=%d ps=%d len=%d: Verify = %v, %v", ds, ps, n, ok, err)
		}
		ec := rsEncodeCase{
			Name: fmt.Sprintf("encode/ds=%d,ps=%d/len=%d", ds, ps, n),
			Ds:   ds, Ps: ps, Len: n, Stream: stream,
			DataSHA256: sha256Hex(bytes.Join(data, nil)),
		}
		ec.Parity, ec.ParityBlob = rsBytes(bytes.Join(shards[ds:], nil))
		encCases = append(encCases, ec)

		for pi, missing := range patterns {
			rc, err := genRsReconstruct(enc, shards, missing, ds, ps, n, stream)
			if err != nil {
				return nil, err
			}
			rc.Name = fmt.Sprintf("reconstruct/ds=%d,ps=%d/len=%d/%s", ds, ps, n, rsPatternNames[pi])
			recCases = append(recCases, rc)
		}
	}
	return append(encCases, recCases...), nil
}

// genRsReconstruct runs ReconstructData on a copy of the full shard set with the missing
// shards set to nil, and checks the result: recovered data equals the original, missing
// parity shards stay nil, present shards are untouched.
func genRsReconstruct(enc reedsolomon.Encoder, full [][]byte, missing []int, ds, ps, n int, stream uint64) (rsReconstructCase, error) {
	shards := make([][]byte, len(full))
	for i := range full {
		if !slices.Contains(missing, i) {
			shards[i] = slices.Clone(full[i])
		}
	}
	if err := enc.ReconstructData(shards); err != nil {
		return rsReconstructCase{}, fmt.Errorf("ds=%d ps=%d len=%d missing=%v: %w", ds, ps, n, missing, err)
	}
	var recovered []int
	var out []byte
	for i := range shards {
		isMissing := slices.Contains(missing, i)
		switch {
		case i < ds && isMissing:
			recovered = append(recovered, i)
			out = append(out, shards[i]...)
			if !bytes.Equal(shards[i], full[i]) {
				return rsReconstructCase{}, fmt.Errorf("ds=%d ps=%d missing=%v: shard %d not recovered", ds, ps, missing, i)
			}
		case isMissing:
			if shards[i] != nil {
				return rsReconstructCase{}, fmt.Errorf("ds=%d ps=%d missing=%v: parity %d was filled", ds, ps, missing, i)
			}
		default:
			if !bytes.Equal(shards[i], full[i]) {
				return rsReconstructCase{}, fmt.Errorf("ds=%d ps=%d missing=%v: shard %d changed", ds, ps, missing, i)
			}
		}
	}
	if recovered == nil {
		recovered = []int{}
	}
	c := rsReconstructCase{Ds: ds, Ps: ps, Len: n, Stream: stream, Missing: missing, Recovered: recovered}
	c.Out, c.OutBlob = rsBytes(out)
	return c, nil
}

// rsErrorOps are the error group: label, op, (ds, ps) and the shard lengths (0 = nil).
var rsErrorOps = []struct {
	label  string
	op     string
	ds, ps int
	lens   []int
}{
	{"new_ds0", "new", 0, 1, nil},
	{"new_ds0_ps0", "new", 0, 0, nil},
	{"new_ps0", "new", 256, 0, nil},
	{"new_256", "new", 200, 56, nil},
	{"new_257", "new", 200, 57, nil},
	{"new_1_256", "new", 1, 256, nil},
	{"encode_count_short", "encode", 4, 2, []int{8, 8, 8, 8, 8}},
	{"encode_count_long", "encode", 4, 2, []int{8, 8, 8, 8, 8, 8, 8}},
	{"encode_size_mismatch", "encode", 4, 2, []int{8, 8, 8, 8, 8, 7}},
	{"encode_one_nil", "encode", 4, 2, []int{8, 8, 0, 8, 8, 8}},
	{"encode_nil_parity", "encode", 4, 2, []int{8, 8, 8, 8, 0, 0}},
	{"encode_all_nil", "encode", 4, 2, []int{0, 0, 0, 0, 0, 0}},
	{"encode_ps0", "encode", 3, 0, []int{8, 8, 8}},
	{"reconstruct_count_short", "reconstruct_data", 4, 2, []int{8, 8, 8, 8, 8}},
	{"reconstruct_too_few", "reconstruct_data", 4, 2, []int{0, 8, 0, 8, 0, 8}},
	{"reconstruct_size_mismatch", "reconstruct_data", 4, 2, []int{8, 8, 7, 0, 8, 8}},
	{"reconstruct_all_nil", "reconstruct_data", 4, 2, []int{0, 0, 0, 0, 0, 0}},
	{"reconstruct_all_present", "reconstruct_data", 4, 2, []int{8, 8, 8, 8, 8, 8}},
	{"reconstruct_data_present", "reconstruct_data", 4, 2, []int{8, 8, 8, 8, 0, 0}},
	{"reconstruct_ps0_missing", "reconstruct_data", 3, 0, []int{8, 0, 8}},
	{"reconstruct_ps0_present", "reconstruct_data", 3, 0, []int{8, 8, 8}},
}

func genRsErrors() ([]any, error) {
	var cases []any
	for i, e := range rsErrorOps {
		c := rsErrorCase{Name: "error/" + e.label, Op: e.op, Ds: e.ds, Ps: e.ps, ShardLens: e.lens}
		enc, err := reedsolomon.New(e.ds, e.ps)
		if e.op == "new" {
			if err != nil {
				c.Err = err.Error()
			} else {
				c.Impl = fmt.Sprintf("%T", enc)
			}
			cases = append(cases, c)
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("error/%s: New: %w", e.label, err)
		}
		r := newRNG("rs", streamRsErrors+uint64(i)) // shard contents are irrelevant to the result
		shards := make([][]byte, len(e.lens))
		for j, n := range e.lens {
			if n > 0 {
				shards[j] = randBytes(r, n)
			}
		}
		switch e.op {
		case "encode":
			err = enc.Encode(shards)
		case "reconstruct_data":
			err = enc.ReconstructData(shards)
		}
		if err != nil {
			c.Err = err.Error()
		}
		cases = append(cases, c)
	}
	return cases, nil
}
