package types

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"strings"
	"unsafe"

	"github.com/wisherd/Pis/build"
	"github.com/wisherd/Pis/crypto"
	"github.com/wisherd/Pis/encoding"
)

// sanityCheckWriter checks that the bytes written to w exactly match the
// bytes in buf.
type sanityCheckWriter struct {
	w   io.Writer
	buf *bytes.Buffer
}

func (s sanityCheckWriter) Write(p []byte) (int, error) {
	if !bytes.Equal(p, s.buf.Next(len(p))) {
		panic("encoding mismatch")
	}
	return s.w.Write(p)
}

// MarshalPis implements the encoding.PisMarshaler interface.
func (b Block) MarshalPis(w io.Writer) error {
	if build.DEBUG {
		// Sanity check: compare against the old encoding
		buf := new(bytes.Buffer)
		encoding.NewEncoder(buf).EncodeAll(
			b.ParentID,
			b.Nonce,
			b.Timestamp,
			b.MinerPayouts,
			b.Transactions,
		)
		w = sanityCheckWriter{w, buf}
	}

	e := encoding.NewEncoder(w)
	e.Write(b.ParentID[:])
	e.Write(b.Nonce[:])
	e.WriteUint64(uint64(b.Timestamp))
	e.WriteInt(len(b.MinerPayouts))
	for i := range b.MinerPayouts {
		b.MinerPayouts[i].MarshalPis(e)
	}
	e.WriteInt(len(b.Transactions))
	for i := range b.Transactions {
		if err := b.Transactions[i].MarshalPis(e); err != nil {
			return err
		}
	}
	return e.Err()
}

// UnmarshalPis implements the encoding.PisUnmarshaler interface.
func (b *Block) UnmarshalPis(r io.Reader) error {
	if build.DEBUG {
		// Sanity check: compare against the old decoding
		buf := new(bytes.Buffer)
		r = io.TeeReader(r, buf)

		defer func() {
			checkB := new(Block)
			if err := encoding.UnmarshalAll(buf.Bytes(),
				&checkB.ParentID,
				&checkB.Nonce,
				&checkB.Timestamp,
				&checkB.MinerPayouts,
				&checkB.Transactions,
			); err != nil {
				// don't check invalid blocks
				return
			}
			if crypto.HashObject(b) != crypto.HashObject(checkB) {
				panic("decoding differs!")
			}
		}()
	}

	d := encoding.NewDecoder(r)
	d.ReadFull(b.ParentID[:])
	d.ReadFull(b.Nonce[:])
	b.Timestamp = Timestamp(d.NextUint64())
	// MinerPayouts
	b.MinerPayouts = make([]PiscoinOutput, d.NextPrefix(unsafe.Sizeof(PiscoinOutput{})))
	for i := range b.MinerPayouts {
		b.MinerPayouts[i].UnmarshalPis(d)
	}
	// Transactions
	b.Transactions = make([]Transaction, d.NextPrefix(unsafe.Sizeof(Transaction{})))
	for i := range b.Transactions {
		b.Transactions[i].UnmarshalPis(d)
	}
	return d.Err()
}

// MarshalJSON marshales a block id as a hex string.
func (bid BlockID) MarshalJSON() ([]byte, error) {
	return json.Marshal(bid.String())
}

// String prints the block id in hex.
func (bid BlockID) String() string {
	return fmt.Sprintf("%x", bid[:])
}

// LoadString loads a BlockID from a string
func (bid *BlockID) LoadString(str string) error {
	return (*crypto.Hash)(bid).LoadString(str)
}

// UnmarshalJSON decodes the json hex string of the block id.
func (bid *BlockID) UnmarshalJSON(b []byte) error {
	return (*crypto.Hash)(bid).UnmarshalJSON(b)
}

// MarshalPis implements the encoding.PisMarshaler interface.
func (cf CoveredFields) MarshalPis(w io.Writer) error {
	e := encoding.NewEncoder(w)
	e.WriteBool(cf.WholeTransaction)
	fields := [][]uint64{
		cf.PiscoinInputs,
		cf.PiscoinOutputs,
		cf.FileContracts,
		cf.FileContractRevisions,
		cf.StorageProofs,
		cf.PisfundInputs,
		cf.PisfundOutputs,
		cf.MinerFees,
		cf.ArbitraryData,
		cf.TransactionSignatures,
	}
	for _, f := range fields {
		e.WriteInt(len(f))
		for _, u := range f {
			e.WriteUint64(u)
		}
	}
	return e.Err()
}

// MarshalPisSize returns the encoded size of cf.
func (cf CoveredFields) MarshalPisSize() (size int) {
	size++ // WholeTransaction
	size += 8 + len(cf.PiscoinInputs)*8
	size += 8 + len(cf.PiscoinOutputs)*8
	size += 8 + len(cf.FileContracts)*8
	size += 8 + len(cf.FileContractRevisions)*8
	size += 8 + len(cf.StorageProofs)*8
	size += 8 + len(cf.PisfundInputs)*8
	size += 8 + len(cf.PisfundOutputs)*8
	size += 8 + len(cf.MinerFees)*8
	size += 8 + len(cf.ArbitraryData)*8
	size += 8 + len(cf.TransactionSignatures)*8
	return
}

// UnmarshalPis implements the encoding.PisUnmarshaler interface.
func (cf *CoveredFields) UnmarshalPis(r io.Reader) error {
	d := encoding.NewDecoder(r)
	buf := make([]byte, 1)
	d.ReadFull(buf)
	cf.WholeTransaction = (buf[0] == 1)
	fields := []*[]uint64{
		&cf.PiscoinInputs,
		&cf.PiscoinOutputs,
		&cf.FileContracts,
		&cf.FileContractRevisions,
		&cf.StorageProofs,
		&cf.PisfundInputs,
		&cf.PisfundOutputs,
		&cf.MinerFees,
		&cf.ArbitraryData,
		&cf.TransactionSignatures,
	}
	for i := range fields {
		f := make([]uint64, d.NextPrefix(unsafe.Sizeof(uint64(0))))
		for i := range f {
			f[i] = d.NextUint64()
		}
		*fields[i] = f
	}
	return d.Err()
}

// MarshalJSON implements the json.Marshaler interface.
func (c Currency) MarshalJSON() ([]byte, error) {
	// Must enclosed the value in quotes; otherwise JS will convert it to a
	// double and lose precision.
	return []byte(`"` + c.String() + `"`), nil
}

// UnmarshalJSON implements the json.Unmarshaler interface. An error is
// returned if a negative number is provided.
func (c *Currency) UnmarshalJSON(b []byte) error {
	// UnmarshalJSON does not expect quotes
	b = bytes.Trim(b, `"`)
	err := c.i.UnmarshalJSON(b)
	if err != nil {
		return err
	}
	if c.i.Sign() < 0 {
		c.i = *big.NewInt(0)
		return ErrNegativeCurrency
	}
	return nil
}

// MarshalPis implements the encoding.PisMarshaler interface. It writes the
// byte-slice representation of the Currency's internal big.Int to w. Note
// that as the bytes of the big.Int correspond to the absolute value of the
// integer, there is no way to marshal a negative Currency.
func (c Currency) MarshalPis(w io.Writer) error {
	// from math/big/arith.go
	const (
		_m    = ^big.Word(0)
		_logS = _m>>8&1 + _m>>16&1 + _m>>32&1
		_S    = 1 << _logS // number of bytes per big.Word
	)

	// get raw bits and seek to first zero byte
	bits := c.i.Bits()
	var i int
	for i = len(bits)*_S - 1; i >= 0; i-- {
		if bits[i/_S]>>(uint(i%_S)*8) != 0 {
			break
		}
	}

	// write length prefix
	e := encoding.NewEncoder(w)
	e.WriteInt(i + 1)

	// write bytes
	for ; i >= 0; i-- {
		e.WriteByte(byte(bits[i/_S] >> (uint(i%_S) * 8)))
	}
	return e.Err()
}

// MarshalPisSize returns the encoded size of c.
func (c Currency) MarshalPisSize() int {
	// from math/big/arith.go
	const (
		_m    = ^big.Word(0)
		_logS = _m>>8&1 + _m>>16&1 + _m>>32&1
		_S    = 1 << _logS // number of bytes per big.Word
	)

	// start with the number of Words * number of bytes per Word, then
	// subtract trailing bytes that are 0
	bits := c.i.Bits()
	size := len(bits) * _S
zeros:
	for i := len(bits) - 1; i >= 0; i-- {
		for j := _S - 1; j >= 0; j-- {
			if (bits[i] >> uintptr(j*8)) != 0 {
				break zeros
			}
			size--
		}
	}
	return 8 + size // account for length prefix
}

// UnmarshalPis implements the encoding.PisUnmarshaler interface.
func (c *Currency) UnmarshalPis(r io.Reader) error {
	d := encoding.NewDecoder(r)
	var dec Currency
	dec.i.SetBytes(d.ReadPrefixedBytes())
	*c = dec
	return d.Err()
}

// HumanString prints the Currency using human readable units. The unit used
// will be the largest unit that results in a value greater than 1. The value is
// rounded to 4 significant digits.
func (c Currency) HumanString() string {
	pico := PiscoinPrecision.Div64(1e12)
	if c.Cmp(pico) < 0 {
		return c.String() + " H"
	}

	// iterate until we find a unit greater than c
	mag := pico
	unit := ""
	for _, unit = range []string{"pS", "nS", "uS", "mS", "SC", "KS", "MS", "GS", "TS"} {
		if c.Cmp(mag.Mul64(1e3)) < 0 {
			break
		} else if unit != "TS" {
			// don't want to perform this multiply on the last iter; that
			// would give us 1.235 TS instead of 1235 TS
			mag = mag.Mul64(1e3)
		}
	}

	num := new(big.Rat).SetInt(c.Big())
	denom := new(big.Rat).SetInt(mag.Big())
	res, _ := new(big.Rat).Mul(num, denom.Inv(denom)).Float64()

	return fmt.Sprintf("%.4g %s", res, unit)
}

// String implements the fmt.Stringer interface.
func (c Currency) String() string {
	return c.i.String()
}

// Scan implements the fmt.Scanner interface, allowing Currency values to be
// scanned from text.
func (c *Currency) Scan(s fmt.ScanState, ch rune) error {
	var dec Currency
	err := dec.i.Scan(s, ch)
	if err != nil {
		return err
	}
	if dec.i.Sign() < 0 {
		return ErrNegativeCurrency
	}
	*c = dec
	return nil
}

// MarshalPis implements the encoding.PisMarshaler interface.
func (fc FileContract) MarshalPis(w io.Writer) error {
	e := encoding.NewEncoder(w)
	e.WriteUint64(fc.FileSize)
	e.Write(fc.FileMerkleRoot[:])
	e.WriteUint64(uint64(fc.WindowStart))
	e.WriteUint64(uint64(fc.WindowEnd))
	fc.Payout.MarshalPis(e)
	e.WriteInt(len(fc.ValidProofOutputs))
	for _, sco := range fc.ValidProofOutputs {
		sco.MarshalPis(e)
	}
	e.WriteInt(len(fc.MissedProofOutputs))
	for _, sco := range fc.MissedProofOutputs {
		sco.MarshalPis(e)
	}
	e.Write(fc.UnlockHash[:])
	e.WriteUint64(fc.RevisionNumber)
	return e.Err()
}

// MarshalPisSize returns the encoded size of fc.
func (fc FileContract) MarshalPisSize() (size int) {
	size += 8 // FileSize
	size += len(fc.FileMerkleRoot)
	size += 8 + 8 // WindowStart + WindowEnd
	size += fc.Payout.MarshalPisSize()
	size += 8
	for _, sco := range fc.ValidProofOutputs {
		size += sco.Value.MarshalPisSize()
		size += len(sco.UnlockHash)
	}
	size += 8
	for _, sco := range fc.MissedProofOutputs {
		size += sco.Value.MarshalPisSize()
		size += len(sco.UnlockHash)
	}
	size += len(fc.UnlockHash)
	size += 8 // RevisionNumber
	return
}

// UnmarshalPis implements the encoding.PisUnmarshaler interface.
func (fc *FileContract) UnmarshalPis(r io.Reader) error {
	d := encoding.NewDecoder(r)
	fc.FileSize = d.NextUint64()
	d.ReadFull(fc.FileMerkleRoot[:])
	fc.WindowStart = BlockHeight(d.NextUint64())
	fc.WindowEnd = BlockHeight(d.NextUint64())
	fc.Payout.UnmarshalPis(d)
	fc.ValidProofOutputs = make([]PiscoinOutput, d.NextPrefix(unsafe.Sizeof(PiscoinOutput{})))
	for i := range fc.ValidProofOutputs {
		fc.ValidProofOutputs[i].UnmarshalPis(d)
	}
	fc.MissedProofOutputs = make([]PiscoinOutput, d.NextPrefix(unsafe.Sizeof(PiscoinOutput{})))
	for i := range fc.MissedProofOutputs {
		fc.MissedProofOutputs[i].UnmarshalPis(d)
	}
	d.ReadFull(fc.UnlockHash[:])
	fc.RevisionNumber = d.NextUint64()
	return d.Err()
}

// MarshalPis implements the encoding.PisMarshaler interface.
func (fcr FileContractRevision) MarshalPis(w io.Writer) error {
	e := encoding.NewEncoder(w)
	e.Write(fcr.ParentID[:])
	fcr.UnlockConditions.MarshalPis(e)
	e.WriteUint64(fcr.NewRevisionNumber)
	e.WriteUint64(fcr.NewFileSize)
	e.Write(fcr.NewFileMerkleRoot[:])
	e.WriteUint64(uint64(fcr.NewWindowStart))
	e.WriteUint64(uint64(fcr.NewWindowEnd))
	e.WriteInt(len(fcr.NewValidProofOutputs))
	for _, sco := range fcr.NewValidProofOutputs {
		sco.MarshalPis(e)
	}
	e.WriteInt(len(fcr.NewMissedProofOutputs))
	for _, sco := range fcr.NewMissedProofOutputs {
		sco.MarshalPis(e)
	}
	e.Write(fcr.NewUnlockHash[:])
	return e.Err()
}

// MarshalPisSize returns the encoded size of fcr.
func (fcr FileContractRevision) MarshalPisSize() (size int) {
	size += len(fcr.ParentID)
	size += fcr.UnlockConditions.MarshalPisSize()
	size += 8 // NewRevisionNumber
	size += 8 // NewFileSize
	size += len(fcr.NewFileMerkleRoot)
	size += 8 + 8 // NewWindowStart + NewWindowEnd
	size += 8
	for _, sco := range fcr.NewValidProofOutputs {
		size += sco.Value.MarshalPisSize()
		size += len(sco.UnlockHash)
	}
	size += 8
	for _, sco := range fcr.NewMissedProofOutputs {
		size += sco.Value.MarshalPisSize()
		size += len(sco.UnlockHash)
	}
	size += len(fcr.NewUnlockHash)
	return
}

// UnmarshalPis implements the encoding.PisUnmarshaler interface.
func (fcr *FileContractRevision) UnmarshalPis(r io.Reader) error {
	d := encoding.NewDecoder(r)
	d.ReadFull(fcr.ParentID[:])
	fcr.UnlockConditions.UnmarshalPis(d)
	fcr.NewRevisionNumber = d.NextUint64()
	fcr.NewFileSize = d.NextUint64()
	d.ReadFull(fcr.NewFileMerkleRoot[:])
	fcr.NewWindowStart = BlockHeight(d.NextUint64())
	fcr.NewWindowEnd = BlockHeight(d.NextUint64())
	fcr.NewValidProofOutputs = make([]PiscoinOutput, d.NextPrefix(unsafe.Sizeof(PiscoinOutput{})))
	for i := range fcr.NewValidProofOutputs {
		fcr.NewValidProofOutputs[i].UnmarshalPis(d)
	}
	fcr.NewMissedProofOutputs = make([]PiscoinOutput, d.NextPrefix(unsafe.Sizeof(PiscoinOutput{})))
	for i := range fcr.NewMissedProofOutputs {
		fcr.NewMissedProofOutputs[i].UnmarshalPis(d)
	}
	d.ReadFull(fcr.NewUnlockHash[:])
	return d.Err()
}

// LoadString loads a FileContractID from a string
func (fcid *FileContractID) LoadString(str string) error {
	return (*crypto.Hash)(fcid).LoadString(str)
}

// MarshalJSON marshals an id as a hex string.
func (fcid FileContractID) MarshalJSON() ([]byte, error) {
	return json.Marshal(fcid.String())
}

// String prints the id in hex.
func (fcid FileContractID) String() string {
	return fmt.Sprintf("%x", fcid[:])
}

// UnmarshalJSON decodes the json hex string of the id.
func (fcid *FileContractID) UnmarshalJSON(b []byte) error {
	return (*crypto.Hash)(fcid).UnmarshalJSON(b)
}

// MarshalJSON marshals an id as a hex string.
func (oid OutputID) MarshalJSON() ([]byte, error) {
	return json.Marshal(oid.String())
}

// String prints the id in hex.
func (oid OutputID) String() string {
	return fmt.Sprintf("%x", oid[:])
}

// UnmarshalJSON decodes the json hex string of the id.
func (oid *OutputID) UnmarshalJSON(b []byte) error {
	return (*crypto.Hash)(oid).UnmarshalJSON(b)
}

// MarshalPis implements the encoding.PisMarshaler interface.
func (sci PiscoinInput) MarshalPis(w io.Writer) error {
	e := encoding.NewEncoder(w)
	e.Write(sci.ParentID[:])
	sci.UnlockConditions.MarshalPis(e)
	return e.Err()
}

// UnmarshalPis implements the encoding.PisUnmarshaler interface.
func (sci *PiscoinInput) UnmarshalPis(r io.Reader) error {
	d := encoding.NewDecoder(r)
	d.ReadFull(sci.ParentID[:])
	sci.UnlockConditions.UnmarshalPis(d)
	return d.Err()
}

// MarshalPis implements the encoding.PisMarshaler interface.
func (sco PiscoinOutput) MarshalPis(w io.Writer) error {
	e := encoding.NewEncoder(w)
	sco.Value.MarshalPis(e)
	e.Write(sco.UnlockHash[:])
	return e.Err()
}

// UnmarshalPis implements the encoding.PisUnmarshaler interface.
func (sco *PiscoinOutput) UnmarshalPis(r io.Reader) error {
	d := encoding.NewDecoder(r)
	sco.Value.UnmarshalPis(d)
	d.ReadFull(sco.UnlockHash[:])
	return d.Err()
}

// MarshalJSON marshals an id as a hex string.
func (scoid PiscoinOutputID) MarshalJSON() ([]byte, error) {
	return json.Marshal(scoid.String())
}

// String prints the id in hex.
func (scoid PiscoinOutputID) String() string {
	return fmt.Sprintf("%x", scoid[:])
}

// UnmarshalJSON decodes the json hex string of the id.
func (scoid *PiscoinOutputID) UnmarshalJSON(b []byte) error {
	return (*crypto.Hash)(scoid).UnmarshalJSON(b)
}

// MarshalPis implements the encoding.PisMarshaler interface.
func (sfi PisfundInput) MarshalPis(w io.Writer) error {
	e := encoding.NewEncoder(w)
	e.Write(sfi.ParentID[:])
	sfi.UnlockConditions.MarshalPis(e)
	e.Write(sfi.ClaimUnlockHash[:])
	return e.Err()
}

// UnmarshalPis implements the encoding.PisUnmarshaler interface.
func (sfi *PisfundInput) UnmarshalPis(r io.Reader) error {
	d := encoding.NewDecoder(r)
	d.ReadFull(sfi.ParentID[:])
	sfi.UnlockConditions.UnmarshalPis(d)
	d.ReadFull(sfi.ClaimUnlockHash[:])
	return d.Err()
}

// MarshalPis implements the encoding.PisMarshaler interface.
func (sfo PisfundOutput) MarshalPis(w io.Writer) error {
	e := encoding.NewEncoder(w)
	sfo.Value.MarshalPis(e)
	e.Write(sfo.UnlockHash[:])
	sfo.ClaimStart.MarshalPis(e)
	return e.Err()
}

// UnmarshalPis implements the encoding.PisUnmarshaler interface.
func (sfo *PisfundOutput) UnmarshalPis(r io.Reader) error {
	d := encoding.NewDecoder(r)
	sfo.Value.UnmarshalPis(d)
	d.ReadFull(sfo.UnlockHash[:])
	sfo.ClaimStart.UnmarshalPis(d)
	return d.Err()
}

// MarshalJSON marshals an id as a hex string.
func (sfoid PisfundOutputID) MarshalJSON() ([]byte, error) {
	return json.Marshal(sfoid.String())
}

// String prints the id in hex.
func (sfoid PisfundOutputID) String() string {
	return fmt.Sprintf("%x", sfoid[:])
}

// UnmarshalJSON decodes the json hex string of the id.
func (sfoid *PisfundOutputID) UnmarshalJSON(b []byte) error {
	return (*crypto.Hash)(sfoid).UnmarshalJSON(b)
}

// MarshalPis implements the encoding.PisMarshaler interface.
func (spk PisPublicKey) MarshalPis(w io.Writer) error {
	e := encoding.NewEncoder(w)
	e.Write(spk.Algorithm[:])
	e.WritePrefixedBytes(spk.Key)
	return e.Err()
}

// UnmarshalPis implements the encoding.PisUnmarshaler interface.
func (spk *PisPublicKey) UnmarshalPis(r io.Reader) error {
	d := encoding.NewDecoder(r)
	d.ReadFull(spk.Algorithm[:])
	spk.Key = d.ReadPrefixedBytes()
	return d.Err()
}

// LoadString is the inverse of PisPublicKey.String().
func (spk *PisPublicKey) LoadString(s string) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return
	}
	var err error
	spk.Key, err = hex.DecodeString(parts[1])
	if err != nil {
		spk.Key = nil
		return
	}
	copy(spk.Algorithm[:], []byte(parts[0]))
}

// String defines how to print a PisPublicKey - hex is used to keep things
// compact during logging. The key type prefix and lack of a checksum help to
// separate it from a sia address.
func (spk *PisPublicKey) String() string {
	return spk.Algorithm.String() + ":" + fmt.Sprintf("%x", spk.Key)
}

// MarshalJSON marshals a specifier as a string.
func (s Specifier) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// String returns the specifier as a string, trimming any trailing zeros.
func (s Specifier) String() string {
	var i int
	for i = range s {
		if s[i] == 0 {
			break
		}
	}
	return string(s[:i])
}

// UnmarshalJSON decodes the json string of the specifier.
func (s *Specifier) UnmarshalJSON(b []byte) error {
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return err
	}
	copy(s[:], str)
	return nil
}

// MarshalPis implements the encoding.PisMarshaler interface.
func (sp *StorageProof) MarshalPis(w io.Writer) error {
	e := encoding.NewEncoder(w)
	e.Write(sp.ParentID[:])
	e.Write(sp.Segment[:])
	e.WriteInt(len(sp.HashSet))
	for i := range sp.HashSet {
		e.Write(sp.HashSet[i][:])
	}
	return e.Err()
}

// UnmarshalPis implements the encoding.PisUnmarshaler interface.
func (sp *StorageProof) UnmarshalPis(r io.Reader) error {
	d := encoding.NewDecoder(r)
	d.ReadFull(sp.ParentID[:])
	d.ReadFull(sp.Segment[:])
	sp.HashSet = make([]crypto.Hash, d.NextPrefix(unsafe.Sizeof(crypto.Hash{})))
	for i := range sp.HashSet {
		d.ReadFull(sp.HashSet[i][:])
	}
	return d.Err()
}

// MarshalPis implements the encoding.PisMarshaler interface.
func (t Transaction) MarshalPis(w io.Writer) error {
	if build.DEBUG {
		// Sanity check: compare against the old encoding
		buf := new(bytes.Buffer)
		encoding.NewEncoder(buf).EncodeAll(
			t.PiscoinInputs,
			t.PiscoinOutputs,
			t.FileContracts,
			t.FileContractRevisions,
			t.StorageProofs,
			t.PisfundInputs,
			t.PisfundOutputs,
			t.MinerFees,
			t.ArbitraryData,
			t.TransactionSignatures,
		)
		w = sanityCheckWriter{w, buf}
	}

	e := encoding.NewEncoder(w)
	t.marshalPisNoSignatures(e)
	e.WriteInt(len((t.TransactionSignatures)))
	for i := range t.TransactionSignatures {
		t.TransactionSignatures[i].MarshalPis(e)
	}
	return e.Err()
}

// marshalPisNoSignatures is a helper function for calculating certain hashes
// that do not include the transaction's signatures.
func (t Transaction) marshalPisNoSignatures(w io.Writer) {
	e := encoding.NewEncoder(w)
	e.WriteInt(len((t.PiscoinInputs)))
	for i := range t.PiscoinInputs {
		t.PiscoinInputs[i].MarshalPis(e)
	}
	e.WriteInt(len((t.PiscoinOutputs)))
	for i := range t.PiscoinOutputs {
		t.PiscoinOutputs[i].MarshalPis(e)
	}
	e.WriteInt(len((t.FileContracts)))
	for i := range t.FileContracts {
		t.FileContracts[i].MarshalPis(e)
	}
	e.WriteInt(len((t.FileContractRevisions)))
	for i := range t.FileContractRevisions {
		t.FileContractRevisions[i].MarshalPis(e)
	}
	e.WriteInt(len((t.StorageProofs)))
	for i := range t.StorageProofs {
		t.StorageProofs[i].MarshalPis(e)
	}
	e.WriteInt(len((t.PisfundInputs)))
	for i := range t.PisfundInputs {
		t.PisfundInputs[i].MarshalPis(e)
	}
	e.WriteInt(len((t.PisfundOutputs)))
	for i := range t.PisfundOutputs {
		t.PisfundOutputs[i].MarshalPis(e)
	}
	e.WriteInt(len((t.MinerFees)))
	for i := range t.MinerFees {
		t.MinerFees[i].MarshalPis(e)
	}
	e.WriteInt(len((t.ArbitraryData)))
	for i := range t.ArbitraryData {
		e.WritePrefixedBytes(t.ArbitraryData[i])
	}
}

// MarshalPisSize returns the encoded size of t.
func (t Transaction) MarshalPisSize() (size int) {
	size += 8
	for _, sci := range t.PiscoinInputs {
		size += len(sci.ParentID)
		size += sci.UnlockConditions.MarshalPisSize()
	}
	size += 8
	for _, sco := range t.PiscoinOutputs {
		size += sco.Value.MarshalPisSize()
		size += len(sco.UnlockHash)
	}
	size += 8
	for i := range t.FileContracts {
		size += t.FileContracts[i].MarshalPisSize()
	}
	size += 8
	for i := range t.FileContractRevisions {
		size += t.FileContractRevisions[i].MarshalPisSize()
	}
	size += 8
	for _, sp := range t.StorageProofs {
		size += len(sp.ParentID)
		size += len(sp.Segment)
		size += 8 + len(sp.HashSet)*crypto.HashSize
	}
	size += 8
	for _, sfi := range t.PisfundInputs {
		size += len(sfi.ParentID)
		size += len(sfi.ClaimUnlockHash)
		size += sfi.UnlockConditions.MarshalPisSize()
	}
	size += 8
	for _, sfo := range t.PisfundOutputs {
		size += sfo.Value.MarshalPisSize()
		size += len(sfo.UnlockHash)
		size += sfo.ClaimStart.MarshalPisSize()
	}
	size += 8
	for i := range t.MinerFees {
		size += t.MinerFees[i].MarshalPisSize()
	}
	size += 8
	for i := range t.ArbitraryData {
		size += 8 + len(t.ArbitraryData[i])
	}
	size += 8
	for _, ts := range t.TransactionSignatures {
		size += len(ts.ParentID)
		size += 8 // ts.PublicKeyIndex
		size += 8 // ts.Timelock
		size += ts.CoveredFields.MarshalPisSize()
		size += 8 + len(ts.Signature)
	}

	// Sanity check against the slower method.
	if build.DEBUG {
		expectedSize := len(encoding.Marshal(t))
		if expectedSize != size {
			panic("Transaction size different from expected size.")
		}
	}
	return
}

// UnmarshalPis implements the encoding.PisUnmarshaler interface.
func (t *Transaction) UnmarshalPis(r io.Reader) error {
	d := encoding.NewDecoder(r)
	t.PiscoinInputs = make([]PiscoinInput, d.NextPrefix(unsafe.Sizeof(PiscoinInput{})))
	for i := range t.PiscoinInputs {
		t.PiscoinInputs[i].UnmarshalPis(d)
	}
	t.PiscoinOutputs = make([]PiscoinOutput, d.NextPrefix(unsafe.Sizeof(PiscoinOutput{})))
	for i := range t.PiscoinOutputs {
		t.PiscoinOutputs[i].UnmarshalPis(d)
	}
	t.FileContracts = make([]FileContract, d.NextPrefix(unsafe.Sizeof(FileContract{})))
	for i := range t.FileContracts {
		t.FileContracts[i].UnmarshalPis(d)
	}
	t.FileContractRevisions = make([]FileContractRevision, d.NextPrefix(unsafe.Sizeof(FileContractRevision{})))
	for i := range t.FileContractRevisions {
		t.FileContractRevisions[i].UnmarshalPis(d)
	}
	t.StorageProofs = make([]StorageProof, d.NextPrefix(unsafe.Sizeof(StorageProof{})))
	for i := range t.StorageProofs {
		t.StorageProofs[i].UnmarshalPis(d)
	}
	t.PisfundInputs = make([]PisfundInput, d.NextPrefix(unsafe.Sizeof(PisfundInput{})))
	for i := range t.PisfundInputs {
		t.PisfundInputs[i].UnmarshalPis(d)
	}
	t.PisfundOutputs = make([]PisfundOutput, d.NextPrefix(unsafe.Sizeof(PisfundOutput{})))
	for i := range t.PisfundOutputs {
		t.PisfundOutputs[i].UnmarshalPis(d)
	}
	t.MinerFees = make([]Currency, d.NextPrefix(unsafe.Sizeof(Currency{})))
	for i := range t.MinerFees {
		t.MinerFees[i].UnmarshalPis(d)
	}
	t.ArbitraryData = make([][]byte, d.NextPrefix(unsafe.Sizeof([]byte{})))
	for i := range t.ArbitraryData {
		t.ArbitraryData[i] = d.ReadPrefixedBytes()
	}
	t.TransactionSignatures = make([]TransactionSignature, d.NextPrefix(unsafe.Sizeof(TransactionSignature{})))
	for i := range t.TransactionSignatures {
		t.TransactionSignatures[i].UnmarshalPis(d)
	}
	return d.Err()
}

// MarshalJSON marshals an id as a hex string.
func (tid TransactionID) MarshalJSON() ([]byte, error) {
	return json.Marshal(tid.String())
}

// String prints the id in hex.
func (tid TransactionID) String() string {
	return fmt.Sprintf("%x", tid[:])
}

// UnmarshalJSON decodes the json hex string of the id.
func (tid *TransactionID) UnmarshalJSON(b []byte) error {
	return (*crypto.Hash)(tid).UnmarshalJSON(b)
}

// MarshalPis implements the encoding.PisMarshaler interface.
func (ts TransactionSignature) MarshalPis(w io.Writer) error {
	e := encoding.NewEncoder(w)
	e.Write(ts.ParentID[:])
	e.WriteUint64(ts.PublicKeyIndex)
	e.WriteUint64(uint64(ts.Timelock))
	ts.CoveredFields.MarshalPis(e)
	e.WritePrefixedBytes(ts.Signature)
	return e.Err()
}

// UnmarshalPis implements the encoding.PisUnmarshaler interface.
func (ts *TransactionSignature) UnmarshalPis(r io.Reader) error {
	d := encoding.NewDecoder(r)
	d.ReadFull(ts.ParentID[:])
	ts.PublicKeyIndex = d.NextUint64()
	ts.Timelock = BlockHeight(d.NextUint64())
	ts.CoveredFields.UnmarshalPis(d)
	ts.Signature = d.ReadPrefixedBytes()
	return d.Err()
}

// MarshalPis implements the encoding.PisMarshaler interface.
func (uc UnlockConditions) MarshalPis(w io.Writer) error {
	e := encoding.NewEncoder(w)
	e.WriteUint64(uint64(uc.Timelock))
	e.WriteInt(len(uc.PublicKeys))
	for _, spk := range uc.PublicKeys {
		spk.MarshalPis(e)
	}
	e.WriteUint64(uc.SignaturesRequired)
	return e.Err()
}

// MarshalPisSize returns the encoded size of uc.
func (uc UnlockConditions) MarshalPisSize() (size int) {
	size += 8 // Timelock
	size += 8 // length prefix for PublicKeys
	for _, spk := range uc.PublicKeys {
		size += len(spk.Algorithm)
		size += 8 + len(spk.Key)
	}
	size += 8 // SignaturesRequired
	return
}

// UnmarshalPis implements the encoding.PisUnmarshaler interface.
func (uc *UnlockConditions) UnmarshalPis(r io.Reader) error {
	d := encoding.NewDecoder(r)
	uc.Timelock = BlockHeight(d.NextUint64())
	uc.PublicKeys = make([]PisPublicKey, d.NextPrefix(unsafe.Sizeof(PisPublicKey{})))
	for i := range uc.PublicKeys {
		uc.PublicKeys[i].UnmarshalPis(d)
	}
	uc.SignaturesRequired = d.NextUint64()
	return d.Err()
}

// MarshalJSON is implemented on the unlock hash to always produce a hex string
// upon marshalling.
func (uh UnlockHash) MarshalJSON() ([]byte, error) {
	return json.Marshal(uh.String())
}

// UnmarshalJSON is implemented on the unlock hash to recover an unlock hash
// that has been encoded to a hex string.
func (uh *UnlockHash) UnmarshalJSON(b []byte) error {
	// Check the length of b.
	if len(b) != crypto.HashSize*2+UnlockHashChecksumSize*2+2 && len(b) != crypto.HashSize*2+2 {
		return ErrUnlockHashWrongLen
	}
	return uh.LoadString(string(b[1 : len(b)-1]))
}

// String returns the hex representation of the unlock hash as a string - this
// includes a checksum.
func (uh UnlockHash) String() string {
	uhChecksum := crypto.HashObject(uh)
	return fmt.Sprintf("%x%x", uh[:], uhChecksum[:UnlockHashChecksumSize])
}

// LoadString loads a hex representation (including checksum) of an unlock hash
// into an unlock hash object. An error is returned if the string is invalid or
// fails the checksum.
func (uh *UnlockHash) LoadString(strUH string) error {
	// Check the length of strUH.
	if len(strUH) != crypto.HashSize*2+UnlockHashChecksumSize*2 {
		return ErrUnlockHashWrongLen
	}

	// Decode the unlock hash.
	var byteUnlockHash []byte
	var checksum []byte
	_, err := fmt.Sscanf(strUH[:crypto.HashSize*2], "%x", &byteUnlockHash)
	if err != nil {
		return err
	}

	// Decode and verify the checksum.
	_, err = fmt.Sscanf(strUH[crypto.HashSize*2:], "%x", &checksum)
	if err != nil {
		return err
	}
	expectedChecksum := crypto.HashBytes(byteUnlockHash)
	if !bytes.Equal(expectedChecksum[:UnlockHashChecksumSize], checksum) {
		return ErrInvalidUnlockHashChecksum
	}

	copy(uh[:], byteUnlockHash[:])
	return nil
}

// Scan implements the fmt.Scanner interface, allowing UnlockHash values to be
// scanned from text.
func (uh *UnlockHash) Scan(s fmt.ScanState, ch rune) error {
	s.SkipSpace()
	tok, err := s.Token(false, nil)
	if err != nil {
		return err
	}
	return uh.LoadString(string(tok))
}
