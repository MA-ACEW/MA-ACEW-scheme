package ma

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

type EbpsParams struct {
	u  bls.G1Jac    // G1 generator in Jacobian coordinates
	v  bls.G2Jac    // G2 generator in Jacobian coordinates
	ua bls.G1Affine // G1 generator in Affine coordinates
	va bls.G2Affine // G2 generator in Affine coordinates
}

type Signer struct {
	lsk1 fr.Element
	lsk2 fr.Element
	tsk  fr.Element
	lvk1 bls.G2Affine
	lvk2 bls.G2Affine
	tvk  bls.G2Affine
}

type User struct {
	aux []byte
	sk  struct {
		gamma fr.Element
		delta fr.Element
	}
	pk struct {
		hGamma bls.G1Affine
		hDelta bls.G1Affine
	}

	longtermSigs []struct {
		h bls.G1Affine
		s []bls.G1Affine
	}
	aggregatedLongSig struct {
		h bls.G1Affine
		s bls.G1Affine
	}

	epochSigs          []bls.G1Affine
	aggregatedEpochSig bls.G1Affine

	ELgamal struct {
		esk fr.Element
		epk bls.G1Affine
	}

	parsedAux struct {
		initialized bool
		messages    [][]byte
		pubKeys     []bls.G2Affine
		positions   []int
	}

	originalMessages  [][]byte
	EncryptedMessages []EncryptedMessage
	Commitments       []bls.G1Affine
}

const (
	LogLevelDebug = iota
	LogLevelInfo
	LogLevelWarn
	LogLevelError
	LogLevelNone
)

var currentLogLevel = LogLevelInfo

var bigIntPool = sync.Pool{
	New: func() interface{} {
		return new(big.Int)
	},
}

func getBigInt() *big.Int {
	return bigIntPool.Get().(*big.Int).SetInt64(0)
}

func putBigInt(i *big.Int) {
	bigIntPool.Put(i)
}

var (
	ErrNilParameters       = errors.New("nil input parameters")
	ErrInvalidMessageCount = errors.New("invalid message count")
	ErrInvalidSignerCount  = errors.New("invalid signer count")
	ErrSignerMismatch      = errors.New("verification key mismatch")
	ErrNoLongtermSig       = errors.New("no longterm signatures found")
	ErrInvalidIndex        = errors.New("index out of range")
)

func logDebug(format string, args ...interface{}) {
	if currentLogLevel <= LogLevelDebug {
		fmt.Printf("[DEBUG] "+format+"\n", args...)
	}
}

func logInfo(format string, args ...interface{}) {
	if currentLogLevel <= LogLevelInfo {
		fmt.Printf("[INFO] "+format+"\n", args...)
	}
}

func logError(format string, args ...interface{}) {
	if currentLogLevel <= LogLevelError {
		fmt.Printf("[ERROR] "+format+"\n", args...)
	}
}

func Setup(lambda int) *EbpsParams {
	u, v, ua, va := bls.Generators()
	return &EbpsParams{
		u:  u,
		v:  v,
		ua: ua,
		va: va,
	}
}

func LongKeyGen(pp *EbpsParams, n int) []Signer {

	signers := make([]Signer, n)

	xs := make([]fr.Element, n)
	ys := make([]fr.Element, n)

	for i := 0; i < n; i++ {
		xs[i].SetRandom()
		ys[i].SetRandom()
	}

	var wg sync.WaitGroup
	wg.Add(2)

	var Xs []bls.G2Affine
	go func() {
		defer wg.Done()
		Xs = bls.BatchScalarMultiplicationG2(&pp.va, xs)
	}()

	var Ys []bls.G2Affine
	go func() {
		defer wg.Done()
		Ys = bls.BatchScalarMultiplicationG2(&pp.va, ys)
	}()

	wg.Wait()

	for i := 0; i < n; i++ {
		signers[i] = Signer{
			lsk1: xs[i],
			lsk2: ys[i],
			lvk1: Xs[i],
			lvk2: Ys[i],
		}
	}

	return signers
}
func EPochKeyGenBenc(pp *EbpsParams, signers *Signer, epoch int) Signer {
	var tsk fr.Element
	var tvk bls.G2Affine
	tsk.SetRandom()
	signers.tsk = tsk
	tskInt := tsk.BigInt(&big.Int{})
	tvk.ScalarMultiplication(&pp.va, tskInt)
	signers.tvk = tvk
	return *signers
}
func EpochKeyGen(pp *EbpsParams, signers []Signer, epoch int) []Signer {
	n := len(signers)
	tsks := make([]fr.Element, n)

	var wg sync.WaitGroup
	wg.Add(n)

	for i := range signers {
		go func(idx int) {
			defer wg.Done()

			tsks[idx].SetRandom()
			signers[idx].tsk = tsks[idx]
		}(i)
	}

	wg.Wait()

	tvks := bls.BatchScalarMultiplicationG2(&pp.va, tsks)

	for i := range signers {
		signers[i].tvk = tvks[i]
	}

	return signers
}

func areSignersDistinct(signers []Signer) bool {
	seen := make(map[string]bool)
	for _, signer := range signers {
		keyBytes := signer.lvk2.Bytes()
		key := string(keyBytes[:])
		if seen[key] {
			return false
		}
		seen[key] = true
	}
	return true
}

var bufferPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

func GenAuxTag(messages [][]byte, signers []Signer, l int, pp *EbpsParams) (*User, error) {
	logDebug("GenAuxTag called with l=%d, len(signers)=%d, len(messages)=%d", l, len(signers), len(messages))

	if l <= 0 {
		logError("Error: l <= 0")
		return nil, errors.New("number of messages must be greater than 0")
	}

	if l > len(signers) {
		logError("Error: l > len(signers)")
		return nil, errors.New("number of messages must be less than or equal to number of signers")
	}

	if len(messages) != l {
		logError("Error: len(messages) != l")
		return nil, errors.New("number of messages must equal to l")
	}

	user := new(User)

	user.sk.gamma.SetRandom()
	user.sk.delta.SetRandom()

	var uGamma, uDelta bls.G1Affine
	uGamma.ScalarMultiplication(&pp.ua, user.sk.gamma.BigInt(new(big.Int)))
	uDelta.ScalarMultiplication(&pp.ua, user.sk.delta.BigInt(new(big.Int)))

	auxBuffer := bufferPool.Get().(*bytes.Buffer)
	auxBuffer.Reset()
	defer bufferPool.Put(auxBuffer)

	gammaBytes := uGamma.Bytes()
	if _, err := auxBuffer.Write(gammaBytes[:]); err != nil {
		return nil, fmt.Errorf("failed to write uGamma: %v", err)
	}

	deltaBytes := uDelta.Bytes()
	if _, err := auxBuffer.Write(deltaBytes[:]); err != nil {
		return nil, fmt.Errorf("failed to write uDelta: %v", err)
	}

	for i := 0; i < l; i++ {

		msgLen := byte(len(messages[i]))
		if err := auxBuffer.WriteByte(msgLen); err != nil {
			return nil, fmt.Errorf("failed to write message length: %v", err)
		}

		if _, err := auxBuffer.Write(messages[i]); err != nil {
			return nil, fmt.Errorf("failed to write message %d: %v", i, err)
		}

		lvk2Bytes := signers[i].lvk2.Bytes()
		if len(lvk2Bytes) != bls.SizeOfG2AffineCompressed {
			return nil, fmt.Errorf("signers[%d].lvk2.Bytes has incorrect length: got %d, want %d", i, len(lvk2Bytes), bls.SizeOfG2AffineCompressed)
		}
		if _, err := auxBuffer.Write(lvk2Bytes[:]); err != nil {
			return nil, fmt.Errorf("failed to write lvk2[%d]: %v", i, err)
		}
	}

	user.aux = make([]byte, auxBuffer.Len())
	copy(user.aux, auxBuffer.Bytes())

	domain := []byte("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_")
	h, err := bls.HashToG1(user.aux, domain)
	if err != nil {
		return nil, fmt.Errorf("failed to hash aux: %v", err)
	}

	user.pk.hGamma.ScalarMultiplication(&h, user.sk.gamma.BigInt(new(big.Int)))
	user.pk.hDelta.ScalarMultiplication(&h, user.sk.delta.BigInt(new(big.Int)))

	return user, nil
}

func GenBlindAuxTag(messages [][]byte, signers []Signer, l int, pp *EbpsParams) (*User, error) {
	fmt.Printf("GenAuxTag called with l=%d, len(signers)=%d, len(messages)=%d\n", l, len(signers), len(messages))

	if l <= 0 {
		fmt.Println("Error: l <= 0")
		return nil, errors.New("number of messages must be greater than 0")
	}

	if l > len(signers) {
		fmt.Println("Error: l > len(signers)")
		return nil, errors.New("number of messages must be less than or equal to number of signers")
	}

	if len(messages) != l {
		fmt.Println("Error: len(messages) != l")
		return nil, errors.New("number of messages must equal to l")
	}

	user := new(User)

	user.sk.gamma.SetRandom()
	user.sk.delta.SetRandom()

	var uGamma, uDelta bls.G1Affine
	uGamma.ScalarMultiplication(&pp.ua, user.sk.gamma.BigInt(new(big.Int)))
	uDelta.ScalarMultiplication(&pp.ua, user.sk.delta.BigInt(new(big.Int)))

	gammaBytes := uGamma.Bytes()
	deltaBytes := uDelta.Bytes()
	fmt.Printf("uGamma.Bytes length: %d\n", len(gammaBytes))
	fmt.Printf("uDelta.Bytes length: %d\n", len(deltaBytes))

	var aux bytes.Buffer

	user.ELgamal.esk.SetRandom()
	user.ELgamal.epk.ScalarMultiplication(&pp.ua, user.ELgamal.esk.BigInt(new(big.Int)))

	if _, err := aux.Write(gammaBytes[:]); err != nil {
		return nil, fmt.Errorf("failed to write uGamma: %v", err)
	}

	if _, err := aux.Write(deltaBytes[:]); err != nil {
		return nil, fmt.Errorf("failed to write uDelta: %v", err)
	}

	var cm []bls.G1Affine
	var o []fr.Element
	var h11 bls.G1Affine
	_, _, h11, _ = bls.Generators()

	for i := 0; i < l; i++ {
		var temp bls.G1Affine
		fmt.Printf("Starting iteration %d\n", i)
		cm[i].ScalarMultiplication(&pp.ua, user.ELgamal.esk.BigInt(new(big.Int)))
		o[i].SetRandom()
		cm[i].Add(&cm[i], temp.ScalarMultiplication(&h11, o[i].BigInt(new(big.Int))))

		msgLen := byte(len(messages[i]))
		if err := aux.WriteByte(msgLen); err != nil {
			return nil, fmt.Errorf("failed to write message length: %v", err)
		}
		fmt.Printf("messages[%d] length: %d\n", i, len(messages[i]))

		if _, err := aux.Write(messages[i]); err != nil {
			return nil, fmt.Errorf("failed to write message %d: %v", i, err)
		}

		lvk2Bytes := signers[i].lvk2.Bytes()
		fmt.Printf("signers[%d].lvk2.Bytes length: %d\n", i, len(lvk2Bytes))
		if len(lvk2Bytes) != bls.SizeOfG2AffineCompressed {
			return nil, fmt.Errorf("signers[%d].lvk2.Bytes has incorrect length: got %d, want %d", i, len(lvk2Bytes), bls.SizeOfG2AffineCompressed)
		}
		if _, err := aux.Write(lvk2Bytes[:]); err != nil {
			return nil, fmt.Errorf("failed to write lvk2[%d]: %v", i, err)
		}

		fmt.Printf("Completed iteration %d\n", i)
	}

	user.aux = aux.Bytes()
	fmt.Printf("Total aux.Bytes length: %d\n", len(user.aux))

	domain := []byte("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_")
	h, err := bls.HashToG1(user.aux, domain)
	if err != nil {
		return nil, fmt.Errorf("failed to hash aux: %v", err)
	}

	user.pk.hGamma.ScalarMultiplication(&h, user.sk.gamma.BigInt(new(big.Int)))
	user.pk.hDelta.ScalarMultiplication(&h, user.sk.delta.BigInt(new(big.Int)))

	return user, nil
}

func (u *User) ClearSecretKey() {
	u.sk.gamma.SetZero()
	u.sk.delta.SetZero()
}

func (u *User) parseAuxIfNeeded() error {
	if u.parsedAux.initialized {
		return nil
	}

	if len(u.aux) < 96 {
		return fmt.Errorf("invalid aux data: too short")
	}

	reader := bytes.NewReader(u.aux)
	if _, err := reader.Seek(96, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek: %v", err)
	}

	var messages [][]byte
	var pubKeys []bls.G2Affine
	var positions []int

	currentPos := 96

	for {
		positions = append(positions, currentPos)

		var msgLen [1]byte
		n, err := reader.Read(msgLen[:])
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("failed to read message length: %v", err)
		}
		if n != 1 {
			return fmt.Errorf("read incomplete message length")
		}

		currentPos++

		msg := make([]byte, msgLen[0])
		n, err = reader.Read(msg)
		if err != nil {
			return fmt.Errorf("failed to read message: %v", err)
		}
		if n != int(msgLen[0]) {
			return fmt.Errorf("read incomplete message")
		}

		messages = append(messages, msg)
		currentPos += int(msgLen[0])

		var lvkBytes [bls.SizeOfG2AffineCompressed]byte
		n, err = reader.Read(lvkBytes[:])
		if err != nil {
			return fmt.Errorf("failed to read verification key: %v", err)
		}
		if n != bls.SizeOfG2AffineCompressed {
			return fmt.Errorf("read incomplete verification key")
		}

		var lvk bls.G2Affine
		if _, err := lvk.SetBytes(lvkBytes[:]); err != nil {
			return fmt.Errorf("invalid verification key encoding: %v", err)
		}

		pubKeys = append(pubKeys, lvk)
		currentPos += bls.SizeOfG2AffineCompressed
	}

	u.parsedAux.messages = messages
	u.parsedAux.pubKeys = pubKeys
	u.parsedAux.positions = positions
	u.parsedAux.initialized = true

	return nil
}

func LongSign(signer *Signer, user *User, pp *EbpsParams, i int) (*User, error) {
	if signer == nil || pp == nil || user == nil {
		return nil, ErrNilParameters
	}

	auxData := user.aux
	if len(auxData) < 96 {
		return nil, fmt.Errorf("invalid aux data: too short")
	}

	msgPositions, err := createMessagePositions(auxData)
	if err != nil {
		return nil, err
	}

	if i >= len(msgPositions) {
		return nil, ErrInvalidIndex
	}

	msgPos := msgPositions[i]
	msgLen := int(auxData[msgPos])
	msg := auxData[msgPos+1 : msgPos+1+msgLen]
	pubKeyPos := msgPos + 1 + msgLen
	pubKeyBytes := auxData[pubKeyPos : pubKeyPos+bls.SizeOfG2AffineCompressed]

	var lvk bls.G2Affine
	if _, err := lvk.SetBytes(pubKeyBytes); err != nil {
		return nil, fmt.Errorf("invalid verification key encoding: %v", err)
	}

	if !lvk.Equal(&signer.lvk2) {
		return nil, ErrSignerMismatch
	}

	for len(user.longtermSigs) <= i {
		user.longtermSigs = append(user.longtermSigs, struct {
			h bls.G1Affine
			s []bls.G1Affine
		}{
			h: user.pk.hGamma,
			s: nil,
		})
	}

	if user.longtermSigs[i].s == nil {
		user.longtermSigs[i].s = make([]bls.G1Affine, 1)
	}

	m := new(fr.Element)
	m.SetBytes(msg)

	var exp fr.Element
	exp.Mul(&signer.lsk2, m).Add(&exp, &signer.lsk1)

	bigInt := getBigInt()
	defer putBigInt(bigInt)

	s := new(bls.G1Affine)
	s.ScalarMultiplication(&user.pk.hGamma, exp.BigInt(bigInt))
	user.longtermSigs[i].s[0] = *s

	return user, nil
}

func createMessagePositions(auxData []byte) ([]int, error) {
	var positions []int
	pos := 96

	for pos < len(auxData) {
		positions = append(positions, pos)

		if pos+1 >= len(auxData) {
			return nil, fmt.Errorf("invalid aux data format: truncated message length")
		}

		msgLen := int(auxData[pos])
		pos += 1 + msgLen

		if pos+bls.SizeOfG2AffineCompressed > len(auxData) {
			return nil, fmt.Errorf("invalid aux data format: truncated public key")
		}

		pos += bls.SizeOfG2AffineCompressed
	}

	return positions, nil
}
func EpochSign(signer *Signer, user *User, pp *EbpsParams, i int, j uint64) (*User, error) {

	if signer == nil || user == nil || pp == nil {
		return nil, fmt.Errorf("nil input parameters")
	}

	if len(user.longtermSigs) == 0 || len(user.longtermSigs[0].s) == 0 {
		return nil, fmt.Errorf("no longterm signatures found")
	}

	if user.epochSigs == nil {
		user.epochSigs = make([]bls.G1Affine, len(user.longtermSigs[0].s))
	}

	currentIndex := 0

	for currentIndex <= i {

		if currentIndex == i {

			jElement := new(fr.Element).SetUint64(j)
			exp := new(fr.Element).Mul(jElement, &signer.tsk)

			var sigma bls.G1Affine
			sigma.ScalarMultiplication(&user.pk.hDelta, exp.BigInt(new(big.Int)))

			user.epochSigs[i] = sigma
			return user, nil
		}

		currentIndex++
	}

	return nil, fmt.Errorf("index %d out of range", i)
}

func CombSig(j uint64, user *User, i int) (struct {
	h bls.G1Affine
	s bls.G1Affine
}, error) {
	if user == nil {
		return struct{ h, s bls.G1Affine }{}, fmt.Errorf("nil user")
	}

	if len(user.longtermSigs) == 0 || len(user.longtermSigs[0].s) <= i {
		return struct{ h, s bls.G1Affine }{}, fmt.Errorf("longterm signature not found for index %d", i)
	}

	if len(user.epochSigs) <= i {
		return struct{ h, s bls.G1Affine }{}, fmt.Errorf("epoch signature not found for index %d", i)
	}

	// σ_i,j = (h', s_i = s_{lt,i} · s_{ep,i,j})
	var combinedSig struct {
		h bls.G1Affine
		s bls.G1Affine
	}

	combinedSig.h = user.longtermSigs[0].h

	ltSig := user.longtermSigs[i].s[0]
	epSig := user.epochSigs[i]

	combinedSig.s.Add(&ltSig, &epSig)

	return combinedSig, nil
}

func Verify(j uint64, user *User, signer *Signer, i int, pp *EbpsParams) (bool, error) {
	if user == nil || signer == nil || pp == nil {
		return false, fmt.Errorf("nil input parameters")
	}

	if len(user.longtermSigs) == 0 || len(user.longtermSigs[0].s) <= i || len(user.epochSigs) <= i {
		return false, fmt.Errorf("signatures not found for index %d", i)
	}

	sig := struct {
		h bls.G1Affine
		s bls.G1Affine
	}{
		h: user.longtermSigs[0].h, // h^γ
		s: user.longtermSigs[i].s[0],
	}
	sig.s.Add(&sig.s, &user.epochSigs[i])

	if sig.h.IsInfinity() {
		return false, nil
	}

	reader := bytes.NewReader(user.aux)

	if _, err := reader.Seek(96, io.SeekStart); err != nil {
		return false, fmt.Errorf("failed to skip uGamma and uDelta: %v", err)
	}

	var currentIndex int
	var m1 []byte

	for currentIndex <= i {

		var msgLen [1]byte
		if _, err := reader.Read(msgLen[:]); err != nil {
			return false, fmt.Errorf("failed to read message length: %v", err)
		}

		m1 = make([]byte, msgLen[0])
		if _, err := reader.Read(m1); err != nil {
			return false, fmt.Errorf("failed to read message: %v", err)
		}

		var lvkBytes [bls.SizeOfG2AffineCompressed]byte
		if _, err := reader.Read(lvkBytes[:]); err != nil {
			return false, fmt.Errorf("failed to read verification key: %v", err)
		}

		if currentIndex == i {
			break
		}
		currentIndex++
	}

	m1Element := new(fr.Element).SetBytes(m1)

	var temp1 bls.G2Affine
	temp1.ScalarMultiplication(&signer.lvk2, m1Element.BigInt(new(big.Int)))
	temp1.Add(&temp1, &signer.lvk1)

	epochExp := new(fr.Element).SetUint64(j)

	var temp2 bls.G1Affine
	temp2.ScalarMultiplication(&user.pk.hDelta, epochExp.BigInt(new(big.Int)))

	// e(h', X_i · Y_i^{m_{1,i}}) · e((h^δ)^{F(m_2,j)}, Z_{i,j}) = e(s_i, v)
	g1Points := []bls.G1Affine{sig.h, temp2, sig.s}
	g2Points := []bls.G2Affine{temp1, signer.tvk, pp.va}
	g2Points[2].Neg(&g2Points[2])

	result, err := bls.PairingCheck(g1Points, g2Points)
	if err != nil {
		return false, fmt.Errorf("pairing check failed: %v", err)
	}

	return result, nil
}

func AggSigAttr(user *User) error {
	if user == nil || len(user.longtermSigs) == 0 {
		return fmt.Errorf("invalid user or empty signatures")
	}

	user.aggregatedLongSig.h = user.longtermSigs[0].h

	var accumulator bls.G1Affine
	accumulator = user.longtermSigs[0].s[0]
	for i := 1; i < len(user.longtermSigs[0].s); i++ {
		accumulator.Add(&accumulator, &user.longtermSigs[i].s[0])
	}

	user.aggregatedLongSig.s = accumulator

	return nil
}

func AggSigEp(user *User) error {
	if user == nil || len(user.epochSigs) == 0 {
		return fmt.Errorf("invalid user or empty epoch signatures")
	}

	var aggregated bls.G1Affine
	aggregated = user.epochSigs[0]
	for i := 1; i < len(user.epochSigs); i++ {
		aggregated.Add(&aggregated, &user.epochSigs[i])
	}

	user.aggregatedEpochSig = aggregated

	return nil
}

func CombAggSig(user *User) (struct {
	h bls.G1Affine
	s bls.G1Affine
}, error) {

	if user == nil {
		return struct{ h, s bls.G1Affine }{}, fmt.Errorf("nil user")
	}

	var combinedSig struct {
		h bls.G1Affine
		s bls.G1Affine
	}

	combinedSig.h = user.aggregatedLongSig.h

	combinedSig.s.Add(&user.aggregatedLongSig.s, &user.aggregatedEpochSig)

	return combinedSig, nil
}

func AggVerify(j uint64, user *User, signers []*Signer, pp *EbpsParams) (bool, error) {
	if user == nil || len(signers) == 0 || pp == nil {
		return false, fmt.Errorf("nil input parameters or no signers provided")
	}

	if user.aggregatedLongSig.h.IsInfinity() {
		return false, nil
	}

	msgs, err := extractMessagesFromAux(user.aux)
	if err != nil {
		return false, err
	}

	if len(msgs) > len(signers) {
		return false, fmt.Errorf("message count exceeds signer count")
	}

	temp := make([]bls.G2Affine, len(msgs))
	var wg sync.WaitGroup
	var mu sync.Mutex
	var computeErr error

	for i := 0; i < len(msgs); i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			if idx >= len(signers) {
				mu.Lock()
				computeErr = fmt.Errorf("signer index out of range")
				mu.Unlock()
				return
			}

			m := new(fr.Element).SetBytes(msgs[idx])
			var t bls.G2Affine
			t.ScalarMultiplication(&signers[idx].lvk2, m.BigInt(new(big.Int)))
			temp[idx].Add(&signers[idx].lvk1, &t)
		}(i)
	}

	wg.Wait()

	if computeErr != nil {
		return false, computeErr
	}

	var Z bls.G2Affine
	Z.Set(&signers[0].tvk)
	var temp1 bls.G2Affine
	temp1.Set(&temp[0])

	for i := 1; i < len(signers) && i < len(msgs); i++ {
		Z.Add(&Z, &signers[i].tvk)
		temp1.Add(&temp1, &temp[i])
	}

	epochExp := new(fr.Element).SetUint64(j) // F(m_2,j) = j
	var temp2 bls.G1Affine
	temp2.ScalarMultiplication(&user.pk.hDelta, epochExp.BigInt(new(big.Int)))

	var temp3 bls.G1Affine
	temp3.Add(&user.aggregatedLongSig.s, &user.aggregatedEpochSig)

	g1Points := []bls.G1Affine{
		user.aggregatedLongSig.h,
		temp2,
		temp3,
	}
	g2Points := []bls.G2Affine{
		temp1,
		Z,
		pp.va,
	}
	g2Points[2].Neg(&g2Points[2]) //

	result, err := bls.PairingCheck(g1Points, g2Points)
	return result, err
}

func extractMessagesFromAux(aux []byte) ([][]byte, error) {
	var msgs [][]byte
	reader := bytes.NewReader(aux)

	if _, err := reader.Seek(96, io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to skip hGamma and hDelta: %v", err)
	}

	for {
		var msgLen [1]byte
		if _, err := reader.Read(msgLen[:]); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("failed to read message length: %v", err)
		}

		msg := make([]byte, msgLen[0])
		if _, err := reader.Read(msg); err != nil {
			return nil, fmt.Errorf("failed to read message: %v", err)
		}
		msgs = append(msgs, msg)

		if _, err := reader.Seek(bls.SizeOfG2AffineCompressed, io.SeekCurrent); err != nil {
			return nil, fmt.Errorf("failed to skip verification key: %v", err)
		}
	}

	return msgs, nil
}

func convertToSignerPtrs(signers []Signer) []*Signer {
	signersPtrs := make([]*Signer, len(signers))
	for i := range signers {
		signersPtrs[i] = &signers[i]
	}
	return signersPtrs
}

func RndSigTag(user *User, r *fr.Element) (struct {
	h bls.G1Affine
	s bls.G1Affine
}, struct {
	hGamma bls.G1Affine
	hDelta bls.G1Affine
}, error) {

	if user == nil || r == nil {
		return struct{ h, s bls.G1Affine }{},
			struct{ hGamma, hDelta bls.G1Affine }{},
			fmt.Errorf("nil input parameters")
	}

	var rndSig struct {
		h bls.G1Affine
		s bls.G1Affine
	}
	rndSig.h.ScalarMultiplication(&user.aggregatedLongSig.h, r.BigInt(new(big.Int)))
	rndSig.s.ScalarMultiplication(&user.aggregatedLongSig.s, r.BigInt(new(big.Int)))

	var rndTag struct {
		hGamma bls.G1Affine
		hDelta bls.G1Affine
	}
	rndTag.hGamma.ScalarMultiplication(&user.pk.hGamma, r.BigInt(new(big.Int)))
	rndTag.hDelta.ScalarMultiplication(&user.pk.hDelta, r.BigInt(new(big.Int)))

	return rndSig, rndTag, nil
}
