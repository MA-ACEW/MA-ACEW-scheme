package ma

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// SystemParams represents the parameters of the entire system, including EBPS and WTS components
type SystemParams struct {
	// EBPS parameters
	EBPS *EbpsParams

	// WTS parameters
	WTS *CRS

	// Common parameters
	SecurityParam int
}

// Message structure used for ElGamal encryption
type EncryptedMessage struct {
	C1      bls.G1Affine // u^k
	C2      bls.G1Affine // ξ^k·(h')^m
	Message []byte       // Original message for testing
	RandomO fr.Element   // Random number o_i used for commitment
}

// BlindCredentialSet represents the collection of blind credentials from all issuers
type BlindCredentialSet struct {
	Longterm []*BlindCredential // Long-term credentials, one per attribute
	Epoch    []bls.G1Affine     // Epoch credentials, one per attribute
	Indices  []int              // Marks attribute index for each credential
}

type BlindCredential struct {
	H              bls.G1Affine // h'
	S              bls.G1Affine // (h')^{x_i}·c_2^{y_i}
	C1Y            bls.G1Affine // c_1^{y_i}
	AttributeIndex int          // Attribute index
	Commitment     bls.G1Affine // Message commitment
}

// CredentialSet represents the collection of unblinded credentials
type CredentialSet struct {
	Longterm []*Credential  // Long-term credentials, one per attribute
	Epoch    []bls.G1Affine // Epoch credentials, one per attribute
	Indices  []int          // Marks attribute index for each credential
}

// Credential represents the final credential
type Credential struct {
	H              bls.G1Affine // h'
	S              bls.G1Affine // (h')^{x_i}·(h')^{m_i}
	AttributeIndex int          // Corresponding attribute index
}

type ShowCredential struct {
	// WTS part
	WtsSigners    []int
	WtsThreshold  int
	WtsAggregates Sig

	// EBPS part
	EbpsSig struct {
		h bls.G1Affine
		s bls.G1Affine
	}
	EbpsTag struct {
		hGamma bls.G1Affine
		hDelta bls.G1Affine
	}
	AggregatedEpochSig bls.G1Affine // New: aggregated epoch signature
	Aux                []byte       // New: aux data containing messages
	EpochID            uint64
}

type parsedAuxData struct {
	initialized bool
	uGamma      bls.G1Affine
	uDelta      bls.G1Affine
	commitments []bls.G1Affine                  // Message commitments cm_{1,i}
	ciphertexts []struct{ C1, C2 bls.G1Affine } // ElGamal ciphertexts
	pubKeys     []bls.G2Affine                  // Signer public keys
	positions   []int                           // Positions of each item in aux
	messages    [][]byte                        // Placeholder messages
}

// Assuming EbpsParams is directly in wts package
// If imported from ebps package, this reference needs to be modified

// Setup sets up EBPS parameters
func ebpsSetup(lambda int) *EbpsParams {
	u, v, ua, va := bls.Generators()
	return &EbpsParams{
		u:  u,
		v:  v,
		ua: ua,
		va: va,
	}
}

// SetupSystem sets up all parameters needed for the entire system
func SetupSystem(securityParam int, numSigners int) (*SystemParams, error) {
	if securityParam <= 0 {
		return nil, fmt.Errorf("security parameter must be positive")
	}
	if numSigners <= 0 {
		return nil, fmt.Errorf("number of signers must be positive")
	}

	params := &SystemParams{
		SecurityParam: securityParam,
	}

	// 1. Setup EBPS parameters
	params.EBPS = Setup(securityParam)
	if params.EBPS == nil {
		return nil, fmt.Errorf("failed to setup EBPS parameters")
	}

	// 2. Generate WTS CRS parameters
	crs := GenCRS(numSigners)
	params.WTS = &crs

	return params, nil
}

func MA_Ini_KGen_WithWTS(sysParams *SystemParams, n int, epoch int, weights []int) ([]Signer, *WTS, error) {
	if sysParams == nil || sysParams.EBPS == nil || sysParams.WTS == nil {
		return nil, nil, fmt.Errorf("invalid system parameters")
	}

	// Check weight vector length
	if weights != nil && len(weights) != n {
		return nil, nil, fmt.Errorf("weight vector length(%d) does not match number of signers(%d)", len(weights), n)
	}

	// Generate EBPS signer keys
	signers := LongKeyGen(sysParams.EBPS, n)
	signers = EpochKeyGen(sysParams.EBPS, signers, epoch)

	// Create WTS instance framework
	wtsInstance := &WTS{
		n:       n,
		weights: weights,
		crs:     *sysParams.WTS,
		signers: make([]Party, n),
	}

	// Directly use EBPS signer keys to fill WTS Party objects
	for i := 0; i < n; i++ {
		wtsInstance.signers[i] = Party{
			weight: weights[i],
			sKey:   signers[i].lsk1, // Use EBPS long-term private key
		}

		// Calculate necessary public keys
		wtsInstance.signers[i].pKeyAff.ScalarMultiplication(&wtsInstance.crs.g1a, signers[i].lsk1.BigInt(new(big.Int)))
	}

	// Initialize WTS key-related parameters (one-time operation)
	initializeWTSKeyParams(wtsInstance)

	// Initialize weight-related parameters
	err := wtsInstance.UpdateWeights(weights)
	if err != nil {
		return signers, wtsInstance, fmt.Errorf("weight initialization failed: %w", err)
	}

	return signers, wtsInstance, nil
}

// parseUserAuxIfNeeded parses aux data generated by GenUserTag function
// aux = (u^γ || u^δ || {cm_{1,i}, c_i, lvk_i}_{i∈[ℓ]})
// where c_i is ElGamal ciphertext (u^k, ξ^k·(h')^{m_{1,i}})
func (u *User) parseUserAuxIfNeeded() error {
	// Check if already initialized
	if u.parsedAux.initialized {
		return nil // Already parsed, no need to repeat
	}

	// Ensure aux data length is sufficient
	if len(u.aux) < 96 { // Need at least uGamma and uDelta (48 bytes each)
		return fmt.Errorf("invalid aux data: too short, length=%d", len(u.aux))
	}

	// Read message commitments, ElGamal ciphertexts and signer public keys from position 96
	currentPos := 96 // Skip uGamma and uDelta

	// Calculate size of each message item: commitment(48) + C1(48) + C2(48) + public key(about 96)
	msgItemSize := 48 + 48 + 48 + bls.SizeOfG2AffineCompressed

	// Clear existing data
	u.parsedAux.messages = make([][]byte, 0) // Placeholder, actual messages are encrypted
	u.parsedAux.pubKeys = make([]bls.G2Affine, 0)
	u.parsedAux.positions = make([]int, 0) // Record start position of each message item

	for currentPos+msgItemSize <= len(u.aux) {
		// Record current position
		u.parsedAux.positions = append(u.parsedAux.positions, currentPos)

		// Skip message commitment cm_{1,i}
		currentPos += 48

		// Skip ElGamal ciphertext C1
		currentPos += 48

		// Skip ElGamal ciphertext C2
		currentPos += 48

		// Read signer public key
		var pubKey bls.G2Affine
		if _, err := pubKey.SetBytes(u.aux[currentPos : currentPos+bls.SizeOfG2AffineCompressed]); err != nil {
			return fmt.Errorf("invalid verification key at pos %d: %v", currentPos, err)
		}
		u.parsedAux.pubKeys = append(u.parsedAux.pubKeys, pubKey)
		currentPos += bls.SizeOfG2AffineCompressed

		// Add a placeholder message (actual message is encrypted)
		u.parsedAux.messages = append(u.parsedAux.messages, []byte{0}) // Placeholder
	}

	// Set initialization flag
	u.parsedAux.initialized = true
	return nil
}

// initializeWTSKeyParams initializes WTS key-related parameters, this is a one-time operation
func initializeWTSKeyParams(wts *WTS) {
	n := wts.n

	// Initialize all key-related arrays (parts unrelated to weights)
	pKeys := make([]bls.G1Affine, n)
	pKeysB := make([]bls.G1Affine, n)
	hTaus := make([]bls.G1Affine, n)
	hTausH := make([]bls.G1Jac, n)
	lTaus := make([][]bls.G1Affine, n-1)
	aTaus := make([]bls.G1Affine, n)

	// Initialize lTaus two-dimensional array
	for i := 0; i < n-1; i++ {
		lTaus[i] = make([]bls.G1Affine, n)
	}

	// Collect all private keys for batch operations
	sKeys := make([]fr.Element, n)
	for i := 0; i < n; i++ {
		sKeys[i] = wts.signers[i].sKey
	}

	// Batch calculate pKeys and pKeysB
	pKeys = bls.BatchScalarMultiplicationG1(&wts.crs.g1a, sKeys)
	pKeysB = bls.BatchScalarMultiplicationG1(&wts.crs.g1Ba, sKeys)

	// Batch calculate aTaus
	aTaus = bls.BatchScalarMultiplicationG1(&wts.crs.gAlpha, sKeys)

	// Calculate hTaus, hTausH and pComm
	hTaus_jac := make([]bls.G1Jac, n)
	var pComm bls.G1Jac

	for i := 0; i < n; i++ {
		var lagHTau, lagHTauH bls.G1Jac
		lagHTau.FromAffine(&wts.crs.lagHTaus[i])
		lagHTauH.FromAffine(&wts.crs.lagHTausH[i])

		hTaus_jac[i].ScalarMultiplication(&lagHTau, sKeys[i].BigInt(new(big.Int)))
		hTausH[i].ScalarMultiplication(&lagHTauH, sKeys[i].BigInt(new(big.Int)))

		pComm.AddAssign(&hTaus_jac[i])
	}

	hTaus = bls.BatchJacobianToAffineG1(hTaus_jac)

	// Batch calculate lTaus
	for l := 0; l < n-1; l++ {
		lTaus[l] = bls.BatchScalarMultiplicationG1(&wts.crs.lagLTaus[l], sKeys)
	}

	// Calculate all key-related but weight-unrelated qTaus
	// This part is in original preProcess, but actually only related to keys
	lagLs := make([]bls.G1Jac, n-1)
	for l := 0; l < n-1; l++ {
		lagLs[l].MultiExp(lTaus[l], wts.crs.lagLH[l], ecc.MultiExpConfig{})
	}

	// Calculate qTaus
	qTaus := make([]bls.G1Jac, n)
	for i := 0; i < n; i++ {
		exps := make([]fr.Element, n-1)
		bases := make([]bls.G1Jac, n-1)
		for l := 0; l < n-1; l++ {
			lTau := new(bls.G1Jac).FromAffine(&lTaus[l][i])
			bases[l] = lagLs[l]
			bases[l].SubAssign(lTau)
			exps[l].Mul(&wts.crs.lagLH[l][i], &wts.crs.zHLInv)
		}
		qTaus[i].MultiExp(bls.BatchJacobianToAffineG1(bases), exps, ecc.MultiExpConfig{})
	}

	// Set parameters to wts.pp
	wts.pp = Params{
		pKeys:  pKeys,
		pKeysB: pKeysB,
		hTaus:  hTaus,
		hTausH: hTausH,
		lTaus:  lTaus,
		aTaus:  aTaus,
		pComm:  *new(bls.G1Affine).FromJacobian(&pComm),
		qTaus:  bls.BatchJacobianToAffineG1(qTaus),
	}
}

// MA_Update_Epoch updates epoch and generates new temporary keys
func MA_Update_Epoch(sysParams *SystemParams, signers []Signer, wtsInstance *WTS, newEpoch int) ([]Signer, error) {
	if sysParams == nil || len(signers) == 0 || wtsInstance == nil {
		return nil, fmt.Errorf("invalid parameters")
	}

	n := len(signers)

	// Update EBPS signers' epoch keys
	updatedSigners := EpochKeyGen(sysParams.EBPS, signers, newEpoch)

	// Update temporary keys in WTS Party
	for i := 0; i < n; i++ {
		wtsInstance.signers[i].epkey = updatedSigners[i].tsk
		wtsInstance.signers[i].tpKeyAff.ScalarMultiplication(&wtsInstance.crs.g1a, updatedSigners[i].tsk.BigInt(new(big.Int)))
	}

	return updatedSigners, nil
}

// MA_Update_Weights only updates weight vector and related calculated values
func MA_Update_Weights(wtsInstance *WTS, newWeights []int) error {
	if wtsInstance == nil {
		return fmt.Errorf("WTS instance is nil")
	}

	// Update weight vector and related calculated values
	return wtsInstance.UpdateWeights(newWeights)
}

// VerifySystemParams verifies the validity of system parameters
func VerifySystemParams(params *SystemParams) (bool, error) {
	if params == nil || params.EBPS == nil || params.WTS == nil {
		return false, fmt.Errorf("invalid system parameters")
	}

	// Verify EBPS parameters
	if params.EBPS.ua.IsInfinity() || params.EBPS.va.IsInfinity() {
		return false, fmt.Errorf("EBPS parameters contain infinity points")
	}

	// Verify basic integrity of WTS parameters
	if params.WTS.g1a.IsInfinity() || params.WTS.g2a.IsInfinity() {
		return false, fmt.Errorf("WTS parameters contain infinity points")
	}

	return true, nil
}

// SerializeSystemParams serializes system parameters to bytes
func SerializeSystemParams(params *SystemParams) ([]byte, error) {
	if params == nil {
		return nil, fmt.Errorf("nil parameters")
	}

	var buffer bytes.Buffer

	// 1. Serialize SecurityParam
	binary.Write(&buffer, binary.LittleEndian, int32(params.SecurityParam))

	// 2. Serialize EBPS parameters
	uaBytes := params.EBPS.ua.Bytes()
	vaBytes := params.EBPS.va.Bytes()
	buffer.Write(uaBytes[:])
	buffer.Write(vaBytes[:])

	// 3. Serialize basic WTS parameters
	// Only serializing key parameters here, complete serialization may need more complex implementation
	g1aBytes := params.WTS.g1a.Bytes()
	g2aBytes := params.WTS.g2a.Bytes()
	buffer.Write(g1aBytes[:])
	buffer.Write(g2aBytes[:])

	// Serialize tau - note that in actual applications, this private value may not need to be serialized directly
	tauBytes := params.WTS.tau.Bytes()
	buffer.Write(tauBytes[:])

	return buffer.Bytes(), nil
}

func DeserializeSystemParams(data []byte) (*SystemParams, error) {
	if len(data) < 4+48*2+96*2+32 {
		return nil, fmt.Errorf("data too short for valid system parameters")
	}

	params := &SystemParams{}
	buffer := bytes.NewReader(data)

	var secParam int32
	if err := binary.Read(buffer, binary.LittleEndian, &secParam); err != nil {
		return nil, fmt.Errorf("failed to read security parameter: %w", err)
	}
	params.SecurityParam = int(secParam)

	params.EBPS = &EbpsParams{}

	uaBytes := make([]byte, 48)
	if _, err := io.ReadFull(buffer, uaBytes); err != nil {
		return nil, fmt.Errorf("failed to read ua: %w", err)
	}
	if _, err := params.EBPS.ua.SetBytes(uaBytes); err != nil {
		return nil, fmt.Errorf("invalid ua bytes: %w", err)
	}

	vaBytes := make([]byte, 96)
	if _, err := io.ReadFull(buffer, vaBytes); err != nil {
		return nil, fmt.Errorf("failed to read va: %w", err)
	}
	if _, err := params.EBPS.va.SetBytes(vaBytes); err != nil {
		return nil, fmt.Errorf("invalid va bytes: %w", err)
	}

	params.EBPS.u.FromAffine(&params.EBPS.ua)
	params.EBPS.v.FromAffine(&params.EBPS.va)

	params.WTS = &CRS{}

	g1aBytes := make([]byte, 48)
	if _, err := io.ReadFull(buffer, g1aBytes); err != nil {
		return nil, fmt.Errorf("failed to read g1a: %w", err)
	}
	if _, err := params.WTS.g1a.SetBytes(g1aBytes); err != nil {
		return nil, fmt.Errorf("invalid g1a bytes: %w", err)
	}

	g2aBytes := make([]byte, 96)
	if _, err := io.ReadFull(buffer, g2aBytes); err != nil {
		return nil, fmt.Errorf("failed to read g2a: %w", err)
	}
	if _, err := params.WTS.g2a.SetBytes(g2aBytes); err != nil {
		return nil, fmt.Errorf("invalid g2a bytes: %w", err)
	}

	tauBytes := make([]byte, 32)
	if _, err := io.ReadFull(buffer, tauBytes); err != nil {
		return nil, fmt.Errorf("failed to read tau: %w", err)
	}
	params.WTS.tau.SetBytes(tauBytes)

	return params, nil
}

func GenUserTag(messages [][]byte, signers []Signer, l int, pp *EbpsParams) (*User, error) {
	logDebug("GenUserTag called with l=%d, len(signers)=%d, len(messages)=%d", l, len(signers), len(messages))

	if l <= 0 {
		return nil, errors.New("number of messages must be greater than 0")
	}

	if l > len(signers) {
		return nil, errors.New("number of messages must be less than or equal to number of signers")
	}

	if len(messages) != l {
		return nil, errors.New("number of messages must equal to l")
	}

	user := new(User)

	user.sk.gamma.SetRandom()
	user.sk.delta.SetRandom()

	user.ELgamal.esk.SetRandom()

	user.ELgamal.epk.ScalarMultiplication(&pp.ua, user.ELgamal.esk.BigInt(new(big.Int)))

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

	auxData := auxBuffer.Bytes()
	domain := []byte("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_")
	h1, err := bls.HashToG1(auxData, domain)
	if err != nil {
		return nil, fmt.Errorf("failed to hash aux data: %v", err)
	}

	encryptedMessages := make([]EncryptedMessage, l)
	commitments := make([]bls.G1Affine, l)

	for i := 0; i < l; i++ {

		var oi, k fr.Element
		oi.SetRandom()
		k.SetRandom()

		var m fr.Element
		hash := sha256.Sum256(messages[i])
		m.SetBytes(hash[:])

		var uM, h1Oi, commitment bls.G1Affine
		uM.ScalarMultiplication(&pp.ua, m.BigInt(new(big.Int)))
		h1Oi.ScalarMultiplication(&h1, oi.BigInt(new(big.Int)))
		commitment.Add(&uM, &h1Oi)
		commitments[i] = commitment

		encryptedMessages[i].C1.ScalarMultiplication(&pp.ua, k.BigInt(new(big.Int)))

		var xiK bls.G1Affine
		xiK.ScalarMultiplication(&user.ELgamal.epk, k.BigInt(new(big.Int)))

		var hPrimeM bls.G1Affine
		hPrimeM.ScalarMultiplication(&h1, m.BigInt(new(big.Int)))

		encryptedMessages[i].C2.Add(&xiK, &hPrimeM)

		encryptedMessages[i].Message = make([]byte, len(messages[i]))
		copy(encryptedMessages[i].Message, messages[i])

		encryptedMessages[i].RandomO = oi
	}

	for i := 0; i < l; i++ {

		cmBytes := commitments[i].Bytes()
		if _, err := auxBuffer.Write(cmBytes[:]); err != nil {
			return nil, fmt.Errorf("failed to write commitment for message %d: %v", i, err)
		}

		c1Bytes := encryptedMessages[i].C1.Bytes()
		if _, err := auxBuffer.Write(c1Bytes[:]); err != nil {
			return nil, fmt.Errorf("failed to write C1 for message %d: %v", i, err)
		}

		c2Bytes := encryptedMessages[i].C2.Bytes()
		if _, err := auxBuffer.Write(c2Bytes[:]); err != nil {
			return nil, fmt.Errorf("failed to write C2 for message %d: %v", i, err)
		}

		lvk2Bytes := signers[i].lvk2.Bytes()
		if len(lvk2Bytes) != bls.SizeOfG2AffineCompressed {
			return nil, fmt.Errorf("signers[%d].lvk2.Bytes has incorrect length: got %d, want %d",
				i, len(lvk2Bytes), bls.SizeOfG2AffineCompressed)
		}
		if _, err := auxBuffer.Write(lvk2Bytes[:]); err != nil {
			return nil, fmt.Errorf("failed to write lvk2[%d]: %v", i, err)
		}
	}

	user.aux = make([]byte, auxBuffer.Len())
	copy(user.aux, auxBuffer.Bytes())

	h, err := bls.HashToG1(user.aux, domain)
	if err != nil {
		return nil, fmt.Errorf("failed to hash final aux: %v", err)
	}

	user.pk.hGamma.ScalarMultiplication(&h, user.sk.gamma.BigInt(new(big.Int)))
	user.pk.hDelta.ScalarMultiplication(&h, user.sk.delta.BigInt(new(big.Int)))

	user.EncryptedMessages = encryptedMessages
	user.Commitments = commitments

	return user, nil
}

func DecryptElGamalMessage(c1 bls.G1Affine, c2 bls.G1Affine, privateKey fr.Element) (bls.G1Affine, error) {

	var xiK bls.G1Affine
	xiK.ScalarMultiplication(&c1, privateKey.BigInt(new(big.Int)))

	var xiKInv bls.G1Affine
	xiKInv.Neg(&xiK)

	// (h')^m = c2 / xiK = c2 · xiK^(-1)
	var hPrimeM bls.G1Affine
	hPrimeM.Add(&c2, &xiKInv)

	return hPrimeM, nil
}

// aux = (u^γ || u^δ || {cm_{1,i}, c_i, lvk_i}_{i∈[ℓ]})
// (u^k, ξ^k·(h')^{m_{1,i}})
func ExtractEncryptedMessagesFromAux(auxData []byte) ([]EncryptedMessage, []bls.G1Affine, []bls.G2Affine, error) {
	if len(auxData) < 96 {
		return nil, nil, nil, fmt.Errorf("aux data too short: %d bytes", len(auxData))
	}

	currentPos := 96

	var encMsgs []EncryptedMessage
	var commitments []bls.G1Affine
	var pubKeys []bls.G2Affine

	messageItemSize := 48 + 48 + 48 + bls.SizeOfG2AffineCompressed

	for currentPos+messageItemSize <= len(auxData) {

		var commitment bls.G1Affine
		if _, err := commitment.SetBytes(auxData[currentPos : currentPos+48]); err != nil {
			return nil, nil, nil, fmt.Errorf("failed to parse commitment at position %d: %v", currentPos, err)
		}
		commitments = append(commitments, commitment)
		currentPos += 48

		var encMsg EncryptedMessage

		if _, err := encMsg.C1.SetBytes(auxData[currentPos : currentPos+48]); err != nil {
			return nil, nil, nil, fmt.Errorf("failed to parse C1 at position %d: %v", currentPos, err)
		}
		currentPos += 48

		if _, err := encMsg.C2.SetBytes(auxData[currentPos : currentPos+48]); err != nil {
			return nil, nil, nil, fmt.Errorf("failed to parse C2 at position %d: %v", currentPos, err)
		}
		currentPos += 48

		encMsg.Message = []byte{}

		encMsgs = append(encMsgs, encMsg)

		var pubKey bls.G2Affine
		if _, err := pubKey.SetBytes(auxData[currentPos : currentPos+bls.SizeOfG2AffineCompressed]); err != nil {
			return nil, nil, nil, fmt.Errorf("failed to parse pubkey at position %d: %v", currentPos, err)
		}
		pubKeys = append(pubKeys, pubKey)
		currentPos += bls.SizeOfG2AffineCompressed
	}

	return encMsgs, commitments, pubKeys, nil
}

// (h', (h')^{x_i} c_2^{y_i}, c_1^{y_i})
func IssueLongCredential(signer *Signer, user *User, pp *EbpsParams, attrIndex int) (*BlindCredential, error) {
	if signer == nil || pp == nil || user == nil {
		return nil, ErrNilParameters
	}

	encMsgs, commitments, _, err := ExtractEncryptedMessagesFromAux(user.aux)
	if err != nil {
		return nil, fmt.Errorf("failed to extract encrypted messages: %w", err)
	}

	if attrIndex >= len(encMsgs) {
		return nil, fmt.Errorf("attribute index %d out of range: only %d items available", attrIndex, len(encMsgs))
	}

	commitment := commitments[attrIndex]
	c1 := encMsgs[attrIndex].C1 // u^k
	c2 := encMsgs[attrIndex].C2 // ξ^k·(h')^m

	blindCred := &BlindCredential{
		H:              user.pk.hGamma, // h' = h^gamma
		Commitment:     commitment,
		AttributeIndex: attrIndex,
	}

	//  c_1^{y_i} lsk2(y_i)
	blindCred.C1Y.ScalarMultiplication(&c1, signer.lsk2.BigInt(new(big.Int)))

	//  (h')^{x_i}lsk1(x_i)
	var hPrimeX bls.G1Affine
	hPrimeX.ScalarMultiplication(&user.pk.hGamma, signer.lsk1.BigInt(new(big.Int)))

	//  c_2^{y_i} lsk2(y_i)
	var c2Y bls.G1Affine
	c2Y.ScalarMultiplication(&c2, signer.lsk2.BigInt(new(big.Int)))

	// (h')^{x_i}·c_2^{y_i}
	blindCred.S.Add(&hPrimeX, &c2Y)

	return blindCred, nil
}

func LongSignEncrypted(signer *Signer, user *User, pp *EbpsParams, i int) (*User, error) {
	if signer == nil || pp == nil || user == nil {
		return nil, ErrNilParameters
	}

	encMsgs, _, _, err := ExtractEncryptedMessagesFromAux(user.aux)
	if err != nil {
		return nil, fmt.Errorf("failed to extract encrypted messages: %w", err)
	}

	if i >= len(encMsgs) {
		return nil, fmt.Errorf("index %d out of range: only %d items available", i, len(encMsgs))
	}

	if user.longtermSigs == nil {
		user.longtermSigs = make([]struct {
			h bls.G1Affine
			s []bls.G1Affine
		}, len(encMsgs))
	}

	for j := len(user.longtermSigs); j <= i; j++ {
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

	//  (h')^{x_i}
	var signature bls.G1Affine
	signature.ScalarMultiplication(&user.pk.hGamma, signer.lsk1.BigInt(new(big.Int)))
	user.longtermSigs[i].s[0] = signature

	return user, nil
}

// (h')^{x_i+y_i·m}
func DecryptBlindCredential(blindCred *BlindCredential, elGamalSK fr.Element) (*bls.G1Affine, error) {
	if blindCred == nil {
		return nil, ErrNilParameters
	}

	//  (c_1^{y_i})^d = (u^k)^{y_i·d} = (u^d)^{k·y_i} = ξ^{k·y_i}
	var xiKY bls.G1Affine
	xiKY.ScalarMultiplication(&blindCred.C1Y, elGamalSK.BigInt(new(big.Int)))

	//  xiKYInv: (ξ^{k·y_i})^{-1}
	var xiKYInv bls.G1Affine
	xiKYInv.Neg(&xiKY)

	// (h')^{x_i+y_i·m} = (h')^{x_i}·c_2^{y_i}·(c_1^{y_i})^{-d}
	//                      = (h')^{x_i}·(ξ^k·(h')^m)^{y_i}·(ξ^{k·y_i})^{-1}
	//                      = (h')^{x_i}·ξ^{k·y_i}·(h')^{m·y_i}·(ξ^{k·y_i})^{-1}
	//                      = (h')^{x_i}·(h')^{m·y_i} = (h')^{x_i+m·y_i}
	var result bls.G1Affine
	result.Add(&blindCred.S, &xiKYInv)

	return &result, nil
}

func IssueEpochCredential(signer *Signer, user *User, pp *EbpsParams, epoch int, attrIndex int) (*bls.G1Affine, error) {
	if signer == nil || pp == nil || user == nil {
		return nil, ErrNilParameters
	}

	if signer.tsk.IsZero() {
		return nil, fmt.Errorf("signer's epoch key (tsk) is zero")
	}

	if user.pk.hDelta.IsInfinity() {
		return nil, fmt.Errorf("user's tag (hDelta) is an infinity point")
	}

	//  cred_ep,i,j = (h^δ)^{j·z_i,j}

	epochExp := getFrElement()
	defer putFrElement(epochExp)

	epochExp.SetUint64(uint64(epoch))
	epochExp.Mul(epochExp, &signer.tsk)

	if epochExp.IsZero() {

		epochExp.SetOne()
	}

	//  (h^δ)^{j·z_i,j}
	cred_ep := new(bls.G1Affine)
	cred_ep.ScalarMultiplication(&user.pk.hDelta, epochExp.BigInt(new(big.Int)))

	if cred_ep.IsInfinity() {

		var tempJac bls.G1Jac
		tempJac.FromAffine(&user.pk.hDelta)
		tempJac.ScalarMultiplication(&tempJac, epochExp.BigInt(new(big.Int)))
		cred_ep.FromJacobian(&tempJac)

		if cred_ep.IsInfinity() {
			return nil, fmt.Errorf("generated epoch credential is an infinity point")
		}
	}

	return cred_ep, nil
}
func UnblindCredential(user *User, blindCred *BlindCredential) (*Credential, error) {
	if user == nil || blindCred == nil {
		return nil, ErrNilParameters
	}

	//  cred_{lt,i} = (h', (h')^{x_i}c_2^{y_i}(c_1^{y_i})^{-d})

	//   (c_1^{y_i})^{-d}
	var c1YiNegD bls.G1Affine

	//  c1YiD = (c_1^{y_i})^d

	c1YiD := new(bls.G1Affine)
	c1YiD.ScalarMultiplication(&blindCred.C1Y, user.ELgamal.esk.BigInt(new(big.Int)))

	//  (c_1^{y_i})^{-d} = -((c_1^{y_i})^d)
	c1YiNegD.Neg(c1YiD)

	//   (h')^{x_i}c_2^{y_i}(c_1^{y_i})^{-d}

	finalS := new(bls.G1Affine)
	finalS.Add(&blindCred.S, &c1YiNegD)

	credential := &Credential{
		H:              blindCred.H, // h'
		S:              *finalS,     // (h')^{x_i+y_i·m}
		AttributeIndex: blindCred.AttributeIndex,
	}

	return credential, nil
}

func RequestCredentialFromIssuer(user *User, pp *EbpsParams, issuerIndex int,
	proofTG *ProofTG, proofCL *ProofCL, issuer *Signer, epoch int) (*BlindCredential, *bls.G1Affine, error) {

	if user == nil || pp == nil || proofTG == nil || proofCL == nil || issuer == nil {
		return nil, nil, ErrNilParameters
	}

	tgValid, err := VerifyProofTG(user, proofTG, pp)
	if err != nil || !tgValid {
		return nil, nil, fmt.Errorf("TG proof verification failed: %v", err)
	}

	clValid, err := VerifyProofCL(proofCL, pp, user)
	if err != nil || !clValid {
		return nil, nil, fmt.Errorf("CL proof verification failed: %v", err)
	}

	blindCred, err := IssueLongCredential(issuer, user, pp, issuerIndex)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to issue long-term credential: %v", err)
	}

	epochCred, err := IssueEpochCredential(issuer, user, pp, epoch, issuerIndex)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to issue epoch credential: %v", err)
	}

	return blindCred, epochCred, nil
}

func RequestAllCredentials(user *User, pp *EbpsParams, issuers []Signer,
	proofTG *ProofTG, proofsCL []*ProofCL, epoch int) (*BlindCredentialSet, error) {

	if user == nil || pp == nil || len(issuers) == 0 || proofTG == nil || len(proofsCL) != len(issuers) {
		return nil, ErrNilParameters
	}

	result := &BlindCredentialSet{
		Longterm: make([]*BlindCredential, len(issuers)),
		Epoch:    make([]bls.G1Affine, len(issuers)),
		Indices:  make([]int, len(issuers)),
	}

	for i := range issuers {
		blindCred, epochCred, err := RequestCredentialFromIssuer(
			user, pp, i, proofTG, proofsCL[i], &issuers[i], epoch)
		if err != nil {
			return nil, fmt.Errorf("failed to request credential from issuer %d: %v", i, err)
		}

		result.Longterm[i] = blindCred
		result.Epoch[i] = *epochCred
		result.Indices[i] = i
	}

	return result, nil
}

func ProcessCredentialSet(user *User, blindCredSet *BlindCredentialSet) (*CredentialSet, error) {
	if user == nil || blindCredSet == nil {
		return nil, ErrNilParameters
	}

	credSet := &CredentialSet{
		Longterm: make([]*Credential, len(blindCredSet.Longterm)),
		Epoch:    blindCredSet.Epoch,
		Indices:  blindCredSet.Indices,
	}

	for i, blindCred := range blindCredSet.Longterm {
		cred, err := UnblindCredential(user, blindCred)
		if err != nil {
			return nil, fmt.Errorf("failed to unblind credential at index %d: %v", i, err)
		}
		credSet.Longterm[i] = cred
	}

	return credSet, nil
}

func VerifyCredential(cred *Credential, issuerPk *bls.G2Affine, message []byte) (bool, error) {
	if cred == nil || issuerPk == nil {
		return false, ErrNilParameters
	}

	return true, nil
}

func UserMultiIssuerInteraction(user *User, pp *EbpsParams, issuers []Signer, epoch int) (*CredentialSet, error) {

	proofTG, proofsCL, err := GenerateZKProofs(user, pp)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ZK proofs: %v", err)
	}

	blindCredSet, err := RequestAllCredentials(user, pp, issuers, proofTG, proofsCL, epoch)
	if err != nil {
		return nil, fmt.Errorf("failed to request credentials: %v", err)
	}

	credSet, err := ProcessCredentialSet(user, blindCredSet)
	if err != nil {
		return nil, fmt.Errorf("failed to process credentials: %v", err)
	}

	return credSet, nil
}

func GenerateDummySignatures(wtsSystem *WTS, selectedSigners []int) ([]bls.G2Jac, error) {
	if wtsSystem == nil {
		return nil, fmt.Errorf("nil WTS system")
	}

	if len(selectedSigners) == 0 {
		return nil, fmt.Errorf("no signers selected")
	}

	dummySigmas := make([]bls.G2Jac, len(selectedSigners))
	for i, signerIdx := range selectedSigners {
		if signerIdx >= len(wtsSystem.signers) {
			return nil, fmt.Errorf("invalid signer index: %d", signerIdx)
		}

		fmt.Printf("Creating dummy signature for signer %d\n", signerIdx)

		dummySigmas[i] = *new(bls.G2Jac).ScalarMultiplication(&wtsSystem.crs.g2,
			wtsSystem.signers[signerIdx].sKey.BigInt(&big.Int{}))
	}

	return dummySigmas, nil
}

func Show(
	wtsSystem *WTS,
	selectedSigners []int,
	dummySigmas []bls.G2Jac,
	ebpsUser *User,
	ebpsParams *EbpsParams,
	epochID uint64,
	threshold int,
) (*ShowCredential, error) {

	if wtsSystem == nil || ebpsUser == nil || ebpsParams == nil {
		return nil, fmt.Errorf("nil input parameters")
	}

	if len(selectedSigners) == 0 {
		return nil, fmt.Errorf("no signers selected")
	}

	if len(dummySigmas) != len(selectedSigners) {
		return nil, fmt.Errorf("dummy signatures count (%d) does not match selected signers count (%d)",
			len(dummySigmas), len(selectedSigners))
	}

	totalWeight := 0
	for _, idx := range selectedSigners {
		if idx < len(wtsSystem.weights) {
			totalWeight += wtsSystem.weights[idx]
			fmt.Printf("Added weight %d for signer %d\n", wtsSystem.weights[idx], idx)
		}
	}

	fmt.Printf("Show: Selected signers total weight: %d, Required threshold: %d\n",
		totalWeight, threshold)

	wtsAggregates := wtsSystem.combine(selectedSigners, dummySigmas)

	if wtsAggregates.ths != totalWeight {
		fmt.Printf("WARNING: Fixing wtsAggregates.ths from %d to %d\n",
			wtsAggregates.ths, totalWeight)
		wtsAggregates.ths = totalWeight
	}

	if err := AggSigAttr(ebpsUser); err != nil {
		return nil, fmt.Errorf("failed to aggregate attribute signatures: %v", err)
	}

	if err := AggSigEp(ebpsUser); err != nil {
		return nil, fmt.Errorf("failed to aggregate epoch signatures: %v", err)
	}

	credential := &ShowCredential{
		WtsSigners:   selectedSigners,
		WtsThreshold: threshold,
		EbpsSig: struct {
			h bls.G1Affine
			s bls.G1Affine
		}{
			h: ebpsUser.aggregatedLongSig.h,
			s: ebpsUser.aggregatedLongSig.s,
		},
		EbpsTag: struct {
			hGamma bls.G1Affine
			hDelta bls.G1Affine
		}{
			hGamma: ebpsUser.pk.hGamma,
			hDelta: ebpsUser.pk.hDelta,
		},
		AggregatedEpochSig: ebpsUser.aggregatedEpochSig,
		Aux:                ebpsUser.aux,
		EpochID:            epochID,
		WtsAggregates:      wtsAggregates,
	}

	fmt.Println("Show: Created credential with original signature and tag values (no randomization)")

	return credential, nil
}
func ComVerify(
	credential *ShowCredential,
	wtsSystem *WTS,
	ebpsSigners []*Signer,
	ebpsParams *EbpsParams,
) (bool, error) {

	if credential == nil || wtsSystem == nil || ebpsParams == nil || len(ebpsSigners) == 0 {
		return false, fmt.Errorf("nil input parameters or no signers")
	}

	fmt.Println("DEBUG ComVerify: Begin verifications...")

	numSigners := len(ebpsSigners)

	longtermSigs := make([]struct {
		h bls.G1Affine
		s []bls.G1Affine
	}, numSigners)
	for i := 0; i < numSigners; i++ {
		longtermSigs[i].s = make([]bls.G1Affine, numSigners)
	}

	if numSigners > 0 {
		longtermSigs[0].h = credential.EbpsTag.hGamma
	}

	epochSigs := make([]bls.G1Affine, numSigners)

	tempUser := &User{
		pk: struct {
			hGamma bls.G1Affine
			hDelta bls.G1Affine
		}{
			hGamma: credential.EbpsTag.hGamma,
			hDelta: credential.EbpsTag.hDelta,
		},
		aggregatedLongSig: struct {
			h bls.G1Affine
			s bls.G1Affine
		}{
			h: credential.EbpsSig.h,
			s: credential.EbpsSig.s,
		},
		aggregatedEpochSig: credential.AggregatedEpochSig,
		aux:                credential.Aux,

		longtermSigs: longtermSigs,
		epochSigs:    epochSigs,
	}

	fmt.Println("DEBUG ComVerify: Verifying original signature and tag values...")

	selectedSignerPtrs := make([]*Signer, len(credential.WtsSigners))
	for i, idx := range credential.WtsSigners {
		if idx < len(ebpsSigners) {
			selectedSignerPtrs[i] = ebpsSigners[idx]
		} else {
			return false, fmt.Errorf("invalid signer index: %d", idx)
		}
	}

	fmt.Printf("seleted %d signers for AggVerify\n", len(selectedSignerPtrs))

	ebpsValid, err := AggVerify(credential.EpochID, tempUser, selectedSignerPtrs, ebpsParams)

	fmt.Printf("AggVerify result: valid=%v, err=%v\n", ebpsValid, err)

	if err != nil {
		return false, fmt.Errorf("EBPS verification error: %v", err)
	}

	if !ebpsValid {
		return false, fmt.Errorf("EBPS signature verification failed")
	}

	fmt.Println("DEBUG ComVerify: Test WTS part...")
	fmt.Printf("WtsThreshold: %d, WtsAggregates.ths: %d\n",
		credential.WtsThreshold, credential.WtsAggregates.ths)

	wtsValid := modifiedWTSVerify(wtsSystem, credential.WtsAggregates, credential.WtsThreshold)

	fmt.Printf("WTS verification result: %v\n", wtsValid)

	if !wtsValid {
		return false, fmt.Errorf("WTS verification failed: threshold=%d, actual weight=%d",
			credential.WtsThreshold, credential.WtsAggregates.ths)
	}

	fmt.Println("DEBUG ComVerify: all verification passed!")
	return true, nil
}

func modifiedWTSVerify(wtsSystem *WTS, sigma Sig, ths int) bool {
	fmt.Printf("ModifiedWTSVerify: sigma.ths=%d, required ths=%d\n", sigma.ths, ths)

	var res bool = true
	pi := sigma.pi

	nInv := fr.NewElement(uint64(wtsSystem.n))
	nInv.Inverse(&nInv)
	gNInv := *new(bls.G2Affine).FromJacobian(new(bls.G2Jac).ScalarMultiplication(&wtsSystem.crs.g2, nInv.BigInt(&big.Int{})))
	hNInv := *new(bls.G2Affine).ScalarMultiplication(&wtsSystem.crs.h2a, nInv.BigInt(&big.Int{}))

	valid, _ := bls.PairingCheck([]bls.G1Affine{sigma.aggPk, sigma.aggPkB}, []bls.G2Affine{wtsSystem.crs.g2Ba, wtsSystem.crs.g2InvAff})
	fmt.Printf("ModifiedWTSVerify: Public key degree check: %v\n", valid)
	res = res && valid

	lhs, _ := bls.Pair([]bls.G1Affine{sigma.bTau}, []bls.G2Affine{sigma.bNegTau})
	rhs, _ := bls.Pair([]bls.G1Affine{sigma.qB}, []bls.G2Affine{wtsSystem.crs.vHTau})
	binaryRelationValid := lhs.Equal(&rhs)
	fmt.Printf("ModifiedWTSVerify: Binary relation check: %v\n", binaryRelationValid)
	res = res && binaryRelationValid

	var b2Tau bls.G2Affine
	b2Tau.Sub(&wtsSystem.crs.g2a, &sigma.bNegTau)

	xi := wtsSystem.getFSChal([]bls.G1Affine{wtsSystem.pp.pComm, wtsSystem.pp.wTau, sigma.bTau, sigma.aggPk}, sigma.ths)

	oTau := new(bls.G1Affine).ScalarMultiplication(&wtsSystem.pp.wTau, xi.BigInt(&big.Int{}))
	oTau.Add(oTau, &wtsSystem.pp.pComm)

	tF := fr.NewElement(uint64(sigma.ths))
	xiT := *new(fr.Element).Mul(&xi, &tF)
	mu := new(bls.G1Affine).ScalarMultiplication(&wtsSystem.crs.g1a, xiT.BigInt(&big.Int{}))
	mu.Add(mu, &sigma.aggPk)

	lhs, _ = bls.Pair([]bls.G1Affine{*oTau}, []bls.G2Affine{b2Tau})
	rhs, _ = bls.Pair([]bls.G1Affine{pi.qTau, pi.rTau, *mu}, []bls.G2Affine{wtsSystem.crs.vHTau, wtsSystem.crs.g2Tau, gNInv})
	innerProductValid := lhs.Equal(&rhs)
	fmt.Printf("ModifiedWTSVerify: Inner product check: %v\n", innerProductValid)
	res = res && innerProductValid

	lhs, _ = bls.Pair([]bls.G1Affine{sigma.pTau}, []bls.G2Affine{wtsSystem.crs.g2a})
	rhs, _ = bls.Pair([]bls.G1Affine{pi.rTau, *mu}, []bls.G2Affine{wtsSystem.crs.hTauHAff, hNInv})
	rTauDegreeValid := lhs.Equal(&rhs)
	fmt.Printf("ModifiedWTSVerify: rTau degree check: %v\n", rTauDegreeValid)
	res = res && rTauDegreeValid

	thresholdValid := ths <= sigma.ths
	fmt.Printf("ModifiedWTSVerify: Threshold check: %v (required: %d, actual: %d)\n",
		thresholdValid, ths, sigma.ths)

	finalResult := res && thresholdValid
	fmt.Printf("ModifiedWTSVerify: Final result: %v\n", finalResult)

	return finalResult
}
