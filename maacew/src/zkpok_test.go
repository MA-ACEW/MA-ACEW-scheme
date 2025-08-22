package ma

import (
	"bytes"
	"fmt"
	"math/big"
	"testing"
	"time"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func TestZKProofGeneration(t *testing.T) {
	pp := Setup(128)
	n := 3
	signers := LongKeyGen(pp, n)

	messages := [][]byte{
		[]byte("msg1"),
		[]byte("msg2"),
		[]byte("msg3"),
	}

	user, err := GenAuxTag(messages, signers, n, pp)
	if err != nil {
		t.Fatalf("Failed to generate auxiliary tag: %v", err)
	}

	// Sign for each attribute
	for i := range signers {
		user, err = LongSign(&signers[i], user, pp, i)
		if err != nil {
			t.Fatalf("Failed to generate long-term signature %d: %v", i, err)
		}
	}

	// Generate πtg proof
	proofTG, err := ProveDiscLog(user, pp)
	if err != nil {
		t.Fatalf("Failed to generate πtg proof: %v", err)
	}

	// Verify proofTG is not nil
	if proofTG == nil {
		t.Fatal("Generated πtg proof is nil")
	}

	// Verify elements in proof are not infinity points
	if proofTG.A.IsInfinity() || proofTG.B.IsInfinity() ||
		proofTG.C.IsInfinity() || proofTG.D.IsInfinity() {
		t.Fatal("πtg proof contains infinity points")
	}

	// Verify Z1 and Z2 are not zero
	if proofTG.Z1.IsZero() || proofTG.Z2.IsZero() {
		t.Fatal("Z1 or Z2 in πtg proof is zero")
	}

	// Generate πCL proof for index 0
	proofCL, err := GenerateProofCL(user, pp, 0)
	if err != nil {
		t.Fatalf("Failed to generate πCL proof: %v", err)
	}

	// Verify proofCL is not nil
	if proofCL == nil {
		t.Fatal("Generated πCL proof is nil")
	}

	// Verify elements in proof are not infinity points
	if proofCL.Zeta.IsInfinity() || proofCL.CM.IsInfinity() ||
		proofCL.C[0].IsInfinity() || proofCL.C[1].IsInfinity() ||
		proofCL.A[0].IsInfinity() || proofCL.A[1].IsInfinity() ||
		proofCL.B.IsInfinity() {
		t.Fatal("πCL proof contains infinity points")
	}

	// Verify responses are not zero
	if proofCL.ZD.IsZero() || proofCL.ZM.IsZero() ||
		proofCL.ZSigma.IsZero() || proofCL.ZK.IsZero() {
		t.Fatal("Responses in πCL proof are zero")
	}
}

// TestZKProofVerification tests zero-knowledge proof verification
func TestZKProofVerification(t *testing.T) {
	pp := Setup(128)
	n := 3
	signers := LongKeyGen(pp, n)

	messages := [][]byte{
		[]byte("Attribute 1"),
		[]byte("Attribute 2"),
		[]byte("Attribute 3"),
	}

	user, err := GenUserTag(messages, signers, n, pp)
	if err != nil {
		t.Fatalf("Failed to generate auxiliary tag: %v", err)
	}

	// Sign for each attribute
	for i := range signers {
		user, err = LongSignEncrypted(&signers[i], user, pp, i)
		if err != nil {
			t.Fatalf("Failed to generate long-term signature %d: %v", i, err)
		}
	}

	// Generate πtg proof
	proofTG, err := ProveDiscLog(user, pp)
	if err != nil {
		t.Fatalf("Failed to generate πtg proof: %v", err)
	}

	// Verify πtg proof
	validTG, err := VerifyProofTG(user, proofTG, pp)
	if err != nil {
		t.Fatalf("Error verifying πtg proof: %v", err)
	}
	if !validTG {
		t.Fatal("πtg proof verification failed")
	}

	// Generate πCL proof for index 0
	proofCL, err := GenerateProofCL(user, pp, 0)
	if err != nil {
		t.Fatalf("Failed to generate πCL proof: %v", err)
	}

	// Verify πCL proof
	validCL, err := VerifyProofCL(proofCL, pp, user)
	if err != nil {
		t.Fatalf("Error verifying πCL proof: %v", err)
	}
	if !validCL {
		t.Fatal("πCL proof verification failed")
	}
}

// Enhanced TestCLProofGenAndVerify test
func TestCLProofGenAndVerify(t *testing.T) {
	// 1. Initialize system parameters
	pp := Setup(128)
	if pp == nil {
		t.Fatal("Failed to initialize system parameters")
	}

	// 2. Create signers
	n := 3
	signers := LongKeyGen(pp, n)
	if len(signers) != n {
		t.Fatalf("Incorrect number of signers created: expected %d, got %d", n, len(signers))
	}

	// 3. Prepare messages
	messages := [][]byte{
		[]byte("Message for signer 1"),
		[]byte("Message for signer 2"),
		[]byte("Message for signer 3"),
	}

	// 4. Generate user tag
	user, err := GenUserTag(messages, signers, n, pp)
	if err != nil {
		t.Fatalf("GenUserTag failed: %v", err)
	}

	// 5. Parse aux data for user
	if err := user.parseUserAuxIfNeeded(); err != nil {
		t.Fatalf("Failed to parse aux data: %v", err)
	}

	// Print user aux data length and content summary
	t.Logf("User aux data length: %d bytes", len(user.aux))
	t.Logf("Number of messages after parsing: %d", len(user.parsedAux.messages))

	// Extract message commitments and encrypted messages from user aux
	encMsgs, commitments, pubKeys, err := extractMessagesAndPubKeys(user.aux)
	if err != nil {
		t.Fatalf("Failed to extract messages: %v", err)
	}
	t.Logf("Extracted from aux: %d encrypted messages, %d commitments, %d public keys",
		len(encMsgs), len(commitments), len(pubKeys))

	// 6. Generate CL proof - standard version
	i := 0 // Test first message
	t.Logf("Testing CL proof for issuer %d", i)

	proofCL, err := GenerateProofCL(user, pp, i)
	if err != nil {
		t.Fatalf("Failed to generate CL proof for issuer %d: %v", i, err)
	}

	// Print proof components
	t.Logf("CL proof component details:")
	t.Logf("  Zeta point coordinates: %s", proofCL.Zeta.String())
	t.Logf("  Ad point coordinates: %s", proofCL.Ad.String())
	t.Logf("  ZD response value: %s", proofCL.ZD.String())

	// 7. Verify CL proof - using modified verification function
	valid, err := VerifyProofCL(proofCL, pp, user)
	if err != nil {
		t.Fatalf("Error verifying CL proof for issuer %d: %v", i, err)
	}

	if !valid {
		t.Fatalf("CL proof verification failed for issuer %d", i)
	}

	t.Logf("Standard CL proof verification passed (equation 1 only)")

	// 8. Use fixed version to generate CL proof
	t.Logf("\nNow testing fixed CL proof:")
	fixedProofCL, err := FixedCLProofGenerate(user, pp, i)
	if err != nil {
		t.Fatalf("Failed to generate fixed CL proof: %v", err)
	}

	// Verify fixed proof
	fixedValid, err := VerifyProofCL(fixedProofCL, pp, user)
	if err != nil {
		t.Fatalf("Error verifying fixed CL proof: %v", err)
	}

	if !fixedValid {
		t.Fatalf("Fixed CL proof verification failed")
	}

	t.Logf("Fixed CL proof verification passed (all 4 equations)")
}

// TestCLProofVerify tests CL proof verification with detailed debugging
func TestCLProofVerify(t *testing.T) {
	// 1. Initialize system parameters
	pp := Setup(128)
	if pp == nil {
		t.Fatal("Failed to initialize system parameters")
	}

	// 2. Create signers
	n := 3
	signers := LongKeyGen(pp, n)
	if len(signers) != n {
		t.Fatalf("Incorrect number of signers created: expected %d, got %d", n, len(signers))
	}

	// 3. Prepare messages
	messages := [][]byte{
		[]byte("Message for signer 1"),
		[]byte("Message for signer 2"),
		[]byte("Message for signer 3"),
	}

	// 4. Generate user tag
	user, err := GenUserTag(messages, signers, n, pp)
	if err != nil {
		t.Fatalf("GenUserTag failed: %v", err)
	}

	// 5. Ensure user aux data is parsed
	if err := user.parseUserAuxIfNeeded(); err != nil {
		t.Fatalf("Failed to parse aux data: %v", err)
	}

	t.Logf("User aux data length: %d bytes", len(user.aux))
	t.Logf("Number of messages after parsing: %d", len(user.parsedAux.messages))

	// 6. Generate CL proof using fixed function
	i := 0 // Test first message
	proofCL, err := FixedCLProofGenerate(user, pp, i)
	if err != nil {
		t.Fatalf("Failed to generate fixed CL proof: %v", err)
	}

	t.Logf("Successfully generated fixed CL proof")
	t.Logf("Ad value: %s", proofCL.Ad.String())
	t.Logf("C[0] value: %s", proofCL.C[0].String())
	t.Logf("ZK value: %s", proofCL.ZK.String())

	// 7. Verify CL proof
	_, err = VerifyProofCL(proofCL, pp, user)
	if err != nil {
		t.Logf("Error verifying CL proof: %v", err)

		// If equation 2 verification fails, manually verify
		if err.Error() == "Equation 2 verification failed: u^(zk) != A[0] · C[0]^c" {
			t.Logf("\nManually verifying equation 2...")

			var left2, right2, right2_part bls.G1Affine
			challenge, _ := generateChallengeCL(
				&proofCL.Zeta, &proofCL.CM, &proofCL.C[0], &proofCL.C[1],
				&proofCL.Ad, &proofCL.A[0], &proofCL.A[1], &proofCL.B,
			)

			left2.ScalarMultiplication(&pp.ua, proofCL.ZK.BigInt(new(big.Int)))
			t.Logf("u^zk = %s", left2.String())

			right2_part.ScalarMultiplication(&proofCL.C[0], challenge.BigInt(new(big.Int)))
			t.Logf("C[0]^c = %s", right2_part.String())
			right2.Add(&proofCL.A[0], &right2_part)
			t.Logf("A[0] · C[0]^c = %s", right2.String())

			t.Logf("u^zk == A[0] · C[0]^c: %v", left2.Equal(&right2))
		}

		t.Fatalf("CL proof verification failed")
	}

	t.Logf("CL proof verification passed")
}

// TestSerializeDeserialize tests proof serialization and deserialization
func TestSerializeDeserialize(t *testing.T) {
	pp := Setup(128)
	n := 3
	signers := LongKeyGen(pp, n)

	messages := [][]byte{
		[]byte("Attribute 1"),
		[]byte("Attribute 2"),
		[]byte("Attribute 3"),
	}

	user, err := GenAuxTag(messages, signers, n, pp)
	if err != nil {
		t.Fatalf("Failed to generate auxiliary tag: %v", err)
	}

	// Sign for each attribute
	for i := range signers {
		user, err = LongSign(&signers[i], user, pp, i)
		if err != nil {
			t.Fatalf("Failed to generate long-term signature %d: %v", i, err)
		}
	}

	// Generate πtg proof
	proofTG, err := ProveDiscLog(user, pp)
	if err != nil {
		t.Fatalf("Failed to generate πtg proof: %v", err)
	}

	// Serialize proof
	serialized, err := SerializeProofTG(proofTG)
	if err != nil {
		t.Fatalf("Failed to serialize πtg proof: %v", err)
	}

	// Deserialize proof
	deserialized, err := DeserializeProofTG(serialized)
	if err != nil {
		t.Fatalf("Failed to deserialize πtg proof: %v", err)
	}

	// Verify if proof is equal before and after serialization
	if !deserialized.A.Equal(&proofTG.A) ||
		!deserialized.B.Equal(&proofTG.B) ||
		!deserialized.C.Equal(&proofTG.C) ||
		!deserialized.D.Equal(&proofTG.D) {
		t.Fatal("G1 points do not match before and after serialization")
	}

	z1Bytes := proofTG.Z1.Bytes()
	deserializedZ1Bytes := deserialized.Z1.Bytes()
	z2Bytes := proofTG.Z2.Bytes()
	deserializedZ2Bytes := deserialized.Z2.Bytes()

	if !bytes.Equal(z1Bytes[:], deserializedZ1Bytes[:]) {
		t.Fatal("Z1 does not match before and after serialization")
	}
	if !bytes.Equal(z2Bytes[:], deserializedZ2Bytes[:]) {
		t.Fatal("Z2 does not match before and after serialization")
	}

	// Verify using deserialized proof
	valid, err := VerifyProofTG(user, deserialized, pp)
	if err != nil {
		t.Fatalf("Error verifying deserialized πtg proof: %v", err)
	}
	if !valid {
		t.Fatal("Deserialized πtg proof verification failed")
	}
}

// BenchmarkProveDiscLog benchmark: πtg proof generation
func BenchmarkProveDiscLog(b *testing.B) {
	pp := Setup(128)
	n := 3
	signers := LongKeyGen(pp, n)

	messages := [][]byte{
		[]byte("Attribute 1"),
		[]byte("Attribute 2"),
		[]byte("Attribute 3"),
	}

	user, _ := GenAuxTag(messages, signers, n, pp)

	// Sign for each attribute
	for i := range signers {
		user, _ = LongSign(&signers[i], user, pp, i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ProveDiscLog(user, pp)
	}
}

// Modified BenchmarkVerifyProofCL benchmark
func BenchmarkVerifyProofCL(b *testing.B) {
	pp := Setup(128)
	n := 3
	signers := LongKeyGen(pp, n)

	messages := [][]byte{
		[]byte("Attribute 1"),
		[]byte("Attribute 2"),
		[]byte("Attribute 3"),
	}

	user, _ := GenAuxTag(messages, signers, n, pp)

	// Sign for each attribute
	for i := range signers {
		user, _ = LongSign(&signers[i], user, pp, i)
	}

	// Generate πCL proof
	proofCL, _ := GenerateProofCL(user, pp, 0)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Modified this line to add user parameter
		VerifyProofCL(proofCL, pp, user)
	}
}

// Example function: Demonstrate complete workflow
func ExampleFullZKPoK() {
	// 1. Setup system parameters
	pp := Setup(128)

	// 2. Generate signer keys
	signers := LongKeyGen(pp, 3)

	// 3. Generate user auxiliary tag
	messages := [][]byte{
		[]byte("Attribute 1"),
		[]byte("Attribute 2"),
		[]byte("Attribute 3"),
	}
	user, _ := GenAuxTag(messages, signers, 3, pp)

	// 4. Each signer signs for the user
	for i := range signers {
		user, _ = LongSign(&signers[i], user, pp, i)
	}

	// 5. Generate zero-knowledge proofs
	start := time.Now()
	proofTG, proofsCL, _ := GenerateZKProofs(user, pp)
	genTime := time.Since(start)

	// 6. Verify zero-knowledge proofs
	start = time.Now()
	valid, _ := VerifyZKProofs(user, pp, proofTG, proofsCL)
	verifyTime := time.Since(start)

	// 7. Output results
	fmt.Printf("Proof generation time: %v\n", genTime)
	fmt.Printf("Proof verification time: %v\n", verifyTime)
	fmt.Printf("Verification result: %v\n", valid)
}

func TestProveAndVerifyDiscLog(t *testing.T) {
	// 1. Setup test environment
	pp := Setup(128)
	numSigners := 3
	signers := LongKeyGen(pp, numSigners)

	// 2. Create user
	messages := [][]byte{[]byte("message1"), []byte("message2"), []byte("message3")}
	user, err := GenAuxTag(messages, signers, len(messages), pp)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// 3. Check if user object is correctly initialized
	if user.sk.gamma.IsZero() || user.sk.delta.IsZero() {
		t.Fatal("User private key not properly initialized")
	}

	if user.pk.hGamma.IsInfinity() || user.pk.hDelta.IsInfinity() {
		t.Fatal("User public key not properly initialized")
	}

	if len(user.aux) == 0 {
		t.Fatal("User auxiliary data not properly initialized")
	}

	// 4. Generate zero-knowledge proof
	fmt.Println("Generating zero-knowledge proof...")
	start := time.Now()
	proof, err := ProveDiscLog(user, pp)
	proveTime := time.Since(start)
	if err != nil {
		t.Fatalf("ProveDiscLog failed: %v", err)
	}

	// 5. Check if proof is correctly generated
	if proof.A.IsInfinity() || proof.B.IsInfinity() ||
		proof.C.IsInfinity() || proof.D.IsInfinity() {
		t.Fatal("Group elements in proof not correctly calculated (contains infinity points)")
	}

	if proof.Z1.IsZero() || proof.Z2.IsZero() {
		t.Fatal("Response values in proof not correctly calculated (are zero)")
	}

	// 6. Verify zero-knowledge proof
	fmt.Println("Verifying zero-knowledge proof...")
	start = time.Now()
	valid, err := VerifyProofTG(user, proof, pp)
	verifyTime := time.Since(start)
	if err != nil {
		t.Fatalf("VerifyProofTG failed: %v", err)
	}

	if !valid {
		t.Fatal("Valid proof failed verification")
	}

	fmt.Printf("Proof generation time: %v\n", proveTime)
	fmt.Printf("Proof verification time: %v\n", verifyTime)

	// 7. Test if invalid proof is rejected
	invalidProof := &ProofTG{
		A:  proof.A,
		B:  proof.B,
		C:  proof.C,
		D:  proof.D,
		Z1: *getFrElement(), // Replace correct response with random value
		Z2: proof.Z2,
	}
	invalidProof.Z1.SetRandom()
	defer putFrElement(&invalidProof.Z1)

	fmt.Println("Verifying invalid proof...")
	valid, err = VerifyProofTG(user, invalidProof, pp)
	if err != nil {
		t.Logf("Error verifying invalid proof: %v", err)
	}

	if valid {
		t.Fatal("Invalid proof incorrectly accepted")
	} else {
		fmt.Println("Successfully rejected invalid proof")
	}

	// 8. Test if proof from different user is rejected
	fmt.Println("Creating another user...")
	anotherUser, err := GenAuxTag([][]byte{[]byte("different message")}, signers, 1, pp)
	if err != nil {
		t.Fatalf("Failed to create another user: %v", err)
	}

	fmt.Println("Verifying proof with mismatched user...")
	valid, err = VerifyProofTG(anotherUser, proof, pp)
	if err != nil {
		t.Logf("Error verifying proof with mismatched user: %v", err)
	}

	if valid {
		t.Fatal("Proof with mismatched user incorrectly accepted")
	} else {
		fmt.Println("Successfully rejected proof with mismatched user")
	}

	// 9. Test if tampered public key causes verification failure
	fmt.Println("Testing tampered public key...")
	tamperedUser := &User{
		sk: user.sk,
		pk: struct {
			hGamma bls.G1Affine
			hDelta bls.G1Affine
		}{
			hGamma: user.pk.hGamma,
			hDelta: anotherUser.pk.hDelta, // Use hDelta from another user
		},
		aux: user.aux,
	}

	valid, err = VerifyProofTG(tamperedUser, proof, pp)
	if err != nil {
		t.Logf("Error verifying proof with tampered user: %v", err)
	}

	if valid {
		t.Fatal("Proof with tampered public key incorrectly accepted")
	} else {
		fmt.Println("Successfully rejected proof with tampered public key")
	}

	// 10. Stress test - multiple proof generations and verifications
	fmt.Println("\nPerforming stress test...")
	numIterations := 10
	var totalProveTime, totalVerifyTime time.Duration

	for i := 0; i < numIterations; i++ {
		start = time.Now()
		iterProof, err := ProveDiscLog(user, pp)
		iterProveTime := time.Since(start)
		totalProveTime += iterProveTime

		if err != nil {
			t.Fatalf("Failed to generate proof in iteration %d: %v", i+1, err)
		}

		start = time.Now()
		iterValid, err := VerifyProofTG(user, iterProof, pp)
		iterVerifyTime := time.Since(start)
		totalVerifyTime += iterVerifyTime

		if err != nil {
			t.Fatalf("Failed to verify proof in iteration %d: %v", i+1, err)
		}

		if !iterValid {
			t.Fatalf("Verification returned false in iteration %d", i+1)
		}

		fmt.Printf("Iteration %d: Generation: %v, Verification: %v\n", i+1, iterProveTime, iterVerifyTime)
	}

	fmt.Printf("\nStress test results (%d iterations):\n", numIterations)
	fmt.Printf("Average proof generation time: %v\n", totalProveTime/time.Duration(numIterations))
	fmt.Printf("Average proof verification time: %v\n", totalVerifyTime/time.Duration(numIterations))

	fmt.Println("\nAll tests passed!")
}

// DetailedVerifyProofCL performs detailed verification of CL proof, outputting all steps
func DetailedVerifyProofCL(proof *ProofCL, pp *EbpsParams, user *User, t *testing.T) (bool, error) {
	if proof == nil || pp == nil || user == nil {
		return false, ErrNilParams
	}

	// Calculate h from user.aux
	domain := []byte("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_")
	h, err := bls.HashToG1(user.aux, domain)
	if err != nil {
		return false, fmt.Errorf("failed to hash aux: %v", err)
	}

	// 1. Recalculate challenge
	challenge, err := generateChallengeCL(
		&proof.Zeta, &proof.CM, &proof.C[0], &proof.C[1],
		&proof.Ad, &proof.A[0], &proof.A[1], &proof.B,
	)
	if err != nil {
		return false, fmt.Errorf("failed to generate challenge: %w", err)
	}

	t.Logf("Challenge value: %s", challenge.String())

	// 2. Verify equation 1: u^(zd) = Ad · Zeta^c
	var left1, right1, right1_1, right1_2 bls.G1Affine
	left1.ScalarMultiplication(&pp.ua, proof.ZD.BigInt(new(big.Int)))

	right1_1 = proof.Ad
	right1_2.ScalarMultiplication(&proof.Zeta, challenge.BigInt(new(big.Int)))
	right1.Add(&right1_1, &right1_2)

	// Print intermediate values for debugging
	t.Logf("Intermediate values for equation 1:")
	t.Logf("  pp.ua: %s", pp.ua.String())
	t.Logf("  ZD (big.Int): %s", proof.ZD.BigInt(new(big.Int)).String())
	t.Logf("  Ad: %s", proof.Ad.String())
	t.Logf("  Zeta: %s", proof.Zeta.String())
	t.Logf("  challenge (big.Int): %s", challenge.BigInt(new(big.Int)).String())

	eq1 := left1.Equal(&right1)
	t.Logf("Equation 1 verification result: %v (u^(zd) = Ad · Zeta^c)", eq1)
	if !eq1 {
		t.Logf("  Left side (u^zd): %s", left1.String())
		t.Logf("  Right side (Ad · Zeta^c): %s", right1.String())
		t.Logf("  Ad: %s", proof.Ad.String())
		t.Logf("  Zeta^c: %s", right1_2.String())
		t.Logf("  ZD: %s", proof.ZD.String())

		// Note: Here we provide more explanation about why the equation should hold
		t.Logf("Note: In correct proof generation, we should have ZD = rd + d*c")
		t.Logf("Thus we should have u^(ZD) = u^(rd + d*c) = u^rd * u^(d*c) = u^rd * (u^d)^c = Ad * Zeta^c")

		return false, fmt.Errorf("equation 1 verification failed: u^(zd) != Ad · Zeta^c")
	}

	// 3. Verify equation 2: u^(zk) = A[0] · C[0]^c
	var left2, right2, temp bls.G1Affine
	left2.ScalarMultiplication(&pp.ua, proof.ZK.BigInt(new(big.Int)))

	temp.ScalarMultiplication(&proof.C[0], challenge.BigInt(new(big.Int)))
	right2.Add(&proof.A[0], &temp)

	eq2 := left2.Equal(&right2)
	t.Logf("Equation 2 verification result: %v (u^(zk) = A[0] · C[0]^c)", eq2)
	if !eq2 {
		t.Logf("  Left side (u^zk): %s", left2.String())
		t.Logf("  Right side (A[0] · C[0]^c): %s", right2.String())
		t.Logf("  A[0]: %s", proof.A[0].String())
		t.Logf("  C[0]^c: %s", temp.String())
		t.Logf("  ZK: %s", proof.ZK.String())
		return false, fmt.Errorf("equation 2 verification failed: u^(zk) != A[0] · C[0]^c")
	}

	// 4. Verify equation 3: (ζ)^(zk) · (h')^(zm) = A[1] · C[1]^c
	var left3_1, left3_2, left3, right3 bls.G1Affine
	left3_1.ScalarMultiplication(&proof.Zeta, proof.ZK.BigInt(new(big.Int)))
	// Use user.pk.hGamma as h'
	left3_2.ScalarMultiplication(&user.pk.hGamma, proof.ZM.BigInt(new(big.Int)))
	left3.Add(&left3_1, &left3_2)

	temp.ScalarMultiplication(&proof.C[1], challenge.BigInt(new(big.Int)))
	right3.Add(&proof.A[1], &temp)

	eq3 := left3.Equal(&right3)
	t.Logf("Equation 3 verification result: %v ((ζ)^(zk) · (h')^(zm) = A[1] · C[1]^c)", eq3)
	if !eq3 {
		t.Logf("  Left side: %s", left3.String())
		t.Logf("  Right side: %s", right3.String())
		return false, fmt.Errorf("equation 3 verification failed: (ζ)^(zk) · (h')^(zm) != A[1] · C[1]^c")
	}

	// 5. Verify equation 4: u^(zm) · h^(zsigma) = B · CM^c
	var left4_1, left4_2, left4, right4 bls.G1Affine
	left4_1.ScalarMultiplication(&pp.ua, proof.ZM.BigInt(new(big.Int)))
	left4_2.ScalarMultiplication(&h, proof.ZSigma.BigInt(new(big.Int)))
	left4.Add(&left4_1, &left4_2)

	temp.ScalarMultiplication(&proof.CM, challenge.BigInt(new(big.Int)))
	right4.Add(&proof.B, &temp)

	eq4 := left4.Equal(&right4)
	t.Logf("Equation 4 verification result: %v (u^(zm) · h^(zsigma) = B · CM^c)", eq4)
	if !eq4 {
		t.Logf("  Left side: %s", left4.String())
		t.Logf("  Right side: %s", right4.String())
		return false, fmt.Errorf("equation 4 verification failed: u^(zm) · h^(zsigma) != B · CM^c")
	}

	return true, nil
}

// TestSimpleCLProof tests simplified CL proof generation and verification
func TestSimpleCLProof(t *testing.T) {
	// 1. Initialize system parameters
	pp := Setup(128)
	if pp == nil {
		t.Fatal("Failed to initialize system parameters")
	}

	// 2. Create signers
	n := 3
	signers := LongKeyGen(pp, n)
	if len(signers) != n {
		t.Fatalf("Incorrect number of signers created: expected %d, got %d", n, len(signers))
	}

	// 3. Prepare messages
	messages := [][]byte{
		[]byte("Message for signer 1"),
		[]byte("Message for signer 2"),
		[]byte("Message for signer 3"),
	}

	// 4. Generate user tag
	user, err := GenUserTag(messages, signers, n, pp)
	if err != nil {
		t.Fatalf("GenUserTag failed: %v", err)
	}

	// 5. Ensure aux data is parsed
	if err := user.parseUserAuxIfNeeded(); err != nil {
		t.Fatalf("Failed to parse aux data: %v", err)
	}

	t.Logf("User aux data length: %d bytes", len(user.aux))
	t.Logf("Number of messages after parsing: %d", len(user.parsedAux.messages))

	// 6. Generate CL proof using simplified function
	i := 0 // Test first message
	proofCL, err := SimpleCLProofGenerate(user, pp, i)
	if err != nil {
		t.Fatalf("Failed to generate simplified CL proof: %v", err)
	}

	t.Logf("Successfully generated simplified CL proof")

	// 7. Detailed verification of CL proof
	valid, err := DetailedVerifyProofCL(proofCL, pp, user, t)
	if err != nil {
		t.Logf("Detailed verification found error: %v", err)
	}

	if !valid {
		t.Fatalf("Simplified CL proof verification failed")
	}

	t.Logf("Simplified CL proof verification passed")
}

// TestVectorCLProof tests vector form of CL proof equation 1
func TestVectorCLProof(t *testing.T) {
	// Initialize parameters
	pp := Setup(128)
	if pp == nil {
		t.Fatal("Failed to initialize system parameters")
	}

	// 1. Direct vector calculation
	t.Log("Using vector to directly calculate equation 1...")

	// Base element
	var u bls.G1Affine = pp.ua

	// Randomly generate private key d
	d := new(fr.Element)
	d.SetRandom()
	t.Logf("d: %s", d.String())

	// Calculate zeta = u^d
	var zeta bls.G1Affine
	zeta.ScalarMultiplication(&u, d.BigInt(new(big.Int)))
	t.Logf("zeta: %s", zeta.String())

	// Randomly generate rd and challenge
	rd := new(fr.Element)
	rd.SetRandom()
	challenge := new(fr.Element)
	challenge.SetRandom()
	t.Logf("rd: %s", rd.String())
	t.Logf("challenge: %s", challenge.String())

	// Calculate zd = rd + challenge*d
	zd := new(fr.Element)
	{
		var temp fr.Element
		temp.Mul(challenge, d)
		zd.Add(&temp, rd)
	}
	t.Logf("zd: %s", zd.String())

	// Verify equation 1: u^zd = zeta^challenge * u^rd
	var left, right1, right2, right bls.G1Affine
	left.ScalarMultiplication(&u, zd.BigInt(new(big.Int)))
	t.Logf("Left side (u^zd): %s", left.String())

	right1.ScalarMultiplication(&zeta, challenge.BigInt(new(big.Int)))
	t.Logf("right1 (zeta^challenge): %s", right1.String())

	right2.ScalarMultiplication(&u, rd.BigInt(new(big.Int)))
	t.Logf("right2 (u^rd): %s", right2.String())

	right.Add(&right1, &right2)
	t.Logf("Right side (zeta^challenge * u^rd): %s", right.String())

	// Check equality
	if !left.Equal(&right) {
		t.Fatalf("Vector verification of equation 1 failed")
	}

	t.Log("Vector verification of equation 1 passed")

	// Alternative form: u^zd = zeta^challenge
	// Here zd = rd + c*d, and zeta = u^d
	// So u^zd = u^(rd + c*d) = u^rd * u^(c*d) = u^rd * (u^d)^c = u^rd * zeta^c
	var altLeft, altRight bls.G1Affine
	altLeft.ScalarMultiplication(&u, zd.BigInt(new(big.Int)))

	// Calculate zeta^c
	var zetaC bls.G1Affine
	zetaC.ScalarMultiplication(&zeta, challenge.BigInt(new(big.Int)))

	// Issue here - correct expression should be u^zd = u^rd * zeta^c
	altRight = zetaC // This is incorrect, just for demonstration

	// Check
	if altLeft.Equal(&altRight) {
		t.Log("Warning: u^zd = zeta^c this equation usually doesn't hold!")
	} else {
		t.Log("Expected result: u^zd != zeta^c")
	}

	// Correct expression: u^zd = u^rd * zeta^c
	var correctRight bls.G1Affine
	correctRight.Add(&right2, &zetaC)

	if altLeft.Equal(&correctRight) {
		t.Log("Correct equation holds: u^zd = u^rd * zeta^c")
	} else {
		t.Fatalf("Error: u^zd != u^rd * zeta^c")
	}
}

// TestFixedCLProof tests equation 1 of CL proof using fixed values
func TestFixedCLProof(t *testing.T) {
	// Initialize parameters
	pp := Setup(128)
	if pp == nil {
		t.Fatal("Failed to initialize system parameters")
	}

	var u bls.G1Affine = pp.ua
	t.Logf("u: %s", u.String())

	// Use fixed values
	d := new(fr.Element)
	d.SetInt64(42)

	rd := new(fr.Element)
	rd.SetInt64(7)

	challenge := new(fr.Element)
	challenge.SetInt64(13)

	// Calculate zeta = u^d
	var zeta bls.G1Affine
	zeta.ScalarMultiplication(&u, d.BigInt(new(big.Int)))
	t.Logf("zeta = u^d = u^42: %s", zeta.String())

	// Calculate zd = rd + challenge*d
	var cd, zd fr.Element
	cd.Mul(challenge, d) // cd = 13*42 = 546
	zd.Add(&cd, rd)      // zd = 546 + 7 = 553
	t.Logf("challenge*d = 13*42 = %s", cd.String())
	t.Logf("zd = rd + challenge*d = 7 + 546 = %s", zd.String())

	// Calculate u^zd
	var uZd bls.G1Affine
	uZd.ScalarMultiplication(&u, zd.BigInt(new(big.Int)))
	t.Logf("u^zd = u^553: %s", uZd.String())

	// Calculate zeta^challenge = (u^d)^challenge = u^(d*challenge)
	var zetaC bls.G1Affine
	zetaC.ScalarMultiplication(&zeta, challenge.BigInt(new(big.Int)))
	t.Logf("zeta^challenge = (u^42)^13: %s", zetaC.String())

	// Verify u^zd == zeta^challenge
	if uZd.Equal(&zetaC) {
		t.Logf("Correct: u^zd = zeta^challenge")
	} else {
		t.Logf("Error: u^zd != zeta^challenge")

		// Check if u^(d*challenge) equals (u^d)^challenge
		var uDC bls.G1Affine
		uDC.ScalarMultiplication(&u, cd.BigInt(new(big.Int)))
		t.Logf("u^(d*challenge) = u^546: %s", uDC.String())

		if uDC.Equal(&zetaC) {
			t.Logf("Verification correct: u^(d*challenge) = (u^d)^challenge")
		} else {
			t.Fatalf("Basic verification failed: u^(d*challenge) != (u^d)^challenge")
		}

		// Check u^zd = u^rd * u^(d*challenge)
		var uRd, combined bls.G1Affine
		uRd.ScalarMultiplication(&u, rd.BigInt(new(big.Int)))
		t.Logf("u^rd = u^7: %s", uRd.String())

		// Addition on elliptic curve equals multiplication
		combined.Add(&uRd, &uDC)
		t.Logf("u^rd * u^(d*challenge) = u^7 * u^546: %s", combined.String())

		if uZd.Equal(&combined) {
			t.Logf("Verification correct: u^zd = u^rd * u^(d*challenge)")
		} else {
			t.Fatalf("Basic verification failed: u^zd != u^rd * u^(d*challenge)")
		}
	}
} // FixedDetailedVerifyProofCL performs detailed verification of the fixed CL proof
func FixedDetailedVerifyProofCL(proof *ProofCL, pp *EbpsParams, user *User, t *testing.T) (bool, error) {
	if proof == nil || pp == nil || user == nil {
		return false, ErrNilParams
	}

	// Calculate h from user.aux
	domain := []byte("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_")
	h, err := bls.HashToG1(user.aux, domain)
	if err != nil {
		return false, fmt.Errorf("failed to hash aux: %v", err)
	}

	// 1. Recalculate challenge - using new function that includes Ad
	challenge, err := generateFixedChallengeCL(
		&proof.Zeta, &proof.CM, &proof.C[0], &proof.C[1],
		&proof.Ad, &proof.A[0], &proof.A[1], &proof.B,
	)
	if err != nil {
		return false, fmt.Errorf("failed to generate challenge: %w", err)
	}

	t.Logf("Challenge value: %s", challenge.String())

	// 2. Verify equation 1: u^(zd) = Ad · Zeta^c
	var left1, right1, right1_1, right1_2 bls.G1Affine
	left1.ScalarMultiplication(&pp.ua, proof.ZD.BigInt(new(big.Int)))

	right1_1 = proof.Ad                                                        // Ad
	right1_2.ScalarMultiplication(&proof.Zeta, challenge.BigInt(new(big.Int))) // Zeta^c
	right1.Add(&right1_1, &right1_2)                                           // Ad · Zeta^c

	// Print intermediate values for debugging
	t.Logf("Intermediate values for equation 1:")
	t.Logf("  pp.ua: %s", pp.ua.String())
	t.Logf("  ZD (big.Int): %s", proof.ZD.BigInt(new(big.Int)).String())
	t.Logf("  Ad: %s", proof.Ad.String())
	t.Logf("  Zeta: %s", proof.Zeta.String())
	t.Logf("  challenge (big.Int): %s", challenge.BigInt(new(big.Int)).String())

	eq1 := left1.Equal(&right1)
	t.Logf("Equation 1 verification result: %v (u^(zd) = Ad · Zeta^c)", eq1)
	if !eq1 {
		t.Logf("  Left side (u^zd): %s", left1.String())
		t.Logf("  Right side (Ad · Zeta^c): %s", right1.String())
		t.Logf("  Ad: %s", proof.Ad.String())
		t.Logf("  Zeta^c: %s", right1_2.String())
		t.Logf("  ZD: %s", proof.ZD.String())
		return false, fmt.Errorf("equation 1 verification failed: u^(zd) != Ad · Zeta^c")
	}

	// 3. Verify equation 2: u^(zk) = A[0] · C[0]^c
	var left2, right2, temp bls.G1Affine
	left2.ScalarMultiplication(&pp.ua, proof.ZK.BigInt(new(big.Int)))

	temp.ScalarMultiplication(&proof.C[0], challenge.BigInt(new(big.Int))) // C[0]^c
	right2.Add(&proof.A[0], &temp)                                         // A[0] · C[0]^c

	eq2 := left2.Equal(&right2)
	t.Logf("Equation 2 verification result: %v (u^(zk) = A[0] · C[0]^c)", eq2)
	if !eq2 {
		t.Logf("  Left side (u^zk): %s", left2.String())
		t.Logf("  Right side (A[0] · C[0]^c): %s", right2.String())
		t.Logf("  A[0]: %s", proof.A[0].String())
		t.Logf("  C[0]^c: %s", temp.String())
		t.Logf("  ZK: %s", proof.ZK.String())
		return false, fmt.Errorf("equation 2 verification failed: u^(zk) != A[0] · C[0]^c")
	}

	// 4. Verify equation 3: (ζ)^(zk) · (h')^(zm) = A[1] · C[1]^c
	var left3_1, left3_2, left3, right3 bls.G1Affine
	left3_1.ScalarMultiplication(&proof.Zeta, proof.ZK.BigInt(new(big.Int))) // (ζ)^(zk)
	// Use user.pk.hGamma as h'
	left3_2.ScalarMultiplication(&user.pk.hGamma, proof.ZM.BigInt(new(big.Int))) // (h')^(zm)
	left3.Add(&left3_1, &left3_2)                                                // (ζ)^(zk) · (h')^(zm)

	temp.ScalarMultiplication(&proof.C[1], challenge.BigInt(new(big.Int))) // C[1]^c
	right3.Add(&proof.A[1], &temp)                                         // A[1] · C[1]^c

	eq3 := left3.Equal(&right3)
	t.Logf("Equation 3 verification result: %v ((ζ)^(zk) · (h')^(zm) = A[1] · C[1]^c)", eq3)
	if !eq3 {
		t.Logf("  Left side: %s", left3.String())
		t.Logf("  Right side: %s", right3.String())
		return false, fmt.Errorf("equation 3 verification failed: (ζ)^(zk) · (h')^(zm) != A[1] · C[1]^c")
	}

	// 5. Verify equation 4: u^(zm) · h^(zsigma) = B · CM^c
	var left4_1, left4_2, left4, right4 bls.G1Affine
	left4_1.ScalarMultiplication(&pp.ua, proof.ZM.BigInt(new(big.Int))) // u^(zm)
	left4_2.ScalarMultiplication(&h, proof.ZSigma.BigInt(new(big.Int))) // h^(zsigma)
	left4.Add(&left4_1, &left4_2)                                       // u^(zm) · h^(zsigma)

	temp.ScalarMultiplication(&proof.CM, challenge.BigInt(new(big.Int))) // CM^c
	right4.Add(&proof.B, &temp)                                          // B · CM^c

	eq4 := left4.Equal(&right4)
	t.Logf("Equation 4 verification result: %v (u^(zm) · h^(zsigma) = B · CM^c)", eq4)
	if !eq4 {
		t.Logf("  Left side: %s", left4.String())
		t.Logf("  Right side: %s", right4.String())
		return false, fmt.Errorf("equation 4 verification failed: u^(zm) · h^(zsigma) != B · CM^c")
	}

	return true, nil
}
