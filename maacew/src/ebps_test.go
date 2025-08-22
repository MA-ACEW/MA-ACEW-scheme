package ma

import (
	"bytes"
	"fmt"
	"math"
	"math/big"
	"runtime"
	"sync"
	"testing"
	"time"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func TestSetup(t *testing.T) {
	pp := Setup(128)
	if pp == nil {
		t.Fatal("Setup failed")
	}

	// 检查生成器不为零点
	if pp.ua.IsInfinity() || pp.va.IsInfinity() {
		t.Error("System parameters contain infinity points")
	}
}

func TestLongKeyGen(t *testing.T) {
	pp := Setup(128)
	numSigners := []int{1, 5, 10, 20}

	for _, n := range numSigners {
		signers := LongKeyGen(pp, n)
		if len(signers) != n {
			t.Errorf("Expected %d signers, got %d", n, len(signers))
		}

		if !areSignersDistinct(signers) {
			t.Errorf("Duplicate verification keys found for %d signers", n)
		}

		for i, signer := range signers {

			var expected bls.G2Affine
			expected.ScalarMultiplication(&pp.va, signer.lsk1.BigInt(new(big.Int)))
			if !expected.Equal(&signer.lvk1) {
				t.Errorf("Key pair mismatch for signer %d (lsk1/lvk1)", i)
			}

			expected.ScalarMultiplication(&pp.va, signer.lsk2.BigInt(new(big.Int)))
			if !expected.Equal(&signer.lvk2) {
				t.Errorf("Key pair mismatch for signer %d (lsk2/lvk2)", i)
			}
		}
	}
}
func TestEpochKeyGenWithTiming(t *testing.T) {
	t.Log("BeginEpochKeyGen Performance...")

	pp := Setup(128)
	numSigners := 256

	signers := LongKeyGen(pp, numSigners)
	start := time.Now()
	longKeyGenTime := time.Since(start).Milliseconds()
	t.Logf("LongKeyGen: %d ms", longKeyGenTime)

	epochs := []int{0, 1, 2}
	var totalTime int64
	var minTime, maxTime int64 = math.MaxInt64, 0

	for _, epoch := range epochs {
		t.Logf("\nTesting epoch = %d", epoch)

		start = time.Now()
		updatedSigners := EpochKeyGen(pp, signers, epoch)
		duration := time.Since(start)
		epochTime := duration.Milliseconds()

		totalTime += epochTime
		minTime = min(minTime, epochTime)
		maxTime = max(maxTime, epochTime)

		t.Logf("Epoch %d KGen time: %d ms", epoch, epochTime)

		for i, signer := range updatedSigners {
			var expected bls.G2Affine
			expected.ScalarMultiplication(&pp.va, signer.tsk.BigInt(new(big.Int)))
			if !expected.Equal(&signer.tvk) {
				t.Errorf("Epoch %d: signer %d failed", epoch, i)
			}
		}

		for i := range updatedSigners {
			if !updatedSigners[i].lvk1.Equal(&signers[i].lvk1) ||
				!updatedSigners[i].lvk2.Equal(&signers[i].lvk2) {
				t.Errorf("Epoch %d: signer %d long-term key pair mismatch", epoch, i)
			}
		}
	}

	avgTime := totalTime / int64(len(epochs))
	t.Logf("\nPerformance (For %d signers):", numSigners)
	t.Logf("Avarege KGen time: %d ms", avgTime)
	t.Logf("Min KGen time: %d ms", minTime)
	t.Logf("Max KGen time: %d ms", maxTime)
	t.Logf("Total time: %d ms", totalTime)

	msPerSigner := float64(avgTime) / float64(numSigners)
	t.Logf("Each signer takes: %.3f ms", msPerSigner)
}

func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func max(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func TestGenAuxTag(t *testing.T) {

	pp := Setup(128)

	numSigners := 4
	signers := LongKeyGen(pp, numSigners)
	if len(signers) != numSigners {
		t.Fatalf("LongKeyGen generated %d signers, expected %d", len(signers), numSigners)
	}
	t.Logf("Number of signers: %d", len(signers))

	t.Run("Normal case", func(t *testing.T) {
		messages := [][]byte{[]byte("message1"), []byte("message2"), []byte("message3")}
		l := len(messages)

		user, err := GenAuxTag(messages, signers, l, pp)
		if err != nil {
			t.Fatalf("GenAuxTag failed: %v", err)
		}

		if user == nil {
			t.Fatal("Expected non-nil user")
		}

		var zeroFr fr.Element
		if user.sk.gamma.Equal(&zeroFr) {
			t.Error("gamma should not be zero")
		}
		if user.sk.delta.Equal(&zeroFr) {
			t.Error("delta should not be zero")
		}

		if len(user.aux) == 0 {
			t.Error("aux should not be empty")
		}

		if (user.pk.hGamma == bls.G1Affine{}) {
			t.Error("hGamma should not be identity")
		}
		if (user.pk.hDelta == bls.G1Affine{}) {
			t.Error("hDelta should not be identity")
		}

		domain := []byte("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_")
		h, err := bls.HashToG1(user.aux, domain)
		if err != nil {
			t.Fatalf("Failed to hash aux: %v", err)
		}

		var expectedHGamma, expectedHDelta bls.G1Affine
		expectedHGamma.ScalarMultiplication(&h, user.sk.gamma.BigInt(new(big.Int)))
		expectedHDelta.ScalarMultiplication(&h, user.sk.delta.BigInt(new(big.Int)))

		if !user.pk.hGamma.Equal(&expectedHGamma) {
			t.Error("hGamma calculation is incorrect")
		}
		if !user.pk.hDelta.Equal(&expectedHDelta) {
			t.Error("hDelta calculation is incorrect")
		}

		var actualLVK2Length int
		if len(signers) > 0 {
			actualLVK2Length = len(signers[0].lvk2.Bytes())
		} else {
			t.Fatal("No signers available to determine lvk2 length")
		}

		expectedMinLength := 2*48 + l*(1+len(messages[0])+actualLVK2Length)
		t.Logf("Expected min aux length: %d, Actual aux length: %d", expectedMinLength, len(user.aux))

		if len(user.aux) < expectedMinLength {
			t.Errorf("aux length too short, got %d, want at least %d",
				len(user.aux), expectedMinLength)
		}
	})

	t.Run("Parameter validation", func(t *testing.T) {

		messages := [][]byte{[]byte("msg1"), []byte("msg2"), []byte("msg3"), []byte("msg4"), []byte("msg5")}
		l := 5
		t.Logf("Testing with l=%d and len(signers)=%d", l, len(signers))
		_, err := GenAuxTag(messages, signers, l, pp)
		if err == nil {
			t.Error("Expected error when l > len(signers), got nil")
		}

		messages = [][]byte{[]byte("msg1")}
		l = 2
		t.Logf("Testing with len(messages)=%d and l=%d", len(messages), l)
		_, err = GenAuxTag(messages, signers, l, pp)
		if err == nil {
			t.Error("Expected error when len(messages) != l, got nil")
		}

		messages = [][]byte{[]byte("")}
		l = 1
		t.Logf("Testing with messages containing an empty message")
		_, err = GenAuxTag(messages, signers, l, pp)
		if err != nil {
			t.Error("Should accept empty message")
		}

		messages = [][]byte{}
		l = 0
		t.Logf("Testing with l=0")
		_, err = GenAuxTag(messages, signers, l, pp)
		if err == nil {
			t.Error("Expected error when l = 0, got nil")
		}

		messages = [][]byte{[]byte("msg1")}
		l = 1
		emptySigners := LongKeyGen(pp, 0)
		t.Logf("Testing with empty signers")
		_, err = GenAuxTag(messages, emptySigners, l, pp)
		if err == nil {
			t.Error("Expected error when signers is empty, got nil")
		}
	})

	t.Run("Randomness check", func(t *testing.T) {
		messages := [][]byte{[]byte("message1")}
		l := len(messages)

		user1, err := GenAuxTag(messages, signers, l, pp)
		if err != nil {
			t.Fatalf("Failed to generate first user: %v", err)
		}

		user2, err := GenAuxTag(messages, signers, l, pp)
		if err != nil {
			t.Fatalf("Failed to generate second user: %v", err)
		}

		if user1.sk.gamma.Equal(&user2.sk.gamma) {
			t.Error("gamma values are not random")
		}
		if user1.sk.delta.Equal(&user2.sk.delta) {
			t.Error("delta values are not random")
		}

		if bytes.Equal(user1.aux, user2.aux) {
			t.Error("aux values should be different")
		}

		numTests := 5
		var users []*User
		for i := 0; i < numTests; i++ {
			user, err := GenAuxTag(messages, signers, l, pp)
			if err != nil {
				t.Fatalf("Failed to generate user %d: %v", i, err)
			}
			users = append(users, user)
		}

		for i := 0; i < numTests; i++ {
			for j := i + 1; j < numTests; j++ {
				if users[i].sk.gamma.Equal(&users[j].sk.gamma) {
					t.Errorf("gamma values are not random between user %d and %d", i, j)
				}
				if users[i].sk.delta.Equal(&users[j].sk.delta) {
					t.Errorf("delta values are not random between user %d and %d", i, j)
				}
				if bytes.Equal(users[i].aux, users[j].aux) {
					t.Errorf("aux values are identical between user %d and %d", i, j)
				}
			}
		}
	})
}

func TestG2AffineSerialization(t *testing.T) {
	pp := Setup(128)
	signer := LongKeyGen(pp, 1)[0]

	pubKeyBytes := signer.lvk2.Bytes()
	if len(pubKeyBytes) != bls.SizeOfG2AffineCompressed {
		t.Fatalf("Public key bytes length incorrect: got %d, want %d", len(pubKeyBytes), bls.SizeOfG2AffineCompressed)
	}

	var pubKey bls.G2Affine
	if _, err := pubKey.SetBytes(pubKeyBytes[:]); err != nil {
		t.Fatalf("G2Affine.SetBytes failed: %v", err)
	}

	if !pubKey.Equal(&signer.lvk2) {
		t.Fatalf("Serialized and deserialized public key do not match")
	}
}
func TestLongSign(t *testing.T) {
	pp := Setup(128)
	numSigners := 3
	signers := LongKeyGen(pp, numSigners)

	messages := [][]byte{
		bytes.Repeat([]byte{0x01}, 32), // 32
		bytes.Repeat([]byte{0x02}, 32), // 32
		bytes.Repeat([]byte{0x03}, 32), // 32
	}

	user, err := GenAuxTag(messages, signers, len(messages), pp)
	if err != nil {
		t.Fatalf("GenAuxTag failed: %v", err)
	}

	user.longtermSigs = make([]struct {
		h bls.G1Affine
		s []bls.G1Affine
	}, 0)

	for i := 0; i < len(messages); i++ {
		updatedUser, err := LongSign(&signers[i], user, pp, i)
		if err != nil {
			t.Errorf("LongSign failed for index %d: %v", i, err)
			continue
		}
		user = updatedUser

		if len(user.longtermSigs) <= i || user.longtermSigs[i].h.IsInfinity() {
			t.Errorf("Invalid signature for index %d", i)
		}
	}

	testCases := []struct {
		name    string
		signer  *Signer
		user    *User
		pp      *EbpsParams
		index   int
		wantErr bool
	}{
		{
			name:    "Nil signer",
			signer:  nil,
			user:    user,
			pp:      pp,
			index:   0,
			wantErr: true,
		},
		{
			name:    "Nil user",
			signer:  &signers[0],
			user:    nil,
			pp:      pp,
			index:   0,
			wantErr: true,
		},
		{
			name:    "Invalid index",
			signer:  &signers[0],
			user:    user,
			pp:      pp,
			index:   len(messages),
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LongSign(tc.signer, tc.user, tc.pp, tc.index)
			if (err != nil) != tc.wantErr {
				t.Errorf("LongSign() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
func TestEpochSignSingleSigner(t *testing.T) {

	pp := Setup(128)

	signers := LongKeyGen(pp, 1)
	if len(signers) != 1 {
		t.Fatalf("expected 1 signer, got %d", len(signers))
	}

	epoch := 42
	signers = EpochKeyGen(pp, signers, epoch)

	user := &User{
		longtermSigs: []struct {
			h bls.G1Affine
			s []bls.G1Affine
		}{},
		pk: struct {
			hGamma bls.G1Affine
			hDelta bls.G1Affine
		}{},
	}

	var m1 fr.Element
	m1.SetUint64(1)
	b1 := m1.Bytes()
	messages := [][]byte{b1[:]}
	l := len(messages)

	user, err := GenAuxTag(messages, signers, l, pp)
	if err != nil {
		t.Fatalf("GenAuxTag failed: %v", err)
	}

	start1 := time.Now()
	user, err = LongSign(&signers[0], user, pp, 0)
	if err != nil {
		t.Fatalf("LongSign failed: %v", err)
	}

	elapsed := float64(time.Since(start1).Nanoseconds()) / 1e6
	t.Logf("EpochSign took %.3f milliseconds", elapsed)

	user.epochSigs = make([]bls.G1Affine, 1)

	start := time.Now()

	aggregatedUser, err := EpochSign(&signers[0], user, pp, 0, uint64(epoch))
	if err != nil {
		t.Fatalf("EpochSign failed: %v", err)
	}

	elapsed1 := float64(time.Since(start).Nanoseconds()) / 1e6
	t.Logf("EpochSign took %.3f milliseconds", elapsed1)

	if len(aggregatedUser.epochSigs) <= 0 {
		t.Fatalf("epochSigs not initialized")
	}

	epochSig := aggregatedUser.epochSigs[0]

	if epochSig.IsInfinity() {
		t.Fatalf("computed epoch signature is point at infinity")
	}

	fmt.Printf("Computed epoch signature: %x\n", epochSig.Bytes())

}

func TestEpochSignMultipleSigners(t *testing.T) {

	pp := Setup(128)

	nSigners := 3
	signers := LongKeyGen(pp, nSigners)
	if len(signers) != nSigners {
		t.Fatalf("expected %d signers, got %d", nSigners, len(signers))
	}

	epoch := 1
	signers = EpochKeyGen(pp, signers, epoch)

	user := &User{
		longtermSigs: []struct {
			h bls.G1Affine
			s []bls.G1Affine
		}{},
	}

	messages := [][]byte{
		bytes.Repeat([]byte{0x01}, 32), // 32
		bytes.Repeat([]byte{0x02}, 32), // 32
		bytes.Repeat([]byte{0x03}, 32), // 32
	}

	l := len(messages)

	user, err := GenAuxTag(messages, signers, l, pp)
	if err != nil {
		t.Fatalf("GenAuxTag failed: %v", err)
	}

	fmt.Printf("After GenAuxTag, aux length: %d\n", len(user.aux))

	for i := 0; i < l; i++ {
		updatedUser, err := LongSign(&signers[i], user, pp, i)
		if err != nil {
			t.Fatalf("LongSign failed for index %d: %v", i, err)
		}

		fmt.Printf("After LongSign, user.longtermSigs[%d].s[0]: %x\n", i, user.longtermSigs[i].s[0].Bytes())

		if len(user.longtermSigs) <= i || user.longtermSigs[i].h.IsInfinity() {
			t.Errorf("Invalid signature for index %d", i)
		}
		user = updatedUser
	}

	user.epochSigs = make([]bls.G1Affine, nSigners)

	for i := 0; i < nSigners; i++ {
		j := uint64(epoch)
		aggregatedUser, err := EpochSign(&signers[i], user, pp, i, j)
		if err != nil {
			t.Fatalf("EpochSign failed for signer %d: %v", i, err)
		}

		user = aggregatedUser

		if len(user.epochSigs) <= i {
			t.Fatalf("epochSigs not initialized at index %d", i)
		}

		epochSig := aggregatedUser.epochSigs[i]

		if epochSig.IsInfinity() {
			t.Fatalf("computed epoch signature for signer %d is point at infinity", i)
		}

		fmt.Printf("Computed epoch signature s[%d]: %x\n", i, epochSig.Bytes())

	}
}
func TestVerifyWithTiming(t *testing.T) {

	pp := Setup(128)
	numSigners := 32
	numIterations := 100

	stats := NewStats()
	errorCaseStats := make(map[string]*Stats)

	signers := LongKeyGen(pp, numSigners)
	messages := [][]byte{[]byte("msg1")}

	fmt.Println("\n=== Verify Performance Test ===")

	start := time.Now()
	user, _ := GenAuxTag(messages, signers, len(messages), pp)
	genAuxTime := time.Since(start).Milliseconds()
	fmt.Printf("GenAuxTag time: %d ms\n", genAuxTime)

	currentEpoch := uint64(1)
	start = time.Now()
	signers = EpochKeyGen(pp, signers, int(currentEpoch))
	epochKeyGenTime := time.Since(start).Milliseconds()
	fmt.Printf("EpochKeyGen time: %d ms\n", epochKeyGenTime)

	var longSignTime, epochSignTime int64
	for i := 0; i < len(messages); i++ {
		start = time.Now()
		user, _ = LongSign(&signers[i], user, pp, i)
		longSignTime = time.Since(start).Milliseconds()
		fmt.Printf("LongSign time: %d ms\n", longSignTime)

		start = time.Now()
		user, _ = EpochSign(&signers[i], user, pp, i, currentEpoch)
		epochSignTime = time.Since(start).Milliseconds()
		fmt.Printf("EpochSign time: %d ms\n", epochSignTime)
	}

	testCases := []struct {
		name    string
		epoch   uint64
		user    *User
		signer  *Signer
		index   int
		pp      *EbpsParams
		wantErr bool
	}{
		{
			name:    "Normal case",
			epoch:   currentEpoch,
			user:    user,
			signer:  &signers[0],
			index:   0,
			pp:      pp,
			wantErr: false,
		},
		{
			name:    "Wrong epoch",
			epoch:   currentEpoch + 1,
			user:    user,
			signer:  &signers[0],
			index:   0,
			pp:      pp,
			wantErr: false,
		},
		{
			name:    "Invalid index",
			epoch:   currentEpoch,
			user:    user,
			signer:  &signers[0],
			index:   len(messages),
			pp:      pp,
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		errorCaseStats[tc.name] = NewStats()
	}

	fmt.Println("\n=== Normal Verification Tests ===")

	for iter := 0; iter < numIterations; iter++ {
		for i := 0; i < len(messages); i++ {
			start := time.Now()
			valid, err := Verify(currentEpoch, user, &signers[i], i, pp)
			duration := time.Since(start)
			stats.Add(duration)

			if err != nil {
				t.Errorf("Iteration %d: Verify failed for index %d: %v", iter, i, err)
			}
			if !valid {
				t.Errorf("Iteration %d: Signature verification failed for index %d", iter, i)
			}

			if iter == 0 {
				fmt.Printf("Verify #%d time: %.3f ms\n", i+1, float64(duration.Microseconds())/1000.0)
			}
		}
	}

	fmt.Println("\n=== Error Case Tests ===")
	for _, tc := range testCases {

		for iter := 0; iter < numIterations; iter++ {
			start := time.Now()
			valid, err := Verify(tc.epoch, tc.user, tc.signer, tc.index, tc.pp)
			duration := time.Since(start)
			errorCaseStats[tc.name].Add(duration)

			if iter == 0 {
				if (err != nil) != tc.wantErr {
					t.Errorf("%s: Verify() error = %v, wantErr %v", tc.name, err, tc.wantErr)
				}
				if err == nil && tc.name == "Wrong epoch" && valid {
					t.Error("Expected verification to fail with wrong epoch")
				}

				fmt.Printf("\nTest Case: %s\n", tc.name)
				fmt.Printf("Verification time: %.3f ms\n", float64(duration.Microseconds())/1000.0)
			}
		}
	}

	stats.Calculate()
	fmt.Printf("\n=== Verification Statistics (Based on %d iterations) ===\n", numIterations)
	fmt.Printf("Mean time: %.3f ms\n", stats.Mean/float64(time.Millisecond))
	fmt.Printf("Std Dev: %.3f ms\n", stats.Std/float64(time.Millisecond))
	fmt.Printf("Min time: %.3f ms\n", stats.Min/float64(time.Millisecond))
	fmt.Printf("Max time: %.3f ms\n", stats.Max/float64(time.Millisecond))

	fmt.Println("\n=== Test Case Statistics ===")
	for name, caseStat := range errorCaseStats {
		caseStat.Calculate()
		fmt.Printf("\n--- %s ---\n", name)
		fmt.Printf("Mean time: %.3f ms\n", caseStat.Mean/float64(time.Millisecond))
		fmt.Printf("Std Dev: %.3f ms\n", caseStat.Std/float64(time.Millisecond))
		fmt.Printf("Min time: %.3f ms\n", caseStat.Min/float64(time.Millisecond))
		fmt.Printf("Max time: %.3f ms\n", caseStat.Max/float64(time.Millisecond))
	}
}
func TestAggregation(t *testing.T) {

	numSigners := 65

	start := time.Now()
	pp := Setup(128)
	setupTime := float64(time.Since(start).Nanoseconds()) / 1e6
	t.Logf("Setup took %.3f milliseconds", setupTime)

	start = time.Now()
	signers := LongKeyGen(pp, numSigners)
	keygenTime := float64(time.Since(start).Nanoseconds()) / 1e6
	t.Logf("LongKeyGen took %.3f milliseconds", keygenTime)

	for i, signer := range signers {
		if signer.lsk1.IsZero() || signer.lsk2.IsZero() {
			t.Fatalf("Signer %d has zero private key", i)
		}
	}

	messages := make([][]byte, numSigners)
	for i := 0; i < numSigners; i++ {
		messages[i] = bytes.Repeat([]byte{byte(i + 1)}, 32)
	}

	start = time.Now()
	user, err := GenAuxTag(messages, signers, len(messages), pp)
	auxTagTime := float64(time.Since(start).Nanoseconds()) / 1e6
	t.Logf("GenAuxTag took %.3f milliseconds", auxTagTime)
	if err != nil {
		t.Fatalf("GenAuxTag failed: %v", err)
	}

	user.longtermSigs = make([]struct {
		h bls.G1Affine
		s []bls.G1Affine
	}, numSigners)
	for i := 0; i < numSigners; i++ {
		user.longtermSigs[i].s = make([]bls.G1Affine, numSigners)
	}

	user.longtermSigs[0].h = user.pk.hGamma

	currentEpoch := uint64(1)

	start = time.Now()
	signers = EpochKeyGen(pp, signers, int(currentEpoch))
	epochKeygenTime := float64(time.Since(start).Nanoseconds()) / 1e6
	t.Logf("EpochKeyGen took %.3f milliseconds", epochKeygenTime)

	var longSignTotalTime float64
	var epochSignTotalTime float64

	for i := 0; i < numSigners; i++ {
		start = time.Now()
		updatedUser, err := LongSign(&signers[i], user, pp, i)
		longSignTime := float64(time.Since(start).Nanoseconds()) / 1e6
		longSignTotalTime += longSignTime
		if err != nil {
			t.Errorf("LongSign failed for index %d: %v", i, err)
			continue
		}
		user = updatedUser

		start = time.Now()
		user, err = EpochSign(&signers[i], user, pp, i, currentEpoch)
		epochSignTime := float64(time.Since(start).Nanoseconds()) / 1e6
		epochSignTotalTime += epochSignTime
		if err != nil {
			t.Fatalf("EpochSign failed for index %d: %v", i, err)
		}
	}

	t.Logf("Average LongSign took %.3f milliseconds", longSignTotalTime/float64(numSigners))
	t.Logf("Average EpochSign took %.3f milliseconds", epochSignTotalTime/float64(numSigners))

	start = time.Now()
	if err := AggSigAttr(user); err != nil {
		t.Fatalf("AggSigAttr failed: %v", err)
	}
	aggSigAttrTime := float64(time.Since(start).Nanoseconds()) / 1e6
	t.Logf("AggSigAttr took %.3f milliseconds", aggSigAttrTime)

	start = time.Now()
	if err := AggSigEp(user); err != nil {
		t.Fatalf("AggSigEp failed: %v", err)
	}
	aggSigEpTime := float64(time.Since(start).Nanoseconds()) / 1e6
	t.Logf("AggSigEp took %.3f milliseconds", aggSigEpTime)

	start = time.Now()
	aggSig, err := CombAggSig(user)
	combAggSigTime := float64(time.Since(start).Nanoseconds()) / 1e6
	t.Logf("CombAggSig took %.3f milliseconds", combAggSigTime)
	if err != nil {
		t.Fatalf("CombAggSig failed: %v", err)
	}

	if aggSig.h.IsInfinity() || aggSig.s.IsInfinity() {
		t.Error("Combined aggregate signature contains infinity point")
	}

	signerPtrs := convertToSignerPtrs(signers)

	start = time.Now()
	valid, err := AggVerify(currentEpoch, user, signerPtrs, pp)
	verifyTime := float64(time.Since(start).Nanoseconds()) / 1e6
	t.Logf("AggVerify took %.3f milliseconds", verifyTime)

	if err != nil {
		t.Fatalf("AggVerify failed: %v", err)
	}
	if !valid {
		t.Error("Aggregate signature verification failed")
	}

	totalTime := setupTime + keygenTime + auxTagTime + epochKeygenTime +
		longSignTotalTime + epochSignTotalTime + aggSigAttrTime +
		aggSigEpTime + combAggSigTime + verifyTime
	t.Logf("Total execution time: %.3f milliseconds", totalTime)
	t.Logf("Number of signers: %d", numSigners)
}
func TestRandomization(t *testing.T) {
	pp := Setup(128)
	numSigners := 3
	signers := LongKeyGen(pp, numSigners)

	messages := [][]byte{[]byte("msg1"), []byte("msg2"), []byte("msg3")}
	user, err := GenAuxTag(messages, signers, len(messages), pp)
	if err != nil {
		t.Fatalf("GenAuxTag failed: %v", err)
	}

	user.longtermSigs = make([]struct {
		h bls.G1Affine
		s []bls.G1Affine
	}, numSigners)
	for i := 0; i < numSigners; i++ {
		user.longtermSigs[i].s = make([]bls.G1Affine, numSigners)
	}
	user.longtermSigs[0].h = user.pk.hGamma
	user.epochSigs = make([]bls.G1Affine, numSigners)

	currentEpoch := uint64(1)
	signers = EpochKeyGen(pp, signers, int(currentEpoch))

	for i := 0; i < numSigners; i++ {
		var updatedUser *User
		updatedUser, err = LongSign(&signers[i], user, pp, i)
		if err != nil {
			t.Fatalf("LongSign failed for signer %d: %v", i, err)
		}
		user = updatedUser

		user, err = EpochSign(&signers[i], user, pp, i, currentEpoch)
		if err != nil {
			t.Fatalf("EpochSign failed for signer %d: %v", i, err)
		}
	}

	err = AggSigAttr(user)
	if err != nil {
		t.Fatalf("AggSigAttr failed: %v", err)
	}

	err = AggSigEp(user)
	if err != nil {
		t.Fatalf("AggSigEp failed: %v", err)
	}

	_, err = CombAggSig(user)
	if err != nil {
		t.Fatalf("CombAggSig failed: %v", err)
	}

	fmt.Println("User object before randomization:")
	fmt.Printf("user.pk.hGamma is nil: %v\n", user.pk.hGamma.IsInfinity())
	fmt.Printf("user.pk.hDelta is nil: %v\n", user.pk.hDelta.IsInfinity())
	fmt.Printf("user.aggregatedLongSig.h is nil: %v\n", user.aggregatedLongSig.h.IsInfinity())
	fmt.Printf("user.aggregatedLongSig.s is nil: %v\n", user.aggregatedLongSig.s.IsInfinity())

	r, _ := new(fr.Element).SetRandom()
	fmt.Printf("Randomization factor: %v\n", r.String())

	rndSig, rndTag, err := RndSigTag(user, r)
	if err != nil {
		t.Fatalf("RndSigTag failed: %v", err)
	}

	if rndSig.h.IsInfinity() || rndSig.s.IsInfinity() {
		t.Error("Randomized signature contains infinity point")
	}

	if rndTag.hGamma.IsInfinity() || rndTag.hDelta.IsInfinity() {
		t.Error("Randomized tag contains infinity point")
	}

	r2, _ := new(fr.Element).SetRandom()
	fmt.Printf("Second randomization factor: %v\n", r2.String())

	rndSig2, rndTag2, err := RndSigTag(user, r2)
	if err != nil {
		t.Fatalf("Second RndSigTag failed: %v", err)
	}

	if rndSig.h.Equal(&rndSig2.h) && rndSig.s.Equal(&rndSig2.s) {
		t.Error("Different randomization produced same signature")
	}

	if rndTag.hGamma.Equal(&rndTag2.hGamma) && rndTag.hDelta.Equal(&rndTag2.hDelta) {
		t.Error("Different randomization produced same tag")
	}

	fmt.Println("Testing verification with randomized signature...")

	randomizedUser := &User{
		pk: struct {
			hGamma bls.G1Affine
			hDelta bls.G1Affine
		}{
			hGamma: rndTag.hGamma,
			hDelta: rndTag.hDelta,
		},
		aggregatedLongSig: struct {
			h bls.G1Affine
			s bls.G1Affine
		}{
			h: rndSig.h,
			s: rndSig.s,
		},
		aggregatedEpochSig: user.aggregatedEpochSig,
		aux:                user.aux,
		epochSigs:          user.epochSigs,
		longtermSigs:       user.longtermSigs,
	}
	signerPtrs := convertToSignerPtrs(signers)

	valid, verifyErr := AggVerify(currentEpoch, randomizedUser, signerPtrs, pp)
	if verifyErr != nil {
		t.Logf("Verification with randomized signature failed with error: %v", verifyErr)
	} else if !valid {
		t.Logf("Verification with randomized signature returned false")
	} else {
		t.Logf("Verification with randomized signature succeeded")
	}
}

func TestConcurrency(t *testing.T) {
	pp := Setup(128)
	numSigners := 10
	signers := LongKeyGen(pp, numSigners)

	messages := make([][]byte, numSigners)
	for i := range messages {
		messages[i] = []byte(fmt.Sprintf("message%d", i))
	}

	user, _ := GenAuxTag(messages, signers, len(messages), pp)

	var wg sync.WaitGroup
	errChan := make(chan error, numSigners)

	for i := 0; i < numSigners; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			_, err := LongSign(&signers[index], user, pp, index)
			if err != nil {
				errChan <- fmt.Errorf("signer %d failed: %v", index, err)
			}
		}(i)
	}

	wg.Wait()
	close(errChan)

	for err := range errChan {
		t.Errorf("Concurrent signing error: %v", err)
	}

	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	t.Logf("Memory stats after concurrent signing: Alloc = %v MiB", m.Alloc/1024/1024)
}

type Stats struct {
	times []time.Duration
	Mean  float64
	Std   float64
	Min   float64
	Max   float64
}

func NewStats() *Stats {
	return &Stats{
		times: make([]time.Duration, 0),
	}
}

func (s *Stats) Add(t time.Duration) {
	s.times = append(s.times, t)
}

func (s *Stats) Calculate() {
	if len(s.times) == 0 {
		return
	}

	var sum time.Duration
	for _, t := range s.times {
		sum += t
	}
	s.Mean = float64(sum) / float64(len(s.times))

	var variance float64
	for _, t := range s.times {
		diff := float64(t) - s.Mean
		variance += diff * diff
	}
	variance /= float64(len(s.times))
	s.Std = math.Sqrt(variance)

	s.Min = float64(s.times[0])
	s.Max = float64(s.times[0])
	for _, t := range s.times {
		if float64(t) < s.Min {
			s.Min = float64(t)
		}
		if float64(t) > s.Max {
			s.Max = float64(t)
		}
	}
}
func BenchmarkEpochKeyGenBenchc(b *testing.B) {
	signerCounts := []int{32, 64, 128, 256, 4096}
	pp := Setup(128)

	for _, n := range signerCounts {
		b.Run(fmt.Sprintf("Signers_%d", n), func(b *testing.B) {

			signers := make([]*Signer, n)
			for i := 0; i < n; i++ {
				signers[i] = &Signer{}
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				var wg sync.WaitGroup
				wg.Add(n)

				for j := 0; j < n; j++ {
					go func(idx int) {
						defer wg.Done()

						EPochKeyGenBenc(pp, signers[idx], 1)
					}(j)
				}
				wg.Wait()
			}
		})
	}
}

func BenchmarkEpochSignMultipleSigners(b *testing.B) {

	signerCounts := []int{32, 64, 128, 256}

	for _, nSigners := range signerCounts {

		n := nSigners
		b.Run(fmt.Sprintf("Signers_%d", n), func(b *testing.B) {

			var totalSetup, totalLongKeyGen, totalEpochKeyGen, totalGenAuxTag, totalLongSign, totalEpochSign time.Duration

			for i := 0; i < b.N; i++ {

				start := time.Now()
				pp := Setup(128)
				totalSetup += time.Since(start)

				start = time.Now()
				signers := LongKeyGen(pp, n)
				durationLongKeyGen := time.Since(start)
				totalLongKeyGen += durationLongKeyGen

				if len(signers) != n {
					b.Fatalf("期望 %d 个签名者，但得到 %d 个", n, len(signers))
				}

				epoch := 1
				start = time.Now()
				signers = EpochKeyGen(pp, signers, epoch)
				durationEpochKeyGen := time.Since(start)
				totalEpochKeyGen += durationEpochKeyGen

				user := &User{
					longtermSigs: []struct {
						h bls.G1Affine
						s []bls.G1Affine
					}{},
				}

				messages := [][]byte{
					bytes.Repeat([]byte{0x01}, 32), // 32
					bytes.Repeat([]byte{0x02}, 32), // 32
					bytes.Repeat([]byte{0x03}, 32), // 32
				}
				l := len(messages)

				start = time.Now()
				var err error
				user, err = GenAuxTag(messages, signers, l, pp)
				if err != nil {
					b.Fatalf("GenAuxTag faile: %v", err)
				}
				durationGenAuxTag := time.Since(start)
				totalGenAuxTag += durationGenAuxTag

				start = time.Now()
				for j := 0; j < l; j++ {
					updatedUser, err := LongSign(&signers[j], user, pp, j)
					if err != nil {
						b.Fatalf("LongSign index %d fail: %v", j, err)
					}

					if len(user.longtermSigs) <= j || user.longtermSigs[j].h.IsInfinity() {
						b.Errorf("index %d signature invaild", j)
					}
					user = updatedUser
				}
				durationLongSign := time.Since(start)
				totalLongSign += durationLongSign

				start = time.Now()
				user.epochSigs = make([]bls.G1Affine, n)
				totalEpochSign += time.Since(start)

				start = time.Now()
				for j := 0; j < n; j++ {
					epochValue := uint64(epoch)
					aggregatedUser, err := EpochSign(&signers[j], user, pp, j, epochValue)
					if err != nil {
						b.Fatalf("EpochSign signer %d failed: %v", j, err)
					}

					user = aggregatedUser

					if len(user.epochSigs) <= j {
						b.Fatalf("epochSigs 在索引 %d 未初始化", j)
					}

					epochSig := user.epochSigs[j]

					if epochSig.IsInfinity() {
						b.Fatalf("签名者 %d 的 epoch 签名为无穷点", j)
					}

				}
				durationEpochSign := time.Since(start)
				totalEpochSign += durationEpochSign
			}

			avgSetup := float64(totalSetup.Milliseconds()) / float64(b.N)
			avgLongKeyGen := float64(totalLongKeyGen.Milliseconds()) / float64(b.N)
			avgEpochKeyGen := float64(totalEpochKeyGen.Milliseconds()) / float64(b.N)
			avgGenAuxTag := float64(totalGenAuxTag.Milliseconds()) / float64(b.N)
			avgLongSign := float64(totalLongSign.Milliseconds()) / float64(b.N)
			avgEpochSign := float64(totalEpochSign.Milliseconds()) / float64(b.N)

			b.ReportMetric(avgSetup, "setup_ms/op")
			b.ReportMetric(avgLongKeyGen, "long_key_gen_ms/op")
			b.ReportMetric(avgEpochKeyGen, "epoch_key_gen_ms/op")
			b.ReportMetric(avgGenAuxTag, "gen_aux_tag_ms/op")
			b.ReportMetric(avgLongSign, "long_sign_ms/op")
			b.ReportMetric(avgEpochSign, "epoch_sign_ms/op")

			b.Logf("Avg Setup time: %.3f ms/op", avgSetup)
			b.Logf("Avg LongKeyGen time: %.3f ms/op", avgLongKeyGen)
			b.Logf("Avg EpochKeyGen time: %.3f ms/op", avgEpochKeyGen)
			b.Logf("Avg GenAuxTag time: %.3f ms/op", avgGenAuxTag)
			b.Logf("Avg LongSign time: %.3f ms/op", avgLongSign)
			b.Logf("Avg EpochSign time: %.3f ms/op", avgEpochSign)
		})
	}
}

func BenchmarkAllEBPSOperations(b *testing.B) {
	// Define different test scales
	sizes := []int{4, 8, 16, 32, 64, 128} // Reduce sizes to accelerate total runtime

	// Run separate sub-benchmarks for each scale
	for _, size := range sizes {
		b.Run(fmt.Sprintf("Size_%d", size), func(b *testing.B) {
			// Initialize statistics collectors for each operation
			operations := []string{
				"Setup", "LongKeyGen", "EpochKeyGen", "GenAuxTag",
				"LongSign", "EpochSign", "AggSigAttr", "AggSigEp",
				"CombAggSig", "AggVerify", "RndSigTag",
				"IssuerLong", "IssuerEpoch", // Add single signer statistics
			}

			stats := make(map[string]*Stats)
			for _, op := range operations {
				stats[op] = NewStats()
			}

			// Warm-up: Perform one-time system setup
			pp := Setup(128)

			// Reset timer for accurate measurements
			b.ResetTimer()

			// Execute multiple benchmark runs
			for i := 0; i < b.N; i++ {
				// 1. Measure Setup (executed independently each iteration)
				start := time.Now()
				pp = Setup(128)
				stats["Setup"].Add(time.Since(start))

				// 2. Measure LongKeyGen
				start = time.Now()
				signers := LongKeyGen(pp, size)
				stats["LongKeyGen"].Add(time.Since(start))

				// Generate messages matching signer count
				messages := make([][]byte, size)
				for j := range messages {
					messages[j] = bytes.Repeat([]byte{byte(j + 1)}, 32)
				}

				// Set epoch value
				currentEpoch := uint64(1)

				// 3. Measure EpochKeyGen
				start = time.Now()
				signers = EpochKeyGen(pp, signers, int(currentEpoch))
				stats["EpochKeyGen"].Add(time.Since(start))

				// 4. Measure GenAuxTag (using messages matching signer count)
				start = time.Now()
				user, err := GenAuxTag(messages, signers, len(messages), pp)
				if err != nil {
					b.Fatalf("GenAuxTag failed: %v", err)
				}
				stats["GenAuxTag"].Add(time.Since(start))

				// Ensure proper initialization of longtermSigs and epochSigs
				user.longtermSigs = make([]struct {
					h bls.G1Affine
					s []bls.G1Affine
				}, size)
				for j := 0; j < size; j++ {
					user.longtermSigs[j].s = make([]bls.G1Affine, size)
				}
				user.longtermSigs[0].h = user.pk.hGamma
				user.epochSigs = make([]bls.G1Affine, size)

				// 5. Measure single signer LongSign (individual operation)
				userCopy := *user // Simple user copy
				start = time.Now()
				_, err = LongSign(&signers[0], &userCopy, pp, 0)
				if err != nil {
					b.Fatalf("Single signer LongSign failed: %v", err)
				}
				stats["IssuerLong"].Add(time.Since(start))

				// 6. Measure single signer EpochSign (individual operation)
				userCopy = *user // Re-copy user object
				start = time.Now()
				_, err = EpochSign(&signers[0], &userCopy, pp, 0, currentEpoch)
				if err != nil {
					b.Fatalf("Single signer EpochSign failed: %v", err)
				}
				stats["IssuerEpoch"].Add(time.Since(start))

				// 7. Measure LongSign (aggregate time for all signers)
				start = time.Now()
				for j := 0; j < size; j++ {
					user, err = LongSign(&signers[j], user, pp, j)
					if err != nil {
						b.Fatalf("LongSign failed for signer %d: %v", j, err)
					}
				}
				stats["LongSign"].Add(time.Since(start))

				// 8. Measure EpochSign (aggregate time for all signers)
				start = time.Now()
				for j := 0; j < size; j++ {
					user, err = EpochSign(&signers[j], user, pp, j, currentEpoch)
					if err != nil {
						b.Fatalf("EpochSign failed for signer %d: %v", j, err)
					}
				}
				stats["EpochSign"].Add(time.Since(start))

				// 9. Measure AggSigAttr
				start = time.Now()
				err = AggSigAttr(user)
				if err != nil {
					b.Fatalf("AggSigAttr failed: %v", err)
				}
				stats["AggSigAttr"].Add(time.Since(start))

				// 10. Measure AggSigEp
				start = time.Now()
				err = AggSigEp(user)
				if err != nil {
					b.Fatalf("AggSigEp failed: %v", err)
				}
				stats["AggSigEp"].Add(time.Since(start))

				// 11. Measure CombAggSig
				start = time.Now()
				_, err = CombAggSig(user)
				if err != nil {
					b.Fatalf("CombAggSig failed: %v", err)
				}
				stats["CombAggSig"].Add(time.Since(start))

				// Convert signers to pointers for AggVerify
				signerPtrs := make([]*Signer, len(signers))
				for j := range signers {
					signerPtrs[j] = &signers[j]
				}

				// 12. Measure AggVerify
				start = time.Now()
				valid, err := AggVerify(currentEpoch, user, signerPtrs, pp)
				if err != nil {
					b.Fatalf("AggVerify failed: %v", err)
				}
				if !valid {
					b.Fatal("Signature verification failed")
				}
				stats["AggVerify"].Add(time.Since(start))

				// 13. Measure RndSigTag
				r, _ := new(fr.Element).SetRandom()
				start = time.Now()
				_, _, err = RndSigTag(user, r)
				if err != nil {
					b.Fatalf("RndSigTag failed: %v", err)
				}
				stats["RndSigTag"].Add(time.Since(start))
			}

			// Report metrics
			b.ReportMetric(0, "ns/op") // Suppress default metric

			// Output benchmark configuration
			fmt.Printf("\n===== EBPS Benchmark - %d Signers =====\n", size)

			// Format results table
			fmt.Printf("%-25s %-12s %-12s\n", "Operation", "Avg(ms)", "StdDev(ms)")
			fmt.Printf("%-25s %-12s %-12s\n", "=========================", "============", "============")

			// Operation descriptions
			opNames := map[string]string{
				"Setup":       "System Setup",
				"LongKeyGen":  fmt.Sprintf("KeyGen (%d signers)", size),
				"EpochKeyGen": fmt.Sprintf("EpochKeyGen (%d signers)", size),
				"GenAuxTag":   fmt.Sprintf("Aux Tag Gen (%d msgs)", size),
				"LongSign":    fmt.Sprintf("Long Sign (%d signers)", size),
				"EpochSign":   fmt.Sprintf("Epoch Sign (%d signers)", size),
				"AggSigAttr":  fmt.Sprintf("Agg Attr Sigs (%d)", size),
				"AggSigEp":    fmt.Sprintf("Agg Epoch Sigs (%d)", size),
				"CombAggSig":  "Combine Agg Signatures",
				"AggVerify":   fmt.Sprintf("Verify Agg Sig (%d)", size),
				"RndSigTag":   "Randomize Sig & Tag",
				"IssuerLong":  "Single Long Sign",
				"IssuerEpoch": "Single Epoch Sign",
			}

			// Total execution time calculation
			var totalMean, totalStd float64

			// Process main operations
			mainOps := []string{
				"Setup", "LongKeyGen", "EpochKeyGen", "GenAuxTag",
				"LongSign", "EpochSign", "AggSigAttr", "AggSigEp",
				"CombAggSig", "AggVerify", "RndSigTag",
			}

			for _, op := range mainOps {
				stats[op].Calculate()
				meanMs := stats[op].Mean / 1e6
				stdMs := stats[op].Std / 1e6
				totalMean += meanMs
				totalStd += stdMs * stdMs
				fmt.Printf("%-25s %-12.3f %-12.3f\n", opNames[op], meanMs, stdMs)
				b.ReportMetric(meanMs, op+"_ms")
				b.ReportMetric(stdMs, op+"_std_ms")
			}

			// Output totals
			totalStd = math.Sqrt(totalStd)
			fmt.Printf("%-25s %-12.3f %-12.3f\n", "Total", totalMean, totalStd)

			// Per-signer metrics
			fmt.Printf("\nPer-Signer Metrics:\n")
			fmt.Printf("%-25s %-12s %-12s\n", "Operation", "Avg(ms)", "StdDev(ms)")
			fmt.Printf("%-25s %-12s %-12s\n", "=========================", "============", "============")

			// Process individual operations
			for _, op := range []string{"IssuerLong", "IssuerEpoch"} {
				stats[op].Calculate()
				meanMs := stats[op].Mean / 1e6
				stdMs := stats[op].Std / 1e6
				fmt.Printf("%-25s %-12.3f %-12.3f\n", opNames[op], meanMs, stdMs)
				b.ReportMetric(meanMs, op+"_ms")
				b.ReportMetric(stdMs, op+"_std_ms")
			}

			// Calculate per-signer averages
			perSignerLongSign := stats["LongSign"].Mean / 1e6 / float64(size)
			perSignerLongStd := stats["LongSign"].Std / 1e6 / float64(size)
			perSignerEpochSign := stats["EpochSign"].Mean / 1e6 / float64(size)
			perSignerEpochStd := stats["EpochSign"].Std / 1e6 / float64(size)

			fmt.Printf("%-25s %-12.3f %-12.3f\n", "Long-term Signature", perSignerLongSign, perSignerLongStd)
			fmt.Printf("%-25s %-12.3f %-12.3f\n", "Epoch Signature", perSignerEpochSign, perSignerEpochStd)

			// Report final metrics
			b.ReportMetric(totalMean, "total_ms")
			b.ReportMetric(perSignerLongSign, "longsign_per_signer_ms")
			b.ReportMetric(perSignerEpochSign, "epochsign_per_signer_ms")
		})
	}
}

func BenchmarkParallelEpochKeyGen(b *testing.B) {
	signerCounts := []int{32, 64, 128, 256, 512}
	pp := Setup(128)

	for _, n := range signerCounts {
		b.Run(fmt.Sprintf("Signers_%d", n), func(b *testing.B) {
			// Create signers once before benchmark loop
			originalSigners := LongKeyGen(pp, n)
			stats := NewStats()

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// Create working copy of signers
				signers := make([]Signer, n)
				copy(signers, originalSigners)

				start := time.Now()
				var wg sync.WaitGroup
				numWorkers := runtime.NumCPU()
				wg.Add(numWorkers)

				// Distribute work across workers
				batchSize := (n + numWorkers - 1) / numWorkers
				for j := 0; j < numWorkers; j++ {
					go func(startIdx int) {
						defer wg.Done()
						endIdx := minInt(startIdx+batchSize, n)
						for k := startIdx; k < endIdx; k++ {
							EPochKeyGenBenc(pp, &signers[k], i%10)
						}
					}(j * batchSize)
				}
				wg.Wait()
				stats.Add(time.Since(start))
			}

			// Calculate and report results
			stats.Calculate()
			meanMs := stats.Mean / 1e6
			b.ReportMetric(meanMs, "parallel_epoch_keygen_ms/op")
			b.ReportMetric(meanMs/float64(n), "parallel_epoch_keygen_ms/signer")
		})
	}
}

// Custom integer min function
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
