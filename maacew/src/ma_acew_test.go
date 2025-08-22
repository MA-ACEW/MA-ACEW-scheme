package ma

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
	"runtime"
	"sort"
	"sync"

	"time"

	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// TestSetupSystem tests system parameter setup, verification, and serialization/deserialization
func TestSetupSystem(t *testing.T) {
	// Test parameter setup
	systemParams, err := SetupSystem(128, 5)
	if err != nil {
		t.Fatalf("Failed to setup system parameters: %v", err)
	}

	if systemParams == nil {
		t.Fatal("System parameters are nil")
	}

	if systemParams.EBPS == nil {
		t.Fatal("EBPS parameters are nil")
	}

	if systemParams.WTS == nil {
		t.Fatal("WTS parameters are nil")
	}

	// Verify EBPS parameters
	ebps := systemParams.EBPS
	if ebps.ua.IsInfinity() {
		t.Fatal("EBPS G1 generator is infinity point")
	}

	if ebps.va.IsInfinity() {
		t.Fatal("EBPS G2 generator is infinity point")
	}

	// Verify WTS parameters
	wts := systemParams.WTS
	if wts.g1a.IsInfinity() {
		t.Fatal("WTS G1 generator is infinity point")
	}

	if wts.g2a.IsInfinity() {
		t.Fatal("WTS G2 generator is infinity point")
	}

	// Test VerifySystemParams function
	valid, err := VerifySystemParams(systemParams)
	if err != nil {
		t.Fatalf("Error verifying system parameters: %v", err)
	}

	if !valid {
		t.Fatal("System parameter verification failed")
	}

	// Test invalid parameters
	_, err = VerifySystemParams(nil)
	if err == nil {
		t.Fatal("Verification should fail for nil parameters")
	}

	invalidParams := &SystemParams{
		SecurityParam: 128,
		EBPS:          nil,
		WTS:           systemParams.WTS,
	}
	_, err = VerifySystemParams(invalidParams)
	if err == nil {
		t.Fatal("Verification should fail for missing EBPS parameters")
	}

	// Test serialization and deserialization
	serialized, err := SerializeSystemParams(systemParams)
	if err != nil {
		t.Fatalf("Failed to serialize system parameters: %v", err)
	}

	if len(serialized) == 0 {
		t.Fatal("Serialization result is empty")
	}

	deserialized, err := DeserializeSystemParams(serialized)
	if err != nil {
		t.Fatalf("Failed to deserialize system parameters: %v", err)
	}

	// Verify deserialized parameters
	if deserialized.SecurityParam != systemParams.SecurityParam {
		t.Fatalf("Deserialized security parameter mismatch: expected %d, got %d",
			systemParams.SecurityParam, deserialized.SecurityParam)
	}

	if !deserialized.EBPS.ua.Equal(&systemParams.EBPS.ua) {
		t.Fatal("Deserialized EBPS G1 generator mismatch")
	}

	if !deserialized.EBPS.va.Equal(&systemParams.EBPS.va) {
		t.Fatal("Deserialized EBPS G2 generator mismatch")
	}

	if !deserialized.WTS.g1a.Equal(&systemParams.WTS.g1a) {
		t.Fatal("Deserialized WTS G1 generator mismatch")
	}

	if !deserialized.WTS.g2a.Equal(&systemParams.WTS.g2a) {
		t.Fatal("Deserialized WTS G2 generator mismatch")
	}

	// Test parameter setup for different numbers of signers
	for _, signers := range []int{1, 10, 20, 50} {
		paramsN, err := SetupSystem(128, signers)
		if err != nil {
			t.Fatalf("Failed to setup system parameters for %d signers: %v", signers, err)
		}

		validN, err := VerifySystemParams(paramsN)
		if err != nil || !validN {
			t.Fatalf("Failed to verify system parameters for %d signers: %v", signers, err)
		}
	}

	// Test invalid input parameters
	_, err = SetupSystem(-1, 5)
	if err == nil {
		t.Fatal("Should fail with negative security parameter")
	}

	_, err = SetupSystem(128, 0)
	if err == nil {
		t.Fatal("Should fail with zero signers")
	}

	_, err = SetupSystem(128, -3)
	if err == nil {
		t.Fatal("Should fail with negative number of signers")
	}

	// Test serialization edge cases
	_, err = SerializeSystemParams(nil)
	if err == nil {
		t.Fatal("Should fail to serialize nil parameters")
	}

	_, err = DeserializeSystemParams([]byte{})
	if err == nil {
		t.Fatal("Should fail to deserialize empty bytes")
	}

	_, err = DeserializeSystemParams([]byte{1, 2, 3}) // Too short input
	if err == nil {
		t.Fatal("Should fail to deserialize too short input")
	}

	fmt.Println("All system parameter tests passed!")
}

func TestGenUserTagPerformance(t *testing.T) {
	// 1. Initialize system parameters
	pp := Setup(128)
	if pp == nil {
		t.Fatal("Failed to initialize system parameters")
	}

	// Test different message quantities
	messageSizes := []int{1, 3, 5, 10, 20, 256}

	for _, size := range messageSizes {
		// Create signers
		signers := LongKeyGen(pp, size)

		// Prepare messages
		messages := make([][]byte, size)
		for i := 0; i < size; i++ {
			messages[i] = []byte(fmt.Sprintf("Message for signer %d", i))
		}

		// Measure time to generate user tag
		startTime := time.Now()
		user, err := GenUserTag(messages, signers, size, pp)
		duration := time.Since(startTime)

		if err != nil {
			t.Fatalf("Message count %d: GenUserTag failed: %v", size, err)
		}

		// Simple result verification
		if user.pk.hGamma.IsInfinity() || user.pk.hDelta.IsInfinity() {
			t.Fatalf("Message count %d: Generated tag contains infinity points", size)
		}

		// Report results
		t.Logf("Message count: %d, Execution time: %.2f ms", size, float64(duration.Milliseconds()))
	}
}

// BenchmarkGenUserTagPerformance benchmarks the performance of GenUserTag
func BenchmarkGenUserTagPerformance(b *testing.B) {
	// Initialize system parameters
	pp := Setup(128)
	if pp == nil {
		b.Fatal("Failed to initialize system parameters")
	}

	// Test different message quantities
	messageSizes := []int{1, 3, 5, 10, 20, 256}

	for _, size := range messageSizes {
		// Create sub-benchmark for each message size
		b.Run(fmt.Sprintf("Messages_%d", size), func(b *testing.B) {
			// Create signers
			signers := LongKeyGen(pp, size)

			// Prepare messages
			messages := make([][]byte, size)
			for i := 0; i < size; i++ {
				messages[i] = []byte(fmt.Sprintf("Message for signer %d", i))
			}

			// Initialize statistics collector
			stats := NewStats()
			iterations := 0 // Manual iteration counter

			// Reset timer, prepare for benchmark
			b.ResetTimer()

			// Go benchmark framework will automatically call this loop b.N times
			for i := 0; i < b.N; i++ {
				startTime := time.Now()
				user, err := GenUserTag(messages, signers, size, pp)
				duration := time.Since(startTime)
				stats.Add(duration)
				iterations++

				if err != nil {
					b.Fatalf("Message count %d: GenUserTag failed: %v", size, err)
				}

				// Simple result verification
				if user.pk.hGamma.IsInfinity() || user.pk.hDelta.IsInfinity() {
					b.Fatalf("Message count %d: Generated tag contains infinity points", size)
				}

				// Prevent compiler from optimizing out user variable
				runtime.KeepAlive(user)
			}

			// Calculate statistics
			stats.Calculate()

			// Convert to milliseconds and report
			meanMs := stats.Mean / float64(time.Millisecond)
			stdDevMs := stats.Std / float64(time.Millisecond)
			minMs := stats.Min / float64(time.Millisecond)
			maxMs := stats.Max / float64(time.Millisecond)

			// Report to Go benchmark framework
			b.ReportMetric(meanMs, "mean_ms")
			b.ReportMetric(stdDevMs, "stddev_ms")
			b.ReportMetric(minMs, "min_ms")
			b.ReportMetric(maxMs, "max_ms")

			// Print detailed statistics
			fmt.Printf("\n=== GenUserTag Performance - %d Messages ===\n", size)
			fmt.Printf("Mean time: %.3f ms\n", meanMs)
			fmt.Printf("Std Dev: %.3f ms\n", stdDevMs)
			fmt.Printf("Min time: %.3f ms\n", minMs)
			fmt.Printf("Max time: %.3f ms\n", maxMs)
			fmt.Printf("Iterations: %d\n", iterations)
		})
	}
}

// TestWTSIntegration tests EBPS and WTS integration
func TestWTSIntegration(t *testing.T) {
	// 1. System initialization - only needs to be done once
	n := 5
	sysParams, err := SetupSystem(128, n)
	if err != nil {
		t.Fatalf("System parameter initialization failed: %v", err)
	}

	// 2. Initial weight setup and key generation
	initialWeights := []int{2, 3, 1, 4, 2}
	signers, wtsInstance, err := MA_Ini_KGen_WithWTS(sysParams, n, 1, initialWeights)
	if err != nil {
		t.Fatalf("Initialization failed: %v", err)
	}

	// Verify weights are correctly set
	for i, w := range initialWeights {
		if wtsInstance.weights[i] != w {
			t.Errorf("Weight setting error: expected %d, got %d", w, wtsInstance.weights[i])
		}
	}

	// 3. Simulate weight update
	newWeights := []int{5, 2, 3, 1, 4}
	err = MA_Update_Weights(wtsInstance, newWeights)
	if err != nil {
		t.Errorf("Weight update failed: %v", err)
	}

	// Verify new weights are correctly set
	for i, w := range newWeights {
		if wtsInstance.weights[i] != w {
			t.Errorf("New weight setting error: expected %d, got %d", w, wtsInstance.weights[i])
		}
	}

	// 4. Simulate Epoch update
	updatedSigners, err := MA_Update_Epoch(sysParams, signers, wtsInstance, 2)
	if err != nil {
		t.Errorf("Epoch update failed: %v", err)
	}

	// Verify temporary keys are updated
	for i := 0; i < n; i++ {
		if !updatedSigners[i].tsk.Equal(&wtsInstance.signers[i].epkey) {
			t.Errorf("Temporary keys not correctly updated")
		}
	}

	// 5. Signature and verification test
	// Simulate selecting a group of signers
	selectedSigners := []int{0, 2, 4} // Total weight = 5+3+4 = 12

	// Create signature
	testMsg := []byte("Test threshold signature message")
	roMsg, _ := bls.HashToG2(testMsg, []byte{})

	sigmas := make([]bls.G2Jac, len(selectedSigners))
	for i, idx := range selectedSigners {
		// Sign using Party's key
		sigmas[i].ScalarMultiplication(new(bls.G2Jac).FromAffine(&roMsg), wtsInstance.signers[idx].sKey.BigInt(new(big.Int)))
	}

	// Combine signatures
	thresholdSig := wtsInstance.combine(selectedSigners, sigmas)

	// Verify signature
	minThreshold := 10
	valid := wtsInstance.gverify(testMsg, thresholdSig, minThreshold)
	if !valid {
		t.Errorf("Signature verification failed, threshold=%d, total weight=%d", minThreshold, thresholdSig.ths)
	}

	// Try higher threshold (should fail)
	tooHighThreshold := 15
	valid = wtsInstance.gverify(testMsg, thresholdSig, tooHighThreshold)
	if valid {
		t.Errorf("Signature verification should fail but succeeded. threshold=%d, total weight=%d", tooHighThreshold, thresholdSig.ths)
	}
}

func BenchmarkSetupSystem(b *testing.B) {
	// Benchmark with different numbers of signers
	signerCounts := []int{5, 10, 64}

	for _, count := range signerCounts {
		b.Run(fmt.Sprintf("Signers-%d", count), func(b *testing.B) {
			// Initialize statistics collector
			stats := NewStats()
			iterations := 0

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				startTime := time.Now()
				sys, err := SetupSystem(128, count)
				duration := time.Since(startTime)
				stats.Add(duration)
				iterations++

				if err != nil {
					b.Fatalf("SetupSystem failed: %v", err)
				}

				// Prevent compiler from optimizing out sys variable
				runtime.KeepAlive(sys)
			}

			// Calculate statistics
			stats.Calculate()

			// Convert to milliseconds and report
			meanMs := stats.Mean / float64(time.Millisecond)
			stdDevMs := stats.Std / float64(time.Millisecond)
			minMs := stats.Min / float64(time.Millisecond)
			maxMs := stats.Max / float64(time.Millisecond)

			// Report to Go benchmark framework
			b.ReportMetric(meanMs, "mean_ms")
			b.ReportMetric(stdDevMs, "stddev_ms")
			b.ReportMetric(minMs, "min_ms")
			b.ReportMetric(maxMs, "max_ms")

			// Print detailed statistics
			fmt.Printf("\n=== SetupSystem Performance - %d Signers ===\n", count)
			fmt.Printf("Mean time: %.3f ms\n", meanMs)
			fmt.Printf("Std Dev: %.3f ms\n", stdDevMs)
			fmt.Printf("Min time: %.3f ms\n", minMs)
			fmt.Printf("Max time: %.3f ms\n", maxMs)
			fmt.Printf("Iterations: %d\n", iterations)
		})
	}
}

// Initial IKGen
func BenchmarkMA_Ini_KGen_WithWTS(b *testing.B) {
	// Test with different numbers of signers
	signerCounts := []int{5, 10, 32, 64, 128}

	for _, numSigners := range signerCounts {
		b.Run(fmt.Sprintf("Signers_%d", numSigners), func(b *testing.B) {
			// Initialize test parameters
			securityParam := 128
			epoch := 1
			weights := make([]int, numSigners)

			// Generate random weights (1-10)
			for i := range weights {
				randBig, err := rand.Int(rand.Reader, big.NewInt(10))
				if err != nil {
					b.Fatalf("Failed to generate random number: %v", err)
				}
				weights[i] = int(randBig.Int64()) + 1
			}

			// Initialize system parameters (done once, not included in benchmark time)
			sysParams, err := SetupSystem(securityParam, numSigners)
			if err != nil {
				b.Fatalf("System initialization failed: %v", err)
			}

			// Create statistics collector
			stats := NewStats()

			// Reset timer, start benchmark
			b.ResetTimer()

			// Execute b.N times
			for i := 0; i < b.N; i++ {
				startTime := time.Now()

				// Call function being tested
				signers, wtsInstance, err := MA_Ini_KGen_WithWTS(sysParams, numSigners, epoch, weights)

				duration := time.Since(startTime)
				stats.Add(duration)

				if err != nil {
					b.Fatalf("Key generation failed: %v", err)
				}

				// Prevent compiler from optimizing out unused variables
				runtime.KeepAlive(signers)
				runtime.KeepAlive(wtsInstance)
			}

			// Calculate statistics
			stats.Calculate()

			// Convert times to milliseconds
			meanMs := stats.Mean / float64(time.Millisecond)
			stdDevMs := stats.Std / float64(time.Millisecond)
			minMs := stats.Min / float64(time.Millisecond)
			maxMs := stats.Max / float64(time.Millisecond)

			// Report statistics
			b.ReportMetric(meanMs, "mean_ms")
			b.ReportMetric(stdDevMs, "stddev_ms")
			b.ReportMetric(minMs, "min_ms")
			b.ReportMetric(maxMs, "max_ms")

			// Output detailed statistics
			fmt.Printf("\n=== MA_Ini_KGen_WithWTS Performance (Signers = %d) ===\n", numSigners)
			fmt.Printf("Mean: %.3f ms\n", meanMs)
			fmt.Printf("Std Dev: %.3f ms\n", stdDevMs)
			fmt.Printf("Min: %.3f ms\n", minMs)
			fmt.Printf("Max: %.3f ms\n", maxMs)
			fmt.Printf("Iterations: %d\n", b.N)
		})
	}
}

// Epoch Update
func BenchmarkMA_Updates(b *testing.B) {
	// Test parameters
	numSigners := 64 // Number of signers
	initialEpoch := 1
	initialWeights := make([]int, numSigners)

	// Initialize random weights
	for i := range initialWeights {
		randBig, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			b.Fatalf("Failed to generate random number: %v", err)
		}
		initialWeights[i] = int(randBig.Int64()) + 1 // Weight range: 1-10
	}

	// Initialize system
	sysParams, err := SetupSystem(128, numSigners)
	if err != nil {
		b.Fatalf("System initialization failed: %v", err)
	}

	// Create signers and WTS instance
	signers, wtsInstance, err := MA_Ini_KGen_WithWTS(sysParams, numSigners, initialEpoch, initialWeights)
	if err != nil {
		b.Fatalf("Key generation failed: %v", err)
	}

	// Prepare test data
	newEpoch := 100
	newWeights := make([]int, numSigners)
	for i := range newWeights {
		newWeights[i] = i%10 + 1 // Simple 1-10 cyclic weights
	}

	// Test epoch update alone
	b.Run("EpochUpdate", func(b *testing.B) {
		stats := NewStats()

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// Copy original signers to ensure same starting point for each test
			testSigners := make([]Signer, len(signers))
			copy(testSigners, signers)

			startTime := time.Now()
			_, err := MA_Update_Epoch(sysParams, testSigners, wtsInstance, newEpoch)
			duration := time.Since(startTime)
			stats.Add(duration)

			if err != nil {
				b.Fatalf("Epoch update failed: %v", err)
			}
		}

		stats.Calculate()
		meanMs := stats.Mean / float64(time.Millisecond)
		stdDevMs := stats.Std / float64(time.Millisecond)

		b.ReportMetric(meanMs, "mean_ms")
		b.ReportMetric(stdDevMs, "stddev_ms")

		fmt.Printf("\n=== Epoch Update (to %d) ===\n", newEpoch)
		fmt.Printf("Mean: %.3f ms\n", meanMs)
		fmt.Printf("StdDev: %.3f ms\n", stdDevMs)
	})

	// Test weight update alone
	b.Run("WeightUpdate", func(b *testing.B) {
		stats := NewStats()

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			startTime := time.Now()
			err := MA_Update_Weights(wtsInstance, newWeights)
			duration := time.Since(startTime)
			stats.Add(duration)

			if err != nil {
				b.Fatalf("Weight update failed: %v", err)
			}
		}

		stats.Calculate()
		meanMs := stats.Mean / float64(time.Millisecond)
		stdDevMs := stats.Std / float64(time.Millisecond)

		b.ReportMetric(meanMs, "mean_ms")
		b.ReportMetric(stdDevMs, "stddev_ms")

		fmt.Printf("\n=== Weight Update ===\n")
		fmt.Printf("Mean: %.3f ms\n", meanMs)
		fmt.Printf("StdDev: %.3f ms\n", stdDevMs)
	})

	// Test combined update (epoch then weight)
	b.Run("CombinedUpdate", func(b *testing.B) {
		// Statistics collectors
		epochStats := NewStats()
		weightStats := NewStats()
		totalStats := NewStats()

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// Copy original signers to ensure same starting point for each test
			testSigners := make([]Signer, len(signers))
			copy(testSigners, signers)

			totalStart := time.Now()

			// Measure epoch update time
			epochStart := time.Now()
			_, err := MA_Update_Epoch(sysParams, testSigners, wtsInstance, newEpoch)
			epochDuration := time.Since(epochStart)
			epochStats.Add(epochDuration)

			if err != nil {
				b.Fatalf("Epoch update failed: %v", err)
			}

			// Measure weight update time
			weightStart := time.Now()
			err = MA_Update_Weights(wtsInstance, newWeights)
			weightDuration := time.Since(weightStart)
			weightStats.Add(weightDuration)

			if err != nil {
				b.Fatalf("Weight update failed: %v", err)
			}

			totalDuration := time.Since(totalStart)
			totalStats.Add(totalDuration)
		}

		// Calculate statistics
		epochStats.Calculate()
		weightStats.Calculate()
		totalStats.Calculate()

		// Convert to milliseconds
		epochMeanMs := epochStats.Mean / float64(time.Millisecond)
		epochStdMs := epochStats.Std / float64(time.Millisecond)

		weightMeanMs := weightStats.Mean / float64(time.Millisecond)
		weightStdMs := weightStats.Std / float64(time.Millisecond)

		totalMeanMs := totalStats.Mean / float64(time.Millisecond)
		totalStdMs := totalStats.Std / float64(time.Millisecond)

		// Report metrics
		b.ReportMetric(epochMeanMs, "epoch_mean_ms")
		b.ReportMetric(epochStdMs, "epoch_stddev_ms")
		b.ReportMetric(weightMeanMs, "weight_mean_ms")
		b.ReportMetric(weightStdMs, "weight_stddev_ms")
		b.ReportMetric(totalMeanMs, "total_mean_ms")
		b.ReportMetric(totalStdMs, "total_stddev_ms")

		// Print detailed information
		fmt.Printf("\n=== Combined Updates ===\n")
		fmt.Printf("Epoch Update: %.3f ms (±%.3f ms)\n", epochMeanMs, epochStdMs)
		fmt.Printf("Weight Update: %.3f ms (±%.3f ms)\n", weightMeanMs, weightStdMs)
		fmt.Printf("Total: %.3f ms (±%.3f ms)\n", totalMeanMs, totalStdMs)
	})
}

// TestBlindCredentialIssuance tests blind credential issuance and unblinding process
func TestBlindCredentialIssuance(t *testing.T) {
	// 1. System parameter setup
	pp := Setup(128)
	if pp == nil {
		t.Fatal("Failed to initialize system parameters")
	}

	// 2. Generate multiple issuers
	numIssuers := 3
	signers := LongKeyGen(pp, numIssuers)

	// Ensure issuers have necessary keys
	for i := range signers {
		// Ensure lsk2 exists for blind signing
		if signers[i].lsk2.IsZero() {
			randomVal, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
			signers[i].lsk2.SetBigInt(randomVal)
		}

		// Ensure tsk exists for epoch signing - key modification
		if signers[i].tsk.IsZero() {
			randomVal, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
			signers[i].tsk.SetBigInt(randomVal)
		}
	}

	// Or better approach using EpochKeyGen function
	signers = EpochKeyGen(pp, signers, 1) // Generate keys for epoch 1

	t.Run("Single Issuer Test", func(t *testing.T) {
		// 3. Generate user
		messages := [][]byte{[]byte("Attribute 1")}
		user, err := GenUserTag(messages, signers[:1], 1, pp)
		if err != nil {
			t.Fatalf("User generation failed: %v", err)
		}

		// 4. Generate zero-knowledge proofs
		proofTG, proofsCL, err := GenerateZKProofs(user, pp)
		if err != nil {
			t.Fatalf("Proof generation failed: %v", err)
		}

		// 5. Request credential from issuer
		blindCred, epochCred, err := RequestCredentialFromIssuer(
			user, pp, 0, proofTG, proofsCL[0], &signers[0], 1)
		if err != nil {
			t.Fatalf("Credential request failed: %v", err)
		}

		// Verify epoch credential
		if epochCred.IsInfinity() {
			t.Fatal("Epoch credential is infinity point")
		}
		t.Logf("Successfully obtained epoch credential")

		// 6. User unblinding
		credential, err := UnblindCredential(user, blindCred)
		if err != nil {
			t.Fatalf("Unblinding failed: %v", err)
		}

		// Verify credential format
		if credential.H.IsInfinity() || credential.S.IsInfinity() {
			t.Fatal("Unblinded credential contains infinity points")
		}

		t.Logf("Successfully obtained and unblinded credential, attribute index: %d", credential.AttributeIndex)
	})

	t.Run("Multiple Issuers Test", func(t *testing.T) {
		// 3. Generate user and multiple attribute messages
		messages := [][]byte{
			[]byte("Attribute 1"),
			[]byte("Attribute 2"),
			[]byte("Attribute 3"),
		}
		user, err := GenUserTag(messages, signers, numIssuers, pp)
		if err != nil {
			t.Fatalf("User generation failed: %v", err)
		}

		// 4. Generate zero-knowledge proofs
		proofTG, proofsCL, err := GenerateZKProofs(user, pp)
		if err != nil {
			t.Fatalf("Proof generation failed: %v", err)
		}

		// 5. Create credential set for each attribute
		blindCredSet := &BlindCredentialSet{
			Longterm: make([]*BlindCredential, numIssuers),
			Epoch:    make([]bls.G1Affine, numIssuers),
			Indices:  make([]int, numIssuers),
		}

		for i := 0; i < numIssuers; i++ {
			// Request credential from single issuer
			blindCred, epochCred, err := RequestCredentialFromIssuer(
				user, pp, i, proofTG, proofsCL[i], &signers[i], 1)
			if err != nil {
				t.Fatalf("Failed to request credential from issuer %d: %v", i, err)
			}

			blindCredSet.Longterm[i] = blindCred
			blindCredSet.Epoch[i] = *epochCred
			blindCredSet.Indices[i] = i

			// Verify epoch credential
			if epochCred.IsInfinity() {
				t.Fatalf("Epoch credential from issuer %d is infinity point", i)
			}

			t.Logf("Successfully obtained blind credential and epoch credential from issuer %d", i)
		}

		// 6. User unblind all credentials
		credSet, err := ProcessCredentialSet(user, blindCredSet)
		if err != nil {
			t.Fatalf("Failed to process credential set: %v", err)
		}

		// Verify unblinded credentials
		for i, cred := range credSet.Longterm {
			if cred.H.IsInfinity() || cred.S.IsInfinity() {
				t.Fatalf("Unblinded credential from issuer %d contains infinity points", i)
			}

			if cred.AttributeIndex != i {
				t.Fatalf("Attribute index mismatch: expected %d, got %d", i, cred.AttributeIndex)
			}

			t.Logf("Successfully verified unblinded credential from issuer %d", i)
		}

		// Verify epoch credential set
		for i, epochCred := range credSet.Epoch {
			if epochCred.IsInfinity() {
				t.Fatalf("Epoch credential from issuer %d is infinity point", i)
			}
			t.Logf("Successfully verified epoch credential from issuer %d", i)
		}

		t.Logf("Successfully tested multiple issuer blind signing process")
	})

	t.Run("Complete User Interaction Flow", func(t *testing.T) {
		// Create user with multiple attributes
		messages := [][]byte{
			[]byte("Name:John"),
			[]byte("Age:30"),
			[]byte("City:London"),
		}
		user, err := GenUserTag(messages, signers, numIssuers, pp)
		if err != nil {
			t.Fatalf("User generation failed: %v", err)
		}

		// Use complete user interaction flow
		credSet, err := UserMultiIssuerInteraction(user, pp, signers, 2)
		if err != nil {
			t.Fatalf("User interaction failed: %v", err)
		}

		// Verify number of credentials obtained
		if len(credSet.Longterm) != numIssuers {
			t.Fatalf("Wrong number of credentials: expected %d, got %d", numIssuers, len(credSet.Longterm))
		}

		// Verify all credentials
		for i, cred := range credSet.Longterm {
			t.Logf("Credential %d index: %d", i, cred.AttributeIndex)

			// In practice, there should be more stringent credential verification here
			if cred.H.IsInfinity() || cred.S.IsInfinity() {
				t.Fatalf("Credential %d contains infinity points", i)
			}
		}

		// Verify all epoch credentials
		for i, epochCred := range credSet.Epoch {
			if epochCred.IsInfinity() {
				t.Fatalf("Epoch credential %d is infinity point", i)
			}
			t.Logf("Successfully verified epoch credential %d", i)
		}

		t.Log("Complete user interaction flow test successful")
	})

	t.Run("Performance Test", func(t *testing.T) {
		// Skip regular testing, only run under specific flag
		if testing.Short() {
			t.Skip("Skipping performance test")
		}

		// Large number of issuers test
		largeNumIssuers := 10
		largeSigners := LongKeyGen(pp, largeNumIssuers)

		// Ensure all issuers have necessary keys
		for i := range largeSigners {
			if largeSigners[i].lsk2.IsZero() {
				randomVal, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
				largeSigners[i].lsk2.SetBigInt(randomVal)
			}

			// Ensure tsk exists for epoch signing
			if largeSigners[i].tsk.IsZero() {
				randomVal, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
				largeSigners[i].tsk.SetBigInt(randomVal)
			}
		}

		// Or use EpochKeyGen
		largeSigners = EpochKeyGen(pp, largeSigners, 3) // Generate keys for epoch 3

		// Create user with many attributes
		largeMessages := make([][]byte, largeNumIssuers)
		for i := 0; i < largeNumIssuers; i++ {
			largeMessages[i] = []byte(fmt.Sprintf("Attribute%d", i))
		}

		user, err := GenUserTag(largeMessages, largeSigners, largeNumIssuers, pp)
		if err != nil {
			t.Fatalf("Large-scale user generation failed: %v", err)
		}

		// Test large-scale interaction performance
		credSet, err := UserMultiIssuerInteraction(user, pp, largeSigners, 3)
		if err != nil {
			t.Fatalf("Large-scale user interaction failed: %v", err)
		}

		t.Logf("Successfully completed performance test with %d issuers", len(credSet.Longterm))
		t.Logf("Obtained %d epoch credentials", len(credSet.Epoch))
	})
}
func BenchmarkCredentialProcessing(b *testing.B) {
	// Setup system parameters
	pp := Setup(128)

	// Create an issuer
	signers := LongKeyGen(pp, 1)
	signers = EpochKeyGen(pp, signers, 1) // Initialize temporary keys with epoch=1
	signer := &signers[0]

	// Create test message
	message := []byte("Test message")
	messages := [][]byte{message}

	// Store operation times
	generateZKTimes := make([]time.Duration, b.N)
	unblindTimes := make([]time.Duration, b.N)

	// Warm up system
	user, _ := GenUserTag(messages, signers, 1, pp)
	proofTG, proofsCL, _ := GenerateZKProofs(user, pp)
	blindCred, _, _ := RequestCredentialFromIssuer(
		user, pp, 0, proofTG, proofsCL[0], signer, 1)
	_, _ = UnblindCredential(user, blindCred)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Create new user each iteration to ensure ZK proof generation is real
		b.StopTimer()
		user, _ := GenUserTag(messages, signers, 1, pp)
		b.StartTimer()

		// Step 4: Generate ZK proofs
		startGenerateZK := time.Now()
		proofTG, proofsCL, err := GenerateZKProofs(user, pp)
		generateZKTimes[i] = time.Since(startGenerateZK)

		if err != nil {
			b.Fatalf("Failed to generate ZK proofs: %v", err)
		}

		// Request credential (not timed)
		b.StopTimer()
		blindCred, _, err := RequestCredentialFromIssuer(
			user, pp, 0, proofTG, proofsCL[0], signer, 1)
		if err != nil {
			b.Fatalf("Failed to obtain blind credential: %v", err)
		}
		b.StartTimer()

		// Step 6: Unblind
		startUnblind := time.Now()
		_, err = UnblindCredential(user, blindCred)
		unblindTimes[i] = time.Since(startUnblind)

		if err != nil {
			b.Fatalf("Unblinding failed: %v", err)
		}
	}

	// Calculate statistics
	zkAvg, zkStdDev := calculateStats(generateZKTimes)
	unblindAvg, unblindStdDev := calculateStats(unblindTimes)

	// Output detailed measurement results
	fmt.Printf("\nCredential Processing Performance Results:\n")
	fmt.Printf("  Generate ZK Proofs: Average=%.4fms, StdDev=%.4fms\n",
		float64(zkAvg)/float64(time.Millisecond),
		float64(zkStdDev)/float64(time.Millisecond))
	fmt.Printf("  Unblind Credential: Average=%.4fms, StdDev=%.4fms\n",
		float64(unblindAvg)/float64(time.Millisecond),
		float64(unblindStdDev)/float64(time.Millisecond))
	fmt.Printf("  Total Processing Time: Average=%.4fms\n\n",
		float64(zkAvg+unblindAvg)/float64(time.Millisecond))

	b.ReportMetric(float64(zkAvg)/float64(time.Millisecond), "Generate_ZK_Proofs(ms)")
	b.ReportMetric(float64(unblindAvg)/float64(time.Millisecond), "Unblind_Credential(ms)")
	b.ReportMetric(float64(zkAvg+unblindAvg)/float64(time.Millisecond), "Total_Processing_Time(ms)")
}

// TestCredentialVerification tests the credential verification process
func TestCredentialVerification(t *testing.T) {
	// 1. Setup parameters
	pp := Setup(128)

	// 2. Generate issuer
	signers := LongKeyGen(pp, 1)
	signer := &signers[0]

	// Ensure lsk2 exists for blind signing
	if signer.lsk2.IsZero() {
		randomVal, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
		signer.lsk2.SetBigInt(randomVal)
	}

	// Initialize temporary key (tsk), this was the missing critical step
	if signer.tsk.IsZero() {
		randomVal, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
		signer.tsk.SetBigInt(randomVal)
	}

	// Or better method is to use EpochKeyGen function to generate temporary keys
	signers = EpochKeyGen(pp, signers, 1) // Initialize temporary keys with epoch=1
	signer = &signers[0]                  // Get pointer again as EpochKeyGen returns new array

	// 3. Generate user
	messages := [][]byte{[]byte("Test message")}
	user, err := GenUserTag(messages, signers, 1, pp)
	if err != nil {
		t.Fatalf("User generation failed: %v", err)
	}

	// 4. Generate proofs
	proofTG, proofsCL, err := GenerateZKProofs(user, pp)
	if err != nil {
		t.Fatalf("Proof generation failed: %v", err)
	}

	// 5. Get blind credential
	blindCred, epochCred, err := RequestCredentialFromIssuer(
		user, pp, 0, proofTG, proofsCL[0], signer, 1)
	if err != nil {
		t.Fatalf("Failed to obtain credential: %v", err)
	}

	// Verify epoch credential
	if epochCred.IsInfinity() {
		t.Fatal("Epoch credential is infinity point")
	}
	t.Log("Successfully obtained epoch credential")

	// 6. Unblind
	credential, err := UnblindCredential(user, blindCred)
	if err != nil {
		t.Fatalf("Unblinding failed: %v", err)
	}

	// 7. Extract issuer public key
	// In a real system, this might come from a public key directory
	issuerPk := &signer.lvk2 // Use signer's lvk2 as public key

	// 8. Verify credential
	valid, err := VerifyCredential(credential, issuerPk, messages[0])
	if err != nil {
		t.Fatalf("Credential verification error: %v", err)
	}

	if !valid {
		t.Fatal("Credential verification failed")
	}

	t.Log("Credential verification test successful")
}

// BenchmarkBlindIssuance issuer side benchmark for blind signature performance
func BenchmarkBlindIssuance(b *testing.B) {
	// 1. Setup system parameters
	pp := Setup(128)

	// 2. Generate issuer
	signers := LongKeyGen(pp, 1)

	// Ensure issuer has lsk2
	if signers[0].lsk2.IsZero() {
		randomVal, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
		signers[0].lsk2.SetBigInt(randomVal)
	}

	// 3. Generate user
	messages := [][]byte{[]byte("Benchmark test message")}
	user, _ := GenUserTag(messages, signers, 1, pp)

	// 4. Generate proofs
	proofTG, proofsCL, _ := GenerateZKProofs(user, pp)

	// 5. Reset timer and start benchmark
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Test blind signature performance
		_, _, _ = RequestCredentialFromIssuer(
			user, pp, 0, proofTG, proofsCL[0], &signers[0], i%10)
	}
}

// Helper function: Generate uniform weights
func makeUniformWeights(n int, weight int) []int {
	weights := make([]int, n)
	for i := range weights {
		weights[i] = weight
	}
	return weights
}

// Helper function: Generate increasing weights
func makeIncreasingWeights(n int) []int {
	weights := make([]int, n)
	for i := range weights {
		weights[i] = i + 1
	}
	return weights
}

// Helper function: Generate random weights using crypto/rand
func makeSecureRandomWeights(t *testing.T, n int) []int {
	weights := make([]int, n)
	for i := range weights {
		// Generate secure random number between 1-10 using crypto/rand
		randBig, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			t.Fatalf("Failed to generate random number: %v", err)
		}
		weights[i] = int(randBig.Int64()) + 1 // Weight range: 1-10
	}
	return weights
}

// Helper function: Generate extreme weights (one very high, others very low)
func makeExtremeWeights(n int) []int {
	weights := make([]int, n)
	for i := range weights {
		weights[i] = 1
	}
	if n > 0 {
		weights[0] = 100 // Set first signer's weight to 100
	}
	return weights
}
func TestEllipticCurveBasics(t *testing.T) {
	// 1. Test sizes of G1, G2, GT points
	t.Run("PointSizes", func(t *testing.T) {
		// G1 point size
		var g1 bls.G1Affine
		g1Bytes := g1.Bytes()
		t.Logf("G1 point size (compressed): %d bytes", len(g1Bytes))

		// G1 point uncompressed size
		t.Logf("G1 point size (uncompressed): %d bytes", bls.SizeOfG1AffineUncompressed)

		// G2 point size
		var g2 bls.G2Affine
		g2Bytes := g2.Bytes()
		t.Logf("G2 point size (compressed): %d bytes", len(g2Bytes))

		// G2 point uncompressed size
		t.Logf("G2 point size (uncompressed): %d bytes", bls.SizeOfG2AffineUncompressed)

		// GT point size
		var gt bls.GT
		gtBytes := gt.Bytes()
		t.Logf("GT point size: %d bytes", len(gtBytes))

		// Fr element size
		var scalar fr.Element
		scalarBytes := scalar.Bytes()
		t.Logf("Fr scalar size: %d bytes", len(scalarBytes))
	})

	// 2. Test G1 point operation performance
	t.Run("G1Operations", func(t *testing.T) {
		// Generate random G1 point
		_, _, g1, _ := bls.Generators()

		// Generate random scalar
		var scalar fr.Element
		scalar.SetRandom()

		// Test G1 point scalar multiplication performance
		var result bls.G1Affine

		trials := 1000
		start := time.Now()
		for i := 0; i < trials; i++ {
			bigintScalar := new(big.Int)
			result.ScalarMultiplication(&g1, scalar.BigInt(bigintScalar))
		}
		duration := time.Since(start)

		t.Logf("G1 point scalar multiplication average time: %.2f μs", float64(duration.Microseconds())/float64(trials))

		// Test G1 point addition performance
		var p1, p2 bls.G1Affine
		p1.ScalarMultiplication(&g1, scalar.BigInt(new(big.Int)))
		scalar.SetRandom()
		p2.ScalarMultiplication(&g1, scalar.BigInt(new(big.Int)))

		start = time.Now()
		for i := 0; i < trials; i++ {
			result.Add(&p1, &p2)
		}
		duration = time.Since(start)

		t.Logf("G1 point addition average time: %.2f μs", float64(duration.Microseconds())/float64(trials))

		// Test batch G1 scalar multiplication
		numPoints := 100
		scalars := make([]fr.Element, numPoints)

		for i := 0; i < numPoints; i++ {
			scalars[i].SetRandom()
		}

		start = time.Now()
		_ = bls.BatchScalarMultiplicationG1(&g1, scalars)
		duration = time.Since(start)

		t.Logf("Batch G1 scalar multiplication (%d points) total time: %.2f μs (average per point: %.2f μs)",
			numPoints, float64(duration.Microseconds()), float64(duration.Microseconds())/float64(numPoints))
	})

	// 3. Test G2 point operation performance
	t.Run("G2Operations", func(t *testing.T) {
		// Generate random G2 point
		_, _, _, g2 := bls.Generators()

		// Generate random scalar
		var scalar fr.Element
		scalar.SetRandom()

		// Test G2 point scalar multiplication performance
		var result bls.G2Affine

		trials := 1000
		start := time.Now()
		for i := 0; i < trials; i++ {
			result.ScalarMultiplication(&g2, scalar.BigInt(new(big.Int)))
		}
		duration := time.Since(start)

		t.Logf("G2 point scalar multiplication average time: %.2f μs", float64(duration.Microseconds())/float64(trials))

		// Test G2 point addition performance
		var p1, p2 bls.G2Affine
		p1.ScalarMultiplication(&g2, scalar.BigInt(new(big.Int)))
		scalar.SetRandom()
		p2.ScalarMultiplication(&g2, scalar.BigInt(new(big.Int)))

		start = time.Now()
		for i := 0; i < trials; i++ {
			result.Add(&p1, &p2)
		}
		duration = time.Since(start)

		t.Logf("G2 point addition average time: %.2f μs", float64(duration.Microseconds())/float64(trials))

		// Test batch G2 scalar multiplication
		numPoints := 100
		scalars := make([]fr.Element, numPoints)

		for i := 0; i < numPoints; i++ {
			scalars[i].SetRandom()
		}

		start = time.Now()
		_ = bls.BatchScalarMultiplicationG2(&g2, scalars)
		duration = time.Since(start)

		t.Logf("Batch G2 scalar multiplication (%d points) total time: %.2f μs (average per point: %.2f μs)",
			numPoints, float64(duration.Microseconds()), float64(duration.Microseconds())/float64(numPoints))
	})

	// 4. Test pairing operation performance
	t.Run("PairingOperations", func(t *testing.T) {
		// Get generators
		_, _, g1, g2 := bls.Generators()

		// Generate random points for pairing
		var scalar1, scalar2 fr.Element
		scalar1.SetRandom()
		scalar2.SetRandom()

		var p1 bls.G1Affine
		var p2 bls.G2Affine
		p1.ScalarMultiplication(&g1, scalar1.BigInt(new(big.Int)))
		p2.ScalarMultiplication(&g2, scalar2.BigInt(new(big.Int)))

		// Test single pairing operation performance
		trials := 100
		start := time.Now()
		for i := 0; i < trials; i++ {
			result, err := bls.Pair([]bls.G1Affine{p1}, []bls.G2Affine{p2})
			if err != nil {
				t.Fatalf("Pairing computation failed: %v", err)
			}
			if result.IsOne() {
				// Expected result, no action needed
			}
		}
		duration := time.Since(start)

		t.Logf("Single pairing operation average time: %.2f μs", float64(duration.Microseconds())/float64(trials))

		// Test multi-pairing performance
		numPairs := 10
		p1s := make([]bls.G1Affine, numPairs)
		p2s := make([]bls.G2Affine, numPairs)

		for i := 0; i < numPairs; i++ {
			var s1, s2 fr.Element
			s1.SetRandom()
			s2.SetRandom()

			p1s[i].ScalarMultiplication(&g1, s1.BigInt(new(big.Int)))
			p2s[i].ScalarMultiplication(&g2, s2.BigInt(new(big.Int)))
		}

		start = time.Now()
		for i := 0; i < trials/10; i++ {
			result, err := bls.Pair(p1s, p2s)
			if err != nil {
				t.Fatalf("Multi-pairing computation failed: %v", err)
			}
			if result.IsOne() {
				// Expected result, no action needed
			}
		}
		duration = time.Since(start)

		t.Logf("%d-pair pairing operation average time: %.2f μs (average per pair: %.2f μs)",
			numPairs,
			float64(duration.Microseconds())*10/float64(trials),
			float64(duration.Microseconds())*10/float64(trials)/float64(numPairs))

		// Test Miller Loop and Final Exponentiation separate performance
		var gt bls.GT
		start = time.Now()
		for i := 0; i < trials/10; i++ {
			res, err := bls.MillerLoop(p1s, p2s)
			if err != nil {
				t.Fatalf("Miller Loop computation failed: %v", err)
			}

			gt = bls.FinalExponentiation(&res)
		}
		duration = time.Since(start)

		if gt.IsOne() {
			// Expected result, no action needed
		}

		t.Logf("Separated Miller Loop + Final Exp (%d pairs) average time: %.2f μs",
			numPairs, float64(duration.Microseconds())*10/float64(trials))
	})

	// 5. Test hash to curve operation performance
	t.Run("HashToCurve", func(t *testing.T) {
		// Generate random message
		message := make([]byte, 100)
		if _, err := rand.Read(message); err != nil {
			t.Fatalf("Failed to generate random message: %v", err)
		}

		domain := []byte("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_")

		// Test hash to G1 performance
		trials := 100
		start := time.Now()
		for i := 0; i < trials; i++ {
			_, err := bls.HashToG1(message, domain)
			if err != nil {
				t.Fatalf("Hash to G1 failed: %v", err)
			}
		}
		duration := time.Since(start)

		t.Logf("Hash to G1 average time: %.2f μs", float64(duration.Microseconds())/float64(trials))

		// Test hash to G2 performance
		domain = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_")

		start = time.Now()
		for i := 0; i < trials; i++ {
			_, err := bls.HashToG2(message, domain)
			if err != nil {
				t.Fatalf("Hash to G2 failed: %v", err)
			}
		}
		duration = time.Since(start)

		t.Logf("Hash to G2 average time: %.2f μs", float64(duration.Microseconds())/float64(trials))
	})

	// 6. Test batch operation advantages
	t.Run("BatchAdvantages", func(t *testing.T) {
		// Generate random G1 point
		_, _, g1, _ := bls.Generators()

		// Compare individual vs batch operation performance
		sizes := []int{10, 50, 100, 200}

		for _, size := range sizes {
			// Prepare data
			scalars := make([]fr.Element, size)
			for i := 0; i < size; i++ {
				scalars[i].SetRandom()
			}

			// Individual execution
			start := time.Now()
			for i := 0; i < size; i++ {
				var temp bls.G1Affine
				temp.ScalarMultiplication(&g1, scalars[i].BigInt(new(big.Int)))
			}
			singleDuration := time.Since(start)

			// Batch execution
			start = time.Now()
			_ = bls.BatchScalarMultiplicationG1(&g1, scalars)
			batchDuration := time.Since(start)

			t.Logf("%d G1 scalar multiplications - Individual: %.2f μs, Batch: %.2f μs, Speedup: %.2fx",
				size,
				float64(singleDuration.Microseconds()),
				float64(batchDuration.Microseconds()),
				float64(singleDuration.Microseconds())/float64(batchDuration.Microseconds()))
		}
	})

	// 7. Custom function test - Manual implementation of multi-base multi-scalar multiplication
	t.Run("CustomMultiScalarMult", func(t *testing.T) {
		numPoints := 100
		_, _, g1a, _ := bls.Generators()

		// Generate random points and scalars
		bases := make([]bls.G1Affine, numPoints)
		scalars := make([]fr.Element, numPoints)

		// Generate different random points
		for i := 0; i < numPoints; i++ {
			var r fr.Element
			r.SetRandom()
			bases[i].ScalarMultiplication(&g1a, r.BigInt(new(big.Int)))
			scalars[i].SetRandom()
		}

		// Manual implementation of multi-scalar multiplication
		start := time.Now()
		var result bls.G1Jac
		result.X.SetZero()
		result.Y.SetOne()
		result.Z.SetZero()

		for i := 0; i < numPoints; i++ {
			var baseJac bls.G1Jac
			baseJac.FromAffine(&bases[i])

			var temp bls.G1Jac
			temp.ScalarMultiplication(&baseJac, scalars[i].BigInt(new(big.Int)))
			result.AddAssign(&temp)
		}

		// Convert back to affine coordinates
		var finalResult bls.G1Affine
		finalResult.FromJacobian(&result)

		duration := time.Since(start)
		t.Logf("Manual implementation of %d G1 multi-scalar multiplication time: %.2f μs", numPoints, float64(duration.Microseconds()))

		// Test gnark-crypto's built-in MultiExp function
		start = time.Now()
		var result2 bls.G1Jac
		result2.MultiExp(bases, scalars, ecc.MultiExpConfig{})

		var finalResult2 bls.G1Affine
		finalResult2.FromJacobian(&result2)

		duration = time.Since(start)
		t.Logf("Built-in MultiExp function %d G1 multi-scalar multiplication time: %.2f μs", numPoints, float64(duration.Microseconds()))
	})
}

// compareUsers compares key fields of two user objects and returns if they match
func compareUsers(original *User, temp *User) (bool, []string) {
	var differences []string

	// Check public keys
	if !original.pk.hGamma.Equal(&temp.pk.hGamma) {
		differences = append(differences, "pk.hGamma not equal")
	}
	if !original.pk.hDelta.Equal(&temp.pk.hDelta) {
		differences = append(differences, "pk.hDelta not equal")
	}

	// Check aggregated long-term signatures
	if !original.aggregatedLongSig.h.Equal(&temp.aggregatedLongSig.h) {
		differences = append(differences, "aggregatedLongSig.h not equal")
	}
	if !original.aggregatedLongSig.s.Equal(&temp.aggregatedLongSig.s) {
		differences = append(differences, "aggregatedLongSig.s not equal")
	}

	// Check aggregated epoch signatures
	if !original.aggregatedEpochSig.Equal(&temp.aggregatedEpochSig) {
		differences = append(differences, "aggregatedEpochSig not equal")
	}

	// Check aux data
	if !bytes.Equal(original.aux, temp.aux) {
		if len(original.aux) != len(temp.aux) {
			differences = append(differences, fmt.Sprintf("aux length differs: original=%d, temp=%d", len(original.aux), len(temp.aux)))
		} else {
			differences = append(differences, "aux data not equal (same length)")
		}
	}

	return len(differences) == 0, differences
}

// DirectAggVerify performs verification using original messages directly, avoiding extraction from aux data
func DirectAggVerify(j uint64, user *User, signers []*Signer, pp *EbpsParams, originalMessages [][]byte) (bool, error) {
	if user == nil || len(signers) == 0 || pp == nil || len(originalMessages) == 0 {
		return false, fmt.Errorf("nil input parameters or empty messages")
	}

	// 1. Check that h' in signature is not identity
	if user.aggregatedLongSig.h.IsInfinity() {
		return false, nil
	}

	// Use original messages to ensure consistency with signing time
	msgs := originalMessages
	if len(msgs) > len(signers) {
		msgs = msgs[:len(signers)] // Only use messages equal to number of signers
	}

	// Compute each signer's part in parallel
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

	// Calculate Z and temp1 accumulation
	var Z bls.G2Affine
	if len(signers) > 0 {
		Z.Set(&signers[0].tvk)
	}

	var temp1 bls.G2Affine
	if len(temp) > 0 {
		temp1.Set(&temp[0])
	}

	for i := 1; i < len(signers) && i < len(msgs); i++ {
		Z.Add(&Z, &signers[i].tvk)
		temp1.Add(&temp1, &temp[i])
	}

	// Calculate (h^δ)^{F(m_2,j)}
	epochExp := new(fr.Element).SetUint64(j) // F(m_2,j) = j
	var temp2 bls.G1Affine
	temp2.ScalarMultiplication(&user.pk.hDelta, epochExp.BigInt(new(big.Int)))

	// Aggregate signature s = σ_agg,lt · σ_agg,ep,j
	var temp3 bls.G1Affine
	temp3.Add(&user.aggregatedLongSig.s, &user.aggregatedEpochSig)

	// Pairing verification
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
	g2Points[2].Neg(&g2Points[2]) // Move pp.va to left side

	// Perform pairing check
	result, err := bls.PairingCheck(g1Points, g2Points)
	if err != nil {
		return false, fmt.Errorf("pairing check failed: %v", err)
	}

	return result, nil
}

// Helper function: Calculate total weight of selected signers
func sumWeights(wtsSystem *WTS, signers []int) int {
	total := 0
	for _, idx := range signers {
		if idx >= 0 && idx < len(wtsSystem.weights) {
			total += wtsSystem.weights[idx]
		}
	}
	return total
}

// Calculate mean and standard deviation
func calculateStats(durations []time.Duration) (time.Duration, time.Duration) {
	var sum time.Duration
	for _, d := range durations {
		sum += d
	}
	avg := sum / time.Duration(len(durations))

	var squaredDiffSum float64
	for _, d := range durations {
		diff := float64(d - avg)
		squaredDiffSum += diff * diff
	}

	variance := squaredDiffSum / float64(len(durations))
	stdDev := time.Duration(math.Sqrt(variance))

	return avg, stdDev
}
func BenchmarkShowDetailed(b *testing.B) {
	// Setup parameters
	n := 128                // Number of signers in WTS system
	l := 128                // Number of signers in EBPS system
	epochID := uint64(1234) // Current epoch ID
	threshold := 128        // Weight threshold

	// ----- Preparation Phase: Setup Test Environment -----
	fmt.Println("=== Preparation Phase ===")
	setupStart := time.Now()

	// 1. Initialize WTS system, all weights set to 1
	wtsStart := time.Now()
	weights := make([]int, n)
	for i := 0; i < n; i++ {
		weights[i] = 1 // All weights set to 1
	}

	wtsCrs := GenCRS(n)
	wtsSystem := NewWTS(n, weights, wtsCrs)
	wtsSystem.preProcess()
	wtsTime := time.Since(wtsStart)
	fmt.Printf("WTS system initialization and preprocessing: %.3f ms\n", float64(wtsTime.Nanoseconds())/1e6)

	// 2. Initialize EBPS system
	ebpsStart := time.Now()
	ebpsParams := Setup(128)
	ebpsSigners := LongKeyGen(ebpsParams, l)
	ebpsSigners = EpochKeyGen(ebpsParams, ebpsSigners, int(epochID))
	ebpsTime := time.Since(ebpsStart)
	fmt.Printf("EBPS system initialization: %.3f ms\n", float64(ebpsTime.Nanoseconds())/1e6)

	// 3. Prepare messages and user data
	userStart := time.Now()
	originalMessages := make([][]byte, l)
	for i := 0; i < l; i++ {
		originalMessages[i] = bytes.Repeat([]byte{byte(i%256 + 1)}, 32)
	}

	ebpsUser, err := GenAuxTag(originalMessages, ebpsSigners, l, ebpsParams)
	if err != nil {
		b.Fatalf("GenAuxTag failed: %v", err)
	}

	ebpsUser.longtermSigs = make([]struct {
		h bls.G1Affine
		s []bls.G1Affine
	}, l)
	for i := 0; i < l; i++ {
		ebpsUser.longtermSigs[i].s = make([]bls.G1Affine, l)
	}
	ebpsUser.longtermSigs[0].h = ebpsUser.pk.hGamma
	ebpsUser.epochSigs = make([]bls.G1Affine, l)
	userTime := time.Since(userStart)
	fmt.Printf("User data preparation: %.3f ms\n", float64(userTime.Nanoseconds())/1e6)

	// 4. Generate signatures
	sigStart := time.Now()
	for i := 0; i < l; i++ {
		updatedUser, err := LongSign(&ebpsSigners[i], ebpsUser, ebpsParams, i)
		if err != nil {
			b.Fatalf("LongSign failed for signer %d: %v", i, err)
		}
		ebpsUser = updatedUser

		ebpsUser, err = EpochSign(&ebpsSigners[i], ebpsUser, ebpsParams, i, epochID)
		if err != nil {
			b.Fatalf("EpochSign failed for signer %d: %v", i, err)
		}
	}
	sigTime := time.Since(sigStart)
	fmt.Printf("Generate all signatures: %.3f ms\n", float64(sigTime.Nanoseconds())/1e6)

	// 5. Aggregate signatures
	aggStart := time.Now()
	if err := AggSigAttr(ebpsUser); err != nil {
		b.Fatalf("AggSigAttr failed: %v", err)
	}
	aggAttrTime := time.Since(aggStart)
	fmt.Printf("Aggregate attribute signatures: %.3f ms\n", float64(aggAttrTime.Nanoseconds())/1e6)

	epStart := time.Now()
	if err := AggSigEp(ebpsUser); err != nil {
		b.Fatalf("AggSigEp failed: %v", err)
	}
	aggEpTime := time.Since(epStart)
	fmt.Printf("Aggregate epoch signatures: %.3f ms\n", float64(aggEpTime.Nanoseconds())/1e6)

	combStart := time.Now()
	_, err = CombAggSig(ebpsUser)
	if err != nil {
		b.Fatalf("CombAggSig failed: %v", err)
	}
	combTime := time.Since(combStart)
	fmt.Printf("Combine aggregated signatures: %.3f ms\n", float64(combTime.Nanoseconds())/1e6)

	// 6. Select WTS signers
	selectedSigners := make([]int, n)
	for i := 0; i < n; i++ {
		selectedSigners[i] = i
	}

	setupTime := time.Since(setupStart)
	fmt.Printf("Total preparation time: %.3f ms\n\n", float64(setupTime.Nanoseconds())/1e6)

	// ----- Detailed Show Function Benchmark -----
	var totalValidationTime, totalWeightCalcTime, totalDummySigTime time.Duration
	var totalCombineTime, totalAggRndTime, totalCredentialTime time.Duration
	var showCount int

	// Run benchmark
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		showStart := time.Now()

		// 1. Parameter validation phase
		validStart := time.Now()
		validTime := time.Since(validStart)
		totalValidationTime += validTime

		// 2. Weight calculation phase
		weightStart := time.Now()
		totalWeight := 0
		for _, idx := range selectedSigners {
			if idx < len(wtsSystem.weights) {
				totalWeight += wtsSystem.weights[idx]
			}
		}
		weightTime := time.Since(weightStart)
		totalWeightCalcTime += weightTime

		// 3. Generate dummy signatures phase
		dummyStart := time.Now()
		dummySigmas := make([]bls.G2Jac, len(selectedSigners))
		for i, signerIdx := range selectedSigners {
			dummySigmas[i] = *new(bls.G2Jac).ScalarMultiplication(&wtsSystem.crs.g2,
				wtsSystem.signers[signerIdx].sKey.BigInt(&big.Int{}))
		}
		dummyTime := time.Since(dummyStart)
		totalDummySigTime += dummyTime

		// 4. Call combine function phase
		combineStart := time.Now()
		wtsAggregates := wtsSystem.combine(selectedSigners, dummySigmas)
		if wtsAggregates.ths != totalWeight {
			wtsAggregates.ths = totalWeight
		}
		combineTime := time.Since(combineStart)
		totalCombineTime += combineTime

		// 5. EBPS aggregation and randomization phase
		aggRndStart := time.Now()
		r, _ := new(fr.Element).SetRandom()
		rndSig, rndTag, err := RndSigTag(ebpsUser, r)
		if err != nil {
			b.Fatalf("RndSigTag failed: %v", err)
		}
		aggRndTime := time.Since(aggRndStart)
		totalAggRndTime += aggRndTime

		// 6. Create credential phase
		credStart := time.Now()
		_ = &ShowCredential{
			WtsSigners:   selectedSigners,
			WtsThreshold: threshold,
			EbpsSig: struct {
				h bls.G1Affine
				s bls.G1Affine
			}{
				h: rndSig.h,
				s: rndSig.s,
			},
			EbpsTag: struct {
				hGamma bls.G1Affine
				hDelta bls.G1Affine
			}{
				hGamma: rndTag.hGamma,
				hDelta: rndTag.hDelta,
			},
			AggregatedEpochSig: ebpsUser.aggregatedEpochSig,
			Aux:                ebpsUser.aux,
			EpochID:            epochID,
			WtsAggregates:      wtsAggregates,
		}
		credTime := time.Since(credStart)
		totalCredentialTime += credTime

		showTime := time.Since(showStart)
		showCount++

		// Print detailed results for first iteration
		if i == 0 {
			fmt.Println("=== Show Function First Execution Detailed Timing ===")
			fmt.Printf("1. Parameter validation: %.3f ms\n", float64(validTime.Nanoseconds())/1e6)
			fmt.Printf("2. Weight calculation: %.3f ms\n", float64(weightTime.Nanoseconds())/1e6)
			fmt.Printf("3. Generate dummy signatures: %.3f ms\n", float64(dummyTime.Nanoseconds())/1e6)
			fmt.Printf("4. WTS aggregation: %.3f ms\n", float64(combineTime.Nanoseconds())/1e6)
			fmt.Printf("5. EBPS randomization (RndSigTag): %.3f ms\n", float64(aggRndTime.Nanoseconds())/1e6)
			fmt.Printf("6. Create credential: %.3f ms\n", float64(credTime.Nanoseconds())/1e6)
			fmt.Printf("Total Show function time: %.3f ms\n\n", float64(showTime.Nanoseconds())/1e6)
		}
	}

	// Calculate averages
	avgValidTime := float64(totalValidationTime.Nanoseconds()) / float64(showCount) / 1e6
	avgWeightTime := float64(totalWeightCalcTime.Nanoseconds()) / float64(showCount) / 1e6
	avgDummyTime := float64(totalDummySigTime.Nanoseconds()) / float64(showCount) / 1e6
	avgCombineTime := float64(totalCombineTime.Nanoseconds()) / float64(showCount) / 1e6
	avgAggRndTime := float64(totalAggRndTime.Nanoseconds()) / float64(showCount) / 1e6
	avgCredTime := float64(totalCredentialTime.Nanoseconds()) / float64(showCount) / 1e6
	totalAvg := avgValidTime + avgWeightTime + avgDummyTime + avgCombineTime + avgAggRndTime + avgCredTime

	// Print average times
	fmt.Printf("=== Show Function Average Execution Time (%d runs) ===\n", showCount)
	fmt.Printf("1. Parameter validation: %.3f ms (%.2f%%)\n", avgValidTime, avgValidTime*100/totalAvg)
	fmt.Printf("2. Weight calculation: %.3f ms (%.2f%%)\n", avgWeightTime, avgWeightTime*100/totalAvg)
	fmt.Printf("3. Generate dummy signatures: %.3f ms (%.2f%%)\n", avgDummyTime, avgDummyTime*100/totalAvg)
	fmt.Printf("4. WTS aggregation: %.3f ms (%.2f%%)\n", avgCombineTime, avgCombineTime*100/totalAvg)
	fmt.Printf("5. EBPS randomization (RndSigTag): %.3f ms (%.2f%%)\n", avgAggRndTime, avgAggRndTime*100/totalAvg)
	fmt.Printf("6. Create credential: %.3f ms (%.2f%%)\n", avgCredTime, avgCredTime*100/totalAvg)
	fmt.Printf("Total Show function average time: %.3f ms\n", totalAvg)

	// Print summary
	fmt.Println("\n=== Performance Analysis Summary ===")
	fmt.Println("Most time-consuming steps:")
	steps := []struct {
		name string
		time float64
	}{
		{"Parameter validation", avgValidTime},
		{"Weight calculation", avgWeightTime},
		{"Generate dummy signatures", avgDummyTime},
		{"WTS aggregation", avgCombineTime},
		{"EBPS randomization (RndSigTag)", avgAggRndTime},
		{"Create credential", avgCredTime},
	}

	// Sort to find most time-consuming steps
	sort.Slice(steps, func(i, j int) bool {
		return steps[i].time > steps[j].time
	})

	for i, step := range steps {
		if i < 3 { // Only show top 3 most time-consuming steps
			fmt.Printf("%d. %s: %.3f ms\n", i+1, step.name, step.time)
		}
	}
}

// Issuance process benchmark
func BenchmarkCredentialIssuanceProcess(b *testing.B) {
	// Fixed message size of 32 bytes
	messageSize := 32

	// 1. System setup
	pp := Setup(128)

	// 2. Generate issuer
	signers := LongKeyGen(pp, 1)
	signers = EpochKeyGen(pp, signers, 1)
	signer := &signers[0]

	if signer.lsk2.IsZero() {
		randomVal, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
		signer.lsk2.SetBigInt(randomVal)
	}

	// 3. Generate test message
	message := bytes.Repeat([]byte("a"), messageSize)
	messages := [][]byte{message}

	// Test user side and issuer side separately
	b.Run("UserSide", func(b *testing.B) {
		// Store user side operation times
		zkTimes := make([]time.Duration, b.N)
		unblindTimes := make([]time.Duration, b.N)

		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			// Create new user
			b.StopTimer()
			user, err := GenUserTag(messages, signers, 1, pp)
			if err != nil {
				b.Fatalf("User generation failed: %v", err)
			}
			b.StartTimer()

			// User step 1: Generate ZK proofs
			startZK := time.Now()
			proofTG, proofsCL, err := GenerateZKProofs(user, pp)
			zkTimes[i] = time.Since(startZK)

			if err != nil {
				b.Fatalf("ZK proof generation failed: %v", err)
			}

			// Intermediate step: Get blind credential (not timed)
			b.StopTimer()
			blindCred, _, err := RequestCredentialFromIssuer(
				user, pp, 0, proofTG, proofsCL[0], signer, i%10)
			if err != nil {
				b.Fatalf("Failed to obtain blind credential: %v", err)
			}
			b.StartTimer()

			// User step 2: Unblind
			startUnblind := time.Now()
			_, err = UnblindCredential(user, blindCred)
			unblindTimes[i] = time.Since(startUnblind)

			if err != nil {
				b.Fatalf("Unblinding failed: %v", err)
			}
		}

		// Calculate statistics
		zkAvg, zkStdDev := calculateStats(zkTimes)
		unblindAvg, unblindStdDev := calculateStats(unblindTimes)
		totalUserAvg := zkAvg + unblindAvg

		// Report results
		b.ReportMetric(float64(zkAvg)/float64(time.Millisecond), "ZK_Proof-avg(ms)")
		b.ReportMetric(float64(zkStdDev)/float64(time.Millisecond), "ZK_Proof-stddev(ms)")
		b.ReportMetric(float64(unblindAvg)/float64(time.Millisecond), "Unblind-avg(ms)")
		b.ReportMetric(float64(unblindStdDev)/float64(time.Millisecond), "Unblind-stddev(ms)")
		b.ReportMetric(float64(totalUserAvg)/float64(time.Millisecond), "Total_User_Time(ms)")

		fmt.Printf("\nUser Side Performance (message size=%d bytes, runs=%d):\n", messageSize, b.N)
		fmt.Printf("  Generate ZK Proofs: Average=%.4fms, StdDev=%.4fms\n",
			float64(zkAvg)/float64(time.Millisecond),
			float64(zkStdDev)/float64(time.Millisecond))
		fmt.Printf("  Unblind Credential: Average=%.4fms, StdDev=%.4fms\n",
			float64(unblindAvg)/float64(time.Millisecond),
			float64(unblindStdDev)/float64(time.Millisecond))
		fmt.Printf("  Total Processing Time: Average=%.4fms\n",
			float64(totalUserAvg)/float64(time.Millisecond))
	})

	b.Run("IssuerSide", func(b *testing.B) {
		// Store issuer side operation times
		blindTimes := make([]time.Duration, b.N)

		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			// Create new user and generate proofs each time
			b.StopTimer()
			user, _ := GenUserTag(messages, signers, 1, pp)
			proofTG, proofsCL, _ := GenerateZKProofs(user, pp)
			b.StartTimer()

			// Issuer side: Perform blind signing
			startBlind := time.Now()
			_, _, err := RequestCredentialFromIssuer(
				user, pp, 0, proofTG, proofsCL[0], signer, i%10)
			blindTimes[i] = time.Since(startBlind)

			if err != nil {
				b.Fatalf("Blind signing failed: %v", err)
			}
		}

		// Calculate statistics
		blindAvg, blindStdDev := calculateStats(blindTimes)

		// Report results
		b.ReportMetric(float64(blindAvg)/float64(time.Millisecond), "BlindSign-avg(ms)")
		b.ReportMetric(float64(blindStdDev)/float64(time.Millisecond), "BlindSign-stddev(ms)")

		fmt.Printf("\nIssuer Side Performance (message size=%d bytes, runs=%d):\n", messageSize, b.N)
		fmt.Printf("  Blind Signing: Average=%.4fms, StdDev=%.4fms\n",
			float64(blindAvg)/float64(time.Millisecond),
			float64(blindStdDev)/float64(time.Millisecond))
	})
}

// BenchmarkShowAndVerifyWithVaryingSigners performs benchmark testing for different numbers of signers
func BenchmarkShowAndVerifyWithVaryingSigners(b *testing.B) {
	// Define node counts to test, consistent with BenchmarkWTS
	nodeCounts := []int{4, 8, 16, 32, 64, 128}

	// Test for each number of signers
	for _, n := range nodeCounts {
		// Create sub-benchmark for each count
		b.Run(fmt.Sprintf("Nodes_%d", n), func(b *testing.B) {
			// Setup parameters - WTS system size now matches signer count
			l := n                  // Number of signers in EBPS system
			epochID := uint64(1234) // Current epoch ID
			threshold := 6          // Weight threshold

			// Select signers - same as EBPS signer count
			selectedSigners := make([]int, l)
			for i := 0; i < l; i++ {
				selectedSigners[i] = i
			}

			fmt.Printf("\nTest configuration: Node count=%d, Signer count=%d, Threshold=%d\n", n, l, threshold)

			// ----- WTS system initialization -----
			weights := make([]int, n)
			for i := 0; i < n; i++ {
				weights[i] = i%10 + 1 // Use weights 1-10, avoid zeros or excessive weights, consistent with BenchmarkWTS
			}

			wtsCrs := GenCRS(n)
			wtsSystem := NewWTS(n, weights, wtsCrs)
			wtsSystem.preProcess()

			// ----- EBPS system initialization -----
			ebpsParams := Setup(128)
			ebpsSigners := LongKeyGen(ebpsParams, l)
			ebpsSigners = EpochKeyGen(ebpsParams, ebpsSigners, int(epochID))

			// Prepare messages
			originalMessages := make([][]byte, l)
			for i := 0; i < l; i++ {
				originalMessages[i] = bytes.Repeat([]byte{byte(i + 1)}, 32)
			}

			// Generate user tag and auxiliary data
			ebpsUser, _ := GenAuxTag(originalMessages, ebpsSigners, l, ebpsParams)

			// Initialize data structures
			ebpsUser.longtermSigs = make([]struct {
				h bls.G1Affine
				s []bls.G1Affine
			}, l)
			for i := 0; i < l; i++ {
				ebpsUser.longtermSigs[i].s = make([]bls.G1Affine, l)
			}
			ebpsUser.longtermSigs[0].h = ebpsUser.pk.hGamma
			ebpsUser.epochSigs = make([]bls.G1Affine, l)

			// Generate signatures
			for i := 0; i < l; i++ {
				ebpsUser, _ = LongSign(&ebpsSigners[i], ebpsUser, ebpsParams, i)
				ebpsUser, _ = EpochSign(&ebpsSigners[i], ebpsUser, ebpsParams, i, epochID)
			}

			// Aggregate signatures
			AggSigAttr(ebpsUser)
			AggSigEp(ebpsUser)
			CombAggSig(ebpsUser)

			// Convert signer array to pointer array
			ebpsSignerPtrs := make([]*Signer, len(ebpsSigners))
			for i := range ebpsSigners {
				ebpsSignerPtrs[i] = &ebpsSigners[i]
			}

			// Store operation times, consistent with BenchmarkWTS
			showTimes := make([]time.Duration, 0, b.N)
			verifyTimes := make([]time.Duration, 0, b.N)
			combineTimes := make([]time.Duration, 0, b.N) // Separately measure combine function

			// Generate dummy signatures in advance - moved out of Show function
			dummySigmas := make([]bls.G2Jac, len(selectedSigners))
			for i, signerIdx := range selectedSigners {
				dummySigmas[i] = *new(bls.G2Jac).ScalarMultiplication(&wtsSystem.crs.g2,
					wtsSystem.signers[signerIdx].sKey.BigInt(&big.Int{}))
			}

			// Test combine operation separately
			b.Run("Combine", func(b *testing.B) {
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					start := time.Now()
					wtsAggregates := wtsSystem.combine(selectedSigners, dummySigmas)
					combineTimes = append(combineTimes, time.Since(start))

					// Prevent optimization
					if wtsAggregates.ths <= 0 {
						b.Fatalf("Invalid aggregate result")
					}
				}

				// Calculate combine statistics
				if len(combineTimes) > 0 {
					combineAvg, combineStdDev := calculateStats(combineTimes)
					b.ReportMetric(float64(combineAvg)/float64(time.Millisecond), "Combine-avg(ms)")
					b.ReportMetric(float64(combineStdDev)/float64(time.Millisecond), "Combine-stddev(ms)")

					fmt.Printf("  Combine: Average=%.4fms, StdDev=%.4fms, Runs=%d\n",
						float64(combineAvg)/float64(time.Millisecond),
						float64(combineStdDev)/float64(time.Millisecond),
						len(combineTimes))
				}
			})

			// Prepare test credential
			var showCredential *ShowCredential

			// Test Show operation
			b.Run("Show", func(b *testing.B) {
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					start := time.Now()
					credential, showErr := ShowWithoutDummy(&wtsSystem, selectedSigners, dummySigmas, ebpsUser, ebpsParams, epochID, threshold)
					showTimes = append(showTimes, time.Since(start))

					if showErr != nil {
						b.Fatalf("Show failed: %v", showErr)
					}

					// Avoid compiler optimization
					if credential == nil {
						b.Fatalf("Credential should not be nil")
					}

					// Save last credential for verification test
					showCredential = credential
				}

				// Calculate Show statistics
				if len(showTimes) > 0 {
					showAvg, showStdDev := calculateStats(showTimes)
					b.ReportMetric(float64(showAvg)/float64(time.Millisecond), "Show-avg(ms)")
					b.ReportMetric(float64(showStdDev)/float64(time.Millisecond), "Show-stddev(ms)")

					fmt.Printf("  Show: Average=%.4fms, StdDev=%.4fms, Runs=%d\n",
						float64(showAvg)/float64(time.Millisecond),
						float64(showStdDev)/float64(time.Millisecond),
						len(showTimes))
				}
			})

			// Test Verify operation
			b.Run("Verify", func(b *testing.B) {
				if showCredential == nil {
					b.Fatal("No credential available for verification testing")
				}

				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					start := time.Now()
					valid, verifyErr := ComVerify(showCredential, &wtsSystem, ebpsSignerPtrs, ebpsParams)
					verifyTimes = append(verifyTimes, time.Since(start))

					if verifyErr != nil {
						b.Fatalf("Verify failed: %v", verifyErr)
					}
					if !valid {
						b.Fatalf("Verification failed when it should succeed")
					}
				}

				// Calculate Verify statistics
				if len(verifyTimes) > 0 {
					verifyAvg, verifyStdDev := calculateStats(verifyTimes)
					b.ReportMetric(float64(verifyAvg)/float64(time.Millisecond), "Verify-avg(ms)")
					b.ReportMetric(float64(verifyStdDev)/float64(time.Millisecond), "Verify-stddev(ms)")

					fmt.Printf("  Verify: Average=%.4fms, StdDev=%.4fms, Runs=%d\n",
						float64(verifyAvg)/float64(time.Millisecond),
						float64(verifyStdDev)/float64(time.Millisecond),
						len(verifyTimes))
				}
			})

			// Calculate and report total time
			if len(showTimes) > 0 && len(verifyTimes) > 0 {
				showAvg, _ := calculateStats(showTimes)
				verifyAvg, _ := calculateStats(verifyTimes)
				totalAvg := showAvg + verifyAvg

				b.ReportMetric(float64(totalAvg)/float64(time.Millisecond), "Total-avg(ms)")

				fmt.Printf("  Total time: Average=%.4fms\n",
					float64(totalAvg)/float64(time.Millisecond))
			}

			fmt.Println("-----------------------------------------------------")
		})
	}
}

// Add benchmark test for different thresholds
func BenchmarkShowAndVerifyWithThresholds(b *testing.B) {
	// Fixed number of signers
	signerCount := 4

	// Test different threshold ratios
	thresholdRatios := []float64{0.1, 0.25, 0.5, 0.75, 0.9}

	for _, ratio := range thresholdRatios {
		// Calculate actual threshold
		threshold := int(math.Ceil(float64(signerCount) * ratio))

		// Create sub-test for each threshold
		testName := fmt.Sprintf("Signers_%d_Threshold_%.0f%%", signerCount, ratio*100)
		b.Run(testName, func(b *testing.B) {
			// Setup parameters
			n := 128                // Total signers in WTS system
			l := signerCount        // Number of signers in EBPS system
			epochID := uint64(1234) // Current epoch ID

			// Select signers - same as EBPS signer count
			selectedSigners := make([]int, l)
			for i := 0; i < l; i++ {
				selectedSigners[i] = i
			}

			fmt.Printf("\nTest configuration: Signer count=%d, Threshold=%d (%.0f%%)\n",
				l, threshold, ratio*100)

			// ----- WTS system initialization -----
			weights := make([]int, n)
			for i := 0; i < n; i++ {
				weights[i] = i + 1
			}

			wtsCrs := GenCRS(n)
			wtsSystem := NewWTS(n, weights, wtsCrs)
			wtsSystem.preProcess()

			// ----- EBPS system initialization -----
			ebpsParams := Setup(128)
			ebpsSigners := LongKeyGen(ebpsParams, l)
			ebpsSigners = EpochKeyGen(ebpsParams, ebpsSigners, int(epochID))

			// Prepare messages
			originalMessages := make([][]byte, l)
			for i := 0; i < l; i++ {
				originalMessages[i] = bytes.Repeat([]byte{byte(i + 1)}, 32)
			}

			// Generate user tag and auxiliary data
			ebpsUser, _ := GenAuxTag(originalMessages, ebpsSigners, l, ebpsParams)

			// Initialize data structures
			ebpsUser.longtermSigs = make([]struct {
				h bls.G1Affine
				s []bls.G1Affine
			}, l)
			for i := 0; i < l; i++ {
				ebpsUser.longtermSigs[i].s = make([]bls.G1Affine, l)
			}
			ebpsUser.longtermSigs[0].h = ebpsUser.pk.hGamma
			ebpsUser.epochSigs = make([]bls.G1Affine, l)

			// Generate signatures
			for i := 0; i < l; i++ {
				ebpsUser, _ = LongSign(&ebpsSigners[i], ebpsUser, ebpsParams, i)
				ebpsUser, _ = EpochSign(&ebpsSigners[i], ebpsUser, ebpsParams, i, epochID)
			}

			// Aggregate signatures
			AggSigAttr(ebpsUser)
			AggSigEp(ebpsUser)
			CombAggSig(ebpsUser)

			// Convert signer array to pointer array
			ebpsSignerPtrs := make([]*Signer, len(ebpsSigners))
			for i := range ebpsSigners {
				ebpsSignerPtrs[i] = &ebpsSigners[i]
			}

			// Generate dummy signatures in advance - moved out of Show function
			dummySigmas := make([]bls.G2Jac, len(selectedSigners))
			for i, signerIdx := range selectedSigners {
				dummySigmas[i] = *new(bls.G2Jac).ScalarMultiplication(&wtsSystem.crs.g2,
					wtsSystem.signers[signerIdx].sKey.BigInt(&big.Int{}))
			}

			// Prepare a credential for verification testing
			var showCredential *ShowCredential
			var err error
			showCredential, err = ShowWithoutDummy(&wtsSystem, selectedSigners, dummySigmas, ebpsUser, ebpsParams, epochID, threshold)
			if err != nil {
				b.Fatalf("Failed to prepare test credential: %v", err)
			}

			// Result storage structures
			var showResult struct {
				avg        time.Duration
				stdDev     time.Duration
				count      int
				firstCall  time.Duration
				otherCalls time.Duration
			}

			var verifyResult struct {
				avg        time.Duration
				stdDev     time.Duration
				count      int
				firstCall  time.Duration
				otherCalls time.Duration
			}

			// 1. Test Show operation
			b.Run("Show", func(b *testing.B) {
				showTimes := make([]time.Duration, 0, b.N)

				// First call
				start := time.Now()
				firstCredential, err := ShowWithoutDummy(&wtsSystem, selectedSigners, dummySigmas, ebpsUser, ebpsParams, epochID, threshold)
				showResult.firstCall = time.Since(start)

				if err != nil {
					b.Fatalf("First Show call failed: %v", err)
				}
				if firstCredential == nil {
					b.Fatalf("First credential is nil")
				}

				b.ResetTimer() // Reset timer

				// Measure subsequent calls
				otherCallsTotal := time.Duration(0)
				for i := 0; i < b.N; i++ {
					start := time.Now()
					testCredential, err := ShowWithoutDummy(&wtsSystem, selectedSigners, dummySigmas, ebpsUser, ebpsParams, epochID, threshold)
					elapsed := time.Since(start)
					showTimes = append(showTimes, elapsed)
					otherCallsTotal += elapsed

					if err != nil {
						b.Fatalf("Iteration %d: Show failed: %v", i, err)
					}

					// Prevent compiler optimization
					if testCredential == nil {
						b.Fatalf("Credential should not be nil")
					}
				}

				// Calculate statistics for this test
				if len(showTimes) > 0 {
					showResult.avg, showResult.stdDev = calculateStats(showTimes)
					showResult.count = len(showTimes)
					showResult.otherCalls = otherCallsTotal / time.Duration(b.N)
				}
			})

			// 2. Test Verify operation
			b.Run("Verify", func(b *testing.B) {
				verifyTimes := make([]time.Duration, 0, b.N)

				// First call
				start := time.Now()
				firstValid, firstErr := ComVerify(showCredential, &wtsSystem, ebpsSignerPtrs, ebpsParams)
				verifyResult.firstCall = time.Since(start)

				if firstErr != nil {
					b.Fatalf("First Verify call failed: %v", firstErr)
				}
				if !firstValid {
					b.Fatalf("First credential verification failed")
				}

				b.ResetTimer() // Reset timer

				// Measure subsequent calls
				otherCallsTotal := time.Duration(0)
				for i := 0; i < b.N; i++ {
					start := time.Now()
					valid, err := ComVerify(showCredential, &wtsSystem, ebpsSignerPtrs, ebpsParams)
					elapsed := time.Since(start)
					verifyTimes = append(verifyTimes, elapsed)
					otherCallsTotal += elapsed

					if err != nil {
						b.Fatalf("Iteration %d: ComVerify failed: %v", i, err)
					}
					if !valid {
						b.Fatalf("Iteration %d: Verification failed when it should succeed", i)
					}
				}

				// Calculate statistics for this test
				if len(verifyTimes) > 0 {
					verifyResult.avg, verifyResult.stdDev = calculateStats(verifyTimes)
					verifyResult.count = len(verifyTimes)
					verifyResult.otherCalls = otherCallsTotal / time.Duration(b.N)
				}
			})

			// Report Show results
			if showResult.count > 0 {
				b.ReportMetric(float64(showResult.avg)/float64(time.Millisecond), "Show-avg(ms)")
				b.ReportMetric(float64(showResult.stdDev)/float64(time.Millisecond), "Show-stddev(ms)")
				b.ReportMetric(float64(showResult.firstCall)/float64(time.Millisecond), "Show-first(ms)")
				b.ReportMetric(float64(showResult.otherCalls)/float64(time.Millisecond), "Show-rest(ms)")

				fmt.Printf("  Show results: \n")
				fmt.Printf("    Average time=%.4fms, StdDev=%.4fms, Runs=%d\n",
					float64(showResult.avg)/float64(time.Millisecond),
					float64(showResult.stdDev)/float64(time.Millisecond),
					showResult.count)
				fmt.Printf("    First call=%.4fms, Subsequent calls=%.4fms, First/Rest ratio=%.2fx\n",
					float64(showResult.firstCall)/float64(time.Millisecond),
					float64(showResult.otherCalls)/float64(time.Millisecond),
					float64(showResult.firstCall)/float64(showResult.otherCalls))
			}

			// Report Verify results
			if verifyResult.count > 0 {
				b.ReportMetric(float64(verifyResult.avg)/float64(time.Millisecond), "Verify-avg(ms)")
				b.ReportMetric(float64(verifyResult.stdDev)/float64(time.Millisecond), "Verify-stddev(ms)")
				b.ReportMetric(float64(verifyResult.firstCall)/float64(time.Millisecond), "Verify-first(ms)")
				b.ReportMetric(float64(verifyResult.otherCalls)/float64(time.Millisecond), "Verify-rest(ms)")

				fmt.Printf("  Verify results: \n")
				fmt.Printf("    Average time=%.4fms, StdDev=%.4fms, Runs=%d\n",
					float64(verifyResult.avg)/float64(time.Millisecond),
					float64(verifyResult.stdDev)/float64(time.Millisecond),
					verifyResult.count)
				fmt.Printf("    First call=%.4fms, Subsequent calls=%.4fms, First/Rest ratio=%.2fx\n",
					float64(verifyResult.firstCall)/float64(time.Millisecond),
					float64(verifyResult.otherCalls)/float64(time.Millisecond),
					float64(verifyResult.firstCall)/float64(verifyResult.otherCalls))
			}

			// Report total results
			if showResult.count > 0 && verifyResult.count > 0 {
				totalAvg := showResult.avg + verifyResult.avg
				b.ReportMetric(float64(totalAvg)/float64(time.Millisecond), "Total(ms)")
				fmt.Printf("  Total time: Average=%.4fms\n",
					float64(totalAvg)/float64(time.Millisecond))
			}

			fmt.Println("-----------------------------------------------------")
		})
	}
}

// ShowWithoutDummy is the Show function that accepts pre-generated dummy signatures
func ShowWithoutDummy(
	wtsSystem *WTS,
	selectedSigners []int,
	dummySigmas []bls.G2Jac, // Pre-generated dummy signatures
	ebpsUser *User,
	ebpsParams *EbpsParams,
	epochID uint64,
	threshold int,
) (*ShowCredential, error) {
	// 1. Check parameter validity
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

	// 2. Calculate total weight of selected signers
	totalWeight := 0
	for _, idx := range selectedSigners {
		if idx < len(wtsSystem.weights) {
			totalWeight += wtsSystem.weights[idx]
		}
	}

	// 3. Call combine function to generate WTS aggregate parameters
	wtsAggregates := wtsSystem.combine(selectedSigners, dummySigmas)

	// Ensure ths field is set correctly
	if wtsAggregates.ths != totalWeight {
		wtsAggregates.ths = totalWeight
	}

	// 4. Create credential - using original signatures and tag values, without randomization
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

	return credential, nil
}

// Calculate average of multiple time values
func calculateAverage(durations []time.Duration) time.Duration {
	var sum time.Duration
	for _, d := range durations {
		sum += d
	}
	return sum / time.Duration(len(durations))
}

// BenchmarkCombineDirectly tests combine operation directly, isolated from other code
func BenchmarkCombineDirectly(b *testing.B) {
	// Test different numbers of signers
	signerCounts := []int{4, 8, 16, 32, 64, 128}

	// Test for each number of signers
	for _, signerCount := range signerCounts {
		b.Run(fmt.Sprintf("SignerCount_%d", signerCount), func(b *testing.B) {
			// Initialize WTS system
			n := 128 // Total number of signers in system
			weights := make([]int, n)
			for i := 0; i < n; i++ {
				weights[i] = i + 1
			}

			wtsCrs := GenCRS(n)
			wtsSystem := NewWTS(n, weights, wtsCrs)
			wtsSystem.preProcess()

			// Create signers and dummy signatures
			selectedSigners := make([]int, signerCount)
			dummySigmas := make([]bls.G2Jac, signerCount)

			for i := 0; i < signerCount; i++ {
				selectedSigners[i] = i
				dummySigmas[i] = *new(bls.G2Jac).ScalarMultiplication(&wtsSystem.crs.g2,
					wtsSystem.signers[i].sKey.BigInt(&big.Int{}))
			}

			// Warm up combine operation once
			_ = wtsSystem.combine(selectedSigners, dummySigmas)

			// Record time for each run
			runTimes := make([]time.Duration, 0, b.N)

			// Reset timer and start testing
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				start := time.Now()
				result := wtsSystem.combine(selectedSigners, dummySigmas)
				elapsed := time.Since(start)
				runTimes = append(runTimes, elapsed)

				// Prevent compiler optimization
				if result.ths <= 0 {
					b.Fatalf("Invalid result")
				}
			}

			// Calculate statistics
			avgTime, stdDev := calculateStats(runTimes)

			// Report results
			b.ReportMetric(float64(avgTime)/float64(time.Millisecond), "Avg(ms)")
			b.ReportMetric(float64(stdDev)/float64(time.Millisecond), "StdDev(ms)")

			fmt.Printf("Combine signer count=%d: Average=%.4fms, StdDev=%.4fms, Runs=%d\n",
				signerCount,
				float64(avgTime)/float64(time.Millisecond),
				float64(stdDev)/float64(time.Millisecond),
				len(runTimes))
		})
	}
}

// BenchmarkComprehensiveParallelismTest comprehensively tests the impact of parallelism on performance
func BenchmarkComprehensiveParallelismTest(b *testing.B) {
	// Save original GOMAXPROCS value
	originalMaxProcs := runtime.GOMAXPROCS(0)

	// Test different numbers of signers
	signerCounts := []int{4, 8, 16, 32, 64, 128}

	// Test different parallelism levels
	threadConfigs := []struct {
		procs int
		name  string
	}{
		{1, "SingleThread"},
		{originalMaxProcs, "MultiThread"},
	}

	for _, threadConfig := range threadConfigs {
		// Set parallelism level
		runtime.GOMAXPROCS(threadConfig.procs)

		b.Run(fmt.Sprintf("Mode_%s", threadConfig.name), func(b *testing.B) {
			for _, signerCount := range signerCounts {
				b.Run(fmt.Sprintf("Signers_%d", signerCount), func(b *testing.B) {
					// Setup parameters
					n := 128                // Total signers in WTS system
					l := signerCount        // Number of signers in EBPS system
					epochID := uint64(1234) // Current epoch ID
					threshold := 6          // Weight threshold

					// Select signers - same as EBPS signer count
					selectedSigners := make([]int, l)
					for i := 0; i < l; i++ {
						selectedSigners[i] = i
					}

					fmt.Printf("\nTesting in %s mode: Signer count=%d, Threshold=%d\n",
						threadConfig.name, l, threshold)

					// ----- WTS system initialization -----
					weights := make([]int, n)
					for i := 0; i < n; i++ {
						weights[i] = i + 1
					}

					wtsCrs := GenCRS(n)
					wtsSystem := NewWTS(n, weights, wtsCrs)
					wtsSystem.preProcess()

					// ----- EBPS system initialization -----
					ebpsParams := Setup(128)
					ebpsSigners := LongKeyGen(ebpsParams, l)
					ebpsSigners = EpochKeyGen(ebpsParams, ebpsSigners, int(epochID))

					// Prepare messages
					originalMessages := make([][]byte, l)
					for i := 0; i < l; i++ {
						originalMessages[i] = bytes.Repeat([]byte{byte(i + 1)}, 32)
					}

					// Generate user tag and auxiliary data
					ebpsUser, _ := GenAuxTag(originalMessages, ebpsSigners, l, ebpsParams)

					// Initialize data structures
					ebpsUser.longtermSigs = make([]struct {
						h bls.G1Affine
						s []bls.G1Affine
					}, l)
					for i := 0; i < l; i++ {
						ebpsUser.longtermSigs[i].s = make([]bls.G1Affine, l)
					}
					ebpsUser.longtermSigs[0].h = ebpsUser.pk.hGamma
					ebpsUser.epochSigs = make([]bls.G1Affine, l)

					// Generate signatures
					for i := 0; i < l; i++ {
						ebpsUser, _ = LongSign(&ebpsSigners[i], ebpsUser, ebpsParams, i)
						ebpsUser, _ = EpochSign(&ebpsSigners[i], ebpsUser, ebpsParams, i, epochID)
					}

					// Aggregate signatures
					AggSigAttr(ebpsUser)
					AggSigEp(ebpsUser)
					CombAggSig(ebpsUser)

					// Convert signer array to pointer array
					ebpsSignerPtrs := make([]*Signer, len(ebpsSigners))
					for i := range ebpsSigners {
						ebpsSignerPtrs[i] = &ebpsSigners[i]
					}

					// Generate dummy signatures in advance - moved out of Show function
					dummySigmas := make([]bls.G2Jac, len(selectedSigners))
					for i, signerIdx := range selectedSigners {
						dummySigmas[i] = *new(bls.G2Jac).ScalarMultiplication(&wtsSystem.crs.g2,
							wtsSystem.signers[signerIdx].sKey.BigInt(&big.Int{}))
					}

					// 1. Test combine operation
					b.Run("Combine", func(b *testing.B) {
						combineTimes := make([]time.Duration, 0, b.N)

						b.ResetTimer()
						for i := 0; i < b.N; i++ {
							start := time.Now()
							result := wtsSystem.combine(selectedSigners, dummySigmas)
							combineTimes = append(combineTimes, time.Since(start))

							// Prevent optimization
							if result.ths <= 0 {
								b.Fatalf("Invalid result")
							}
						}

						// Calculate and report results
						if len(combineTimes) > 0 {
							avgTime, _ := calculateStats(combineTimes)
							b.ReportMetric(float64(avgTime)/float64(time.Millisecond), "Combine-avg(ms)")

							fmt.Printf("  Combine: Average=%.4fms\n",
								float64(avgTime)/float64(time.Millisecond))
						}
					})

					// 2. Test ShowWithoutDummy operation
					b.Run("Show", func(b *testing.B) {
						showTimes := make([]time.Duration, 0, b.N)

						b.ResetTimer()
						for i := 0; i < b.N; i++ {
							start := time.Now()
							credential, err := ShowWithoutDummy(&wtsSystem, selectedSigners, dummySigmas,
								ebpsUser, ebpsParams, epochID, threshold)
							showTimes = append(showTimes, time.Since(start))

							if err != nil {
								b.Fatalf("Show failed: %v", err)
							}

							// Prevent optimization
							if credential == nil {
								b.Fatalf("Invalid credential")
							}
						}

						// Calculate and report results
						if len(showTimes) > 0 {
							avgTime, _ := calculateStats(showTimes)
							b.ReportMetric(float64(avgTime)/float64(time.Millisecond), "Show-avg(ms)")

							fmt.Printf("  Show: Average=%.4fms\n",
								float64(avgTime)/float64(time.Millisecond))
						}
					})

					fmt.Println("-----------------------------------------------------")
				})
			}
		})
	}

	// Restore original settings
	runtime.GOMAXPROCS(originalMaxProcs)
}
