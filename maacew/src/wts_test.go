package ma

import (
	"flag"
	"fmt"
	"math/big"
	"math/rand"

	"testing"
	"time"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/stretchr/testify/assert"
)

var NUM_NODES = flag.Int("signers", 1<<8, "Number of Signers")

func BenchmarkCompF(b *testing.B) {
	logN := 15
	n := 1 << logN

	fs := make([]fr.Element, n*logN)
	for i := 0; i < n*logN; i++ {
		fs[i].SetRandom()
	}

	for i := 0; i < b.N; i++ {
		for j := 0; j < 4; j++ {
			var sum fr.Element
			for ii := 0; ii < n*logN; ii++ {
				sum.Add(&sum, &fs[ii])
			}
		}
	}
}

func BenchmarkCompG1(b *testing.B) {
	logN := 15
	n := 1 << logN
	g1, _, _, _ := bls.Generators()

	var exp fr.Element
	gs := make([]bls.G1Jac, n)
	for i := 0; i < n; i++ {
		exp.SetRandom()
		gs[i].ScalarMultiplication(&g1, exp.BigInt(&big.Int{}))
	}

	for i := 0; i < b.N; i++ {
		var sumG bls.G1Jac
		for ii := 0; ii < n; ii++ {
			sumG.AddAssign(&gs[ii])
		}
	}
}

func TestGetOmega(t *testing.T) {
	n := 1 << 16
	seed := 0
	omega := GetOmega(n, seed)

	var omegaN fr.Element
	omegaN.Exp(omega, big.NewInt(int64(n)))
	one := fr.One()
	assert.Equal(t, omegaN, one, true)
}

func TestKeyGen(t *testing.T) {
	n := 1 << 4

	weights := make([]int, n)
	for i := 0; i < n; i++ {
		weights[i] = i
	}

	crs := GenCRS(n)
	w := NewWTS(n, weights, crs)

	// Testing that public keys are generated correctly
	var tPk bls.G1Affine
	for i := 0; i < n; i++ {
		tPk.ScalarMultiplication(&w.crs.g1a, w.signers[i].sKey.BigInt(&big.Int{}))
		assert.Equal(t, tPk.Equal(&w.signers[i].pKeyAff), true)
	}

	// Checking whether the public key and hTaus is computed correctly
	lagH := GetAllLagAtWithOmegas(w.crs.H, w.crs.tau)
	var skTau fr.Element

	for i := 0; i < n; i++ {
		var skH fr.Element
		skH.Mul(&w.signers[i].sKey, &lagH[i])
		skTau.Add(&skTau, &skH)

		// Checking correctness of hTaus
		var hTau bls.G1Affine
		hTau.ScalarMultiplication(&w.crs.g1a, skH.BigInt(&big.Int{}))
		assert.Equal(t, hTau.Equal(&w.pp.hTaus[i]), true)
	}

	// Checking aggregated public key correctness
	var pComm bls.G1Affine
	pComm.ScalarMultiplication(&w.crs.g1a, skTau.BigInt(&big.Int{}))
	assert.Equal(t, pComm.Equal(&w.pp.pComm), true)

	// Checking whether lTaus are computed correcly or not
	lagL := GetLagAtSlow(w.crs.tau, w.crs.L)
	for i := 0; i < n; i++ {
		var skLl fr.Element
		var lTauL bls.G1Affine
		for l := 0; l < n-1; l++ {
			skLl.Mul(&w.signers[i].sKey, &lagL[l])
			lTauL.ScalarMultiplication(&w.crs.g1a, skLl.BigInt(&big.Int{}))
			assert.Equal(t, lTauL.Equal(&w.pp.lTaus[l][i]), true)
		}
	}
}

func BenchmarkKeyGen(b *testing.B) {
	signerCounts := []int{32, 64, 128, 256}

	for _, numSigners := range signerCounts {
		b.Run(fmt.Sprintf("Signers_%d", numSigners), func(b *testing.B) {
			weights := make([]int, numSigners)
			for i := 0; i < numSigners; i++ {
				weights[i] = i
			}

			crs := GenCRS(numSigners)
			w := WTS{
				n:       numSigners,
				weights: weights,
				crs:     crs,
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				w.keyGenBench()
			}
		})
	}
}

func BenchmarkCComp1(b *testing.B) {
	n := 1 << 15
	scalars := make([]fr.Element, n)
	b.ResetTimer()
	for i := 0; i < n; i++ {
		scalars[i].SetRandom()
	}
}

func BenchmarkCComp2(b *testing.B) {
	n := 1 << 15
	scalars := make([]fr.Element, n)

	b.ResetTimer()
	for i := 0; i < n; i++ {
		scalars[i].SetOne()
	}
}

func BenchmarkGenCRS(b *testing.B) {
	flag.Parse()
	n := *NUM_NODES

	weights := make([]int, n)
	for i := 0; i < n; i++ {
		weights[i] = i
	}
	crs := GenCRS(n)
	w := NewWTS(n, weights, crs)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.preProcess()
	}
}

func TestPreProcess(t *testing.T) {
	n := 1 << 8

	weights := make([]int, n)
	for i := 0; i < n; i++ {
		weights[i] = i
	}

	crs := GenCRS(n)
	w := NewWTS(n, weights, crs)
	w.preProcess()

	// tau^n-1
	var zTau fr.Element
	zTau.Exp(w.crs.tau, big.NewInt(int64(n)))
	one := fr.One()
	zTau.Sub(&zTau, &one)

	var lhsG, rhsG, qi bls.G1Affine
	lagH := GetAllLagAtWithOmegas(w.crs.H, w.crs.tau)
	for i := 0; i < n; i++ {
		lhsG.ScalarMultiplication(&w.pp.pComm, lagH[i].BigInt(&big.Int{}))
		rhsG.ScalarMultiplication(&w.signers[i].pKeyAff, lagH[i].BigInt(&big.Int{}))
		qi.ScalarMultiplication(&w.pp.qTaus[i], zTau.BigInt(&big.Int{}))
		rhsG.Add(&rhsG, &qi)
		assert.Equal(t, lhsG.Equal(&rhsG), true)
	}
}

func TestBin(t *testing.T) {
	n := 1 << 7
	weights := make([]int, n)
	for i := 0; i < n; i++ {
		weights[i] = i
	}

	crs := GenCRS(n)
	w := NewWTS(n, weights, crs)
	w.preProcess()

	var bTau bls.G1Affine
	var bNegTau bls.G2Affine

	var signers []int
	ths := 0
	for i := 0; i < n; i++ {
		if rand.Intn(2) == 1 {
			signers = append(signers, i)
			// sigmas = append(sigmas, w.psign(msg, w.signers[i]))
			bTau.Add(&bTau, &crs.lagHTaus[i])
			bNegTau.Add(&bNegTau, &crs.lag2HTaus[i])
			ths += weights[i]
		}
	}
	bTauG2 := bNegTau
	bNegTau.Sub(&crs.g2a, &bNegTau)
	qTau := w.binaryPf(signers)
	fmt.Println("Signers ", len(signers), "Threshold", ths)

	var bNegTauG1 bls.G1Affine
	bNegTauG1.Sub(&w.crs.g1a, &bTau)
	lhs, _ := bls.Pair([]bls.G1Affine{bNegTauG1}, []bls.G2Affine{crs.g2a})
	rhs, _ := bls.Pair([]bls.G1Affine{crs.g1a}, []bls.G2Affine{bNegTau})
	assert.Equal(t, lhs.Equal(&rhs), true, "Proving BNeg Correctness!")

	// Checking the binary relation
	lhs, _ = bls.Pair([]bls.G1Affine{bTau}, []bls.G2Affine{bNegTau})
	rhs, _ = bls.Pair([]bls.G1Affine{qTau}, []bls.G2Affine{w.crs.vHTau})
	assert.Equal(t, lhs.Equal(&rhs), true, "Proving Binary relation!")

	// Checking weights relation
	qwTau, rwTau, _ := w.weightsPf(signers)
	qwTauAff := *new(bls.G1Affine).FromJacobian(&qwTau)
	rwTauAff := *new(bls.G1Affine).FromJacobian(&rwTau)

	var gThs bls.G1Affine
	nInv := fr.NewElement(uint64(w.n))
	nInv.Inverse(&nInv)
	gThs.ScalarMultiplication(&w.crs.g1a, big.NewInt(int64(ths)))
	gThs.ScalarMultiplication(&gThs, nInv.BigInt(&big.Int{}))

	lhs, _ = bls.Pair([]bls.G1Affine{w.pp.wTau}, []bls.G2Affine{bTauG2})
	rhs, _ = bls.Pair([]bls.G1Affine{qwTauAff, rwTauAff, gThs}, []bls.G2Affine{w.crs.vHTau, w.crs.g2Tau, w.crs.g2a})
	assert.Equal(t, lhs.Equal(&rhs), true, "Proving weights!")
}

func TestWTS(t *testing.T) {
	msg := []byte("hello world")
	roMsg, _ := bls.HashToG2(msg, []byte{})

	n := 1 << 7
	weights := make([]int, n)
	for i := 0; i < n; i++ {
		weights[i] = i
	}

	crs := GenCRS(n)
	w := NewWTS(n, weights, crs)
	w.preProcess()

	var signers []int
	var sigmas []bls.G2Jac
	ths := 0
	for i := 0; i < n; i++ {
		signers = append(signers, i)
		sigmas = append(sigmas, w.psign(msg, w.signers[i]))
		ths += weights[i]
	}

	for i, idx := range signers {
		assert.Equal(t, w.pverify(roMsg, sigmas[i], w.signers[idx].pKeyAff), true)
	}

	sig := w.combine(signers, sigmas)
	assert.Equal(t, w.gverify(msg, sig, ths), true)
}
func TestDetailedWTSGVerify(t *testing.T) {
	n := 8
	weights := make([]int, n)
	for i := 0; i < n; i++ {
		weights[i] = i // Use i as weight
	}

	// 2. Initialize WTS system
	fmt.Println("Initializing WTS system...")
	crs := GenCRS(n)
	wtsSystem := NewWTS(n, weights, crs)
	wtsSystem.preProcess()

	// 3. Select all signers
	signers := make([]int, n)
	for i := 0; i < n; i++ {
		signers[i] = i
	}

	// 4. Create test message
	msg := []byte("This is a test message")

	// 5. Generate signatures for all signers
	fmt.Println("Generating signatures for all signers...")
	sigmas := make([]bls.G2Jac, n)
	totalWeight := 0
	for i := 0; i < n; i++ {
		sigmas[i] = wtsSystem.psign(msg, wtsSystem.signers[i])
		totalWeight += weights[i]
		fmt.Printf("Signer %d (weight: %d) generated signature\n", i, weights[i])
	}
	fmt.Printf("Total weight: %d\n", totalWeight)

	// 6. Aggregate signatures
	fmt.Println("Aggregating signatures...")
	signature := wtsSystem.combine(signers, sigmas)
	fmt.Printf("Aggregated weight: %d\n", signature.ths)

	// 7. Verify using modified gverify with detailed output
	threshold := totalWeight
	fmt.Printf("Detailed signature verification (threshold=%d)...\n", threshold)
	valid := DetailedGVerify(&wtsSystem, msg, signature, threshold)

	if valid {
		fmt.Println("✅ Detailed verification test successful")
	} else {
		t.Errorf("❌ Detailed verification test failed")
	}

	// 8. Check if weight verification works properly
	fmt.Println("Testing threshold verification separately...")
	thresholdValid := signature.ths >= threshold
	fmt.Printf("Threshold verification result: %v (signature.ths=%d, threshold=%d)\n",
		thresholdValid, signature.ths, threshold)

	// 9. Check if original gverify also fails
	fmt.Println("Verifying with original gverify...")
	originalValid := wtsSystem.gverify(msg, signature, threshold)
	if originalValid {
		fmt.Println("✅ Original gverify verification successful")
	} else {
		fmt.Println("❌ Original gverify verification failed")
	}
}

// DetailedGVerify is a version of gverify function with detailed debug output
func DetailedGVerify(w *WTS, msg []byte, sigma Sig, ths int) bool {
	fmt.Println("===== Detailed gverify debug start =====")
	fmt.Printf("sigma.ths=%d, required threshold=%d\n", sigma.ths, ths)

	// Initialize result as true
	var res bool = true
	pi := sigma.pi

	// 1. Check if aggregate signature is correct
	roMsg, _ := bls.HashToG2(msg, []byte{})
	signatureValid, _ := bls.PairingCheck(
		[]bls.G1Affine{sigma.aggPk, w.crs.g1InvAff},
		[]bls.G2Affine{roMsg, *new(bls.G2Affine).FromJacobian(&sigma.aggSig)},
	)
	fmt.Printf("Step 1. Aggregate signature verification: %v\n", signatureValid)
	res = res && signatureValid

	// Calculate g^{1/n}
	nInv := fr.NewElement(uint64(w.n))
	nInv.Inverse(&nInv)
	gNInv := *new(bls.G2Affine).FromJacobian(
		new(bls.G2Jac).ScalarMultiplication(&w.crs.g2, nInv.BigInt(&big.Int{})),
	)
	hNInv := *new(bls.G2Affine).ScalarMultiplication(&w.crs.h2a, nInv.BigInt(&big.Int{}))

	// 2. Check aggregate public key degree
	pkDegreeValid, _ := bls.PairingCheck(
		[]bls.G1Affine{sigma.aggPk, sigma.aggPkB},
		[]bls.G2Affine{w.crs.g2Ba, w.crs.g2InvAff},
	)
	fmt.Printf("Step 2. Aggregate public key degree verification: %v\n", pkDegreeValid)
	res = res && pkDegreeValid

	// 3. Check binary relation
	lhs, _ := bls.Pair([]bls.G1Affine{sigma.bTau}, []bls.G2Affine{sigma.bNegTau})
	rhs, _ := bls.Pair([]bls.G1Affine{sigma.qB}, []bls.G2Affine{w.crs.vHTau})
	binaryRelationValid := lhs.Equal(&rhs)
	fmt.Printf("Step 3. Binary relation verification: %v\n", binaryRelationValid)
	res = res && binaryRelationValid

	var b2Tau bls.G2Affine
	b2Tau.Sub(&w.crs.g2a, &sigma.bNegTau)

	xi := w.getFSChal([]bls.G1Affine{w.pp.pComm, w.pp.wTau, sigma.bTau, sigma.aggPk}, sigma.ths)

	oTau := new(bls.G1Affine).ScalarMultiplication(&w.pp.wTau, xi.BigInt(&big.Int{}))
	oTau.Add(oTau, &w.pp.pComm)

	tF := fr.NewElement(uint64(sigma.ths))
	xiT := *new(fr.Element).Mul(&xi, &tF)
	mu := new(bls.G1Affine).ScalarMultiplication(&w.crs.g1a, xiT.BigInt(&big.Int{}))
	mu.Add(mu, &sigma.aggPk)

	// 4. Check if inner product is correct
	lhs, _ = bls.Pair([]bls.G1Affine{*oTau}, []bls.G2Affine{b2Tau})
	rhs, _ = bls.Pair([]bls.G1Affine{pi.qTau, pi.rTau, *mu}, []bls.G2Affine{w.crs.vHTau, w.crs.g2Tau, gNInv})
	innerProductValid := lhs.Equal(&rhs)
	fmt.Printf("Step 4. Inner product verification: %v\n", innerProductValid)
	res = res && innerProductValid

	// 5. Check if rTau has correct degree
	lhs, _ = bls.Pair([]bls.G1Affine{sigma.pTau}, []bls.G2Affine{w.crs.g2a})
	rhs, _ = bls.Pair([]bls.G1Affine{pi.rTau, *mu}, []bls.G2Affine{w.crs.hTauHAff, hNInv})
	rTauDegreeValid := lhs.Equal(&rhs)
	fmt.Printf("Step 5. rTau degree verification: %v\n", rTauDegreeValid)
	res = res && rTauDegreeValid

	// 6. Check if threshold requirement is met
	thresholdValid := ths <= sigma.ths
	fmt.Printf("Step 6. Threshold verification: %v (required: %d <= actual: %d)\n", thresholdValid, ths, sigma.ths)

	// Final result
	finalResult := res && thresholdValid
	fmt.Printf("Final verification result: %v\n", finalResult)
	fmt.Println("===== Detailed gverify debug end =====")

	return finalResult
}
func BenchmarkWTS(b *testing.B) {
	flag.Parse()

	// Define node counts to test
	nodeCounts := []int{4, 8, 16, 32, 64, 128}
	msg := []byte("hello world")

	for _, n := range nodeCounts {
		// Create sub-test for each node count
		b.Run(fmt.Sprintf("Nodes_%d", n), func(b *testing.B) {
			// Set weights for each node
			weights := make([]int, n)
			for i := 0; i < n; i++ {
				weights[i] = i%10 + 1 // Use weights 1-10, avoid 0 or too large weights
			}

			// Generate CRS and WTS instance
			crs := GenCRS(n)
			w := NewWTS(n, weights, crs)

			// Store operation times
			kgenTimes := make([]time.Duration, 0, b.N)
			prepTimes := make([]time.Duration, 0, b.N)
			aggTimes := make([]time.Duration, 0, b.N)
			verTimes := make([]time.Duration, 0, b.N)

			// Test key generation
			b.Run("KGen", func(b *testing.B) {
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					start := time.Now()
					w.keyGenBench()
					kgenTimes = append(kgenTimes, time.Since(start))
				}
			})

			// Test preprocessing
			b.Run("Prep", func(b *testing.B) {
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					start := time.Now()
					w.preProcess()
					prepTimes = append(prepTimes, time.Since(start))
				}
			})

			// Prepare signature data
			ths := 0
			signers := make([]int, w.n)
			sigmas := make([]bls.G2Jac, w.n)
			for i := 0; i < w.n; i++ {
				signers[i] = i
				sigmas[i] = w.psign(msg, w.signers[i])
				ths += weights[i]
			}

			var sig Sig

			// Test aggregation
			b.Run("Agg", func(b *testing.B) {
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					start := time.Now()
					sig = w.combine(signers, sigmas)
					aggTimes = append(aggTimes, time.Since(start))
				}
			})

			// Test verification
			b.Run("Ver", func(b *testing.B) {
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					start := time.Now()
					w.gverify(msg, sig, ths)
					verTimes = append(verTimes, time.Since(start))
				}
			})

			// Calculate and report statistics
			kgenAvg, kgenStdDev := calculateStats(kgenTimes)
			prepAvg, prepStdDev := calculateStats(prepTimes)
			aggAvg, aggStdDev := calculateStats(aggTimes)
			verAvg, verStdDev := calculateStats(verTimes)

			// Report results in milliseconds
			fmt.Printf("\nPerformance statistics for node count = %d:\n", n)
			fmt.Printf("  KeyGen: avg=%.4fms, stddev=%.4fms, runs=%d\n",
				float64(kgenAvg)/float64(time.Millisecond),
				float64(kgenStdDev)/float64(time.Millisecond),
				len(kgenTimes))
			fmt.Printf("  Prep:   avg=%.4fms, stddev=%.4fms, runs=%d\n",
				float64(prepAvg)/float64(time.Millisecond),
				float64(prepStdDev)/float64(time.Millisecond),
				len(prepTimes))
			fmt.Printf("  Agg:    avg=%.4fms, stddev=%.4fms, runs=%d\n",
				float64(aggAvg)/float64(time.Millisecond),
				float64(aggStdDev)/float64(time.Millisecond),
				len(aggTimes))
			fmt.Printf("  Ver:    avg=%.4fms, stddev=%.4fms, runs=%d\n",
				float64(verAvg)/float64(time.Millisecond),
				float64(verStdDev)/float64(time.Millisecond),
				len(verTimes))

			// Report metrics using b.ReportMetric
			b.ReportMetric(float64(kgenAvg)/float64(time.Millisecond), "KeyGen-avg(ms)")
			b.ReportMetric(float64(kgenStdDev)/float64(time.Millisecond), "KeyGen-stddev(ms)")
			b.ReportMetric(float64(prepAvg)/float64(time.Millisecond), "Prep-avg(ms)")
			b.ReportMetric(float64(prepStdDev)/float64(time.Millisecond), "Prep-stddev(ms)")
			b.ReportMetric(float64(aggAvg)/float64(time.Millisecond), "Agg-avg(ms)")
			b.ReportMetric(float64(aggStdDev)/float64(time.Millisecond), "Agg-stddev(ms)")
			b.ReportMetric(float64(verAvg)/float64(time.Millisecond), "Ver-avg(ms)")
			b.ReportMetric(float64(verStdDev)/float64(time.Millisecond), "Ver-stddev(ms)")
		})
	}
}

// Test UpdateWeights function
func TestUpdateWeights(t *testing.T) {
	// Create WTS instance
	n := 5
	initialWeights := []int{1, 1, 1, 1, 1} // All signers have weight 1
	crs := GenCRS(n)
	wts := NewWTS(n, initialWeights, crs)

	// Verify initial weights are processed correctly
	initialWTau := wts.pp.wTau

	// Update to new weights
	newWeights := []int{2, 3, 1, 4, 5} // New weight distribution
	err := wts.UpdateWeights(newWeights)
	if err != nil {
		t.Fatalf("Failed to update weights: %v", err)
	}

	// Verify weights are updated
	if wts.weights[0] != 2 || wts.weights[1] != 3 || wts.weights[4] != 5 {
		t.Fatalf("Weights not updated correctly")
	}

	// Verify wTau is recalculated
	if wts.pp.wTau.Equal(&initialWTau) {
		t.Fatalf("Weight commitment wTau not recalculated")
	}

	// Try operations with new weights
	// For example, signing and verification...
}

// Do not user this test function, something wrong here
func TestWTSGVerify(t *testing.T) {
	// 1. Set up test parameters
	n := 5                            // Total number of signers
	weights := []int{1, 2, 3, 4, 5}   // Weight for each signer
	threshold := 8                    // Minimum required weight threshold
	selectedSigners := []int{2, 3, 4} // Selected signer indices (weights 3+4+5=12 > 8)

	// 2. Initialize WTS system
	fmt.Println("Initializing WTS system...")
	start := time.Now()
	crs := GenCRS(n)
	fmt.Printf("GenCRS time: %v\n", time.Since(start))

	wtsSystem := NewWTS(n, weights, crs)
	fmt.Printf("WTS system initialized, number of signers: %d\n", n)

	// 3. Preprocess WTS system
	start = time.Now()
	wtsSystem.preProcess()
	fmt.Printf("WTS preprocessing time: %v\n", time.Since(start))

	// 4. Create message for signing
	msg := []byte("This is a test message")

	// 5. Generate signatures for selected signers
	fmt.Println("Generating signatures...")
	sigmas := make([]bls.G2Jac, len(selectedSigners))
	for i, idx := range selectedSigners {
		sigmas[i] = wtsSystem.psign(msg, wtsSystem.signers[idx])
		fmt.Printf("Signer %d (weight: %d) generated signature\n", idx, wtsSystem.weights[idx])
	}

	// 6. Aggregate signatures
	fmt.Println("Aggregating signatures...")
	start = time.Now()
	signature := wtsSystem.combine(selectedSigners, sigmas)
	fmt.Printf("Aggregation time: %v\n", time.Since(start))
	fmt.Printf("Aggregated weight: %d\n", signature.ths)

	// 7. Verify signature
	fmt.Println("Verifying signature...")
	start = time.Now()
	valid := wtsSystem.gverify(msg, signature, threshold)
	fmt.Printf("Verification time: %v\n", time.Since(start))

	if valid {
		fmt.Println("✅ Test successful: Signature verification passed")
	} else {
		t.Errorf("❌ Test failed: Signature verification failed")
	}

	// 8. Test threshold verification - Case with threshold higher than aggregated weight
	highThreshold := 15 // Higher than aggregated signature weight 12
	valid = wtsSystem.gverify(msg, signature, highThreshold)
	if !valid {
		fmt.Printf("✅ Test successful: Threshold(%d) higher than aggregated weight(%d), verification failed\n", highThreshold, signature.ths)
	} else {
		t.Errorf("❌ Test failed: Threshold(%d) higher than aggregated weight(%d), but verification passed\n", highThreshold, signature.ths)
	}

	// 9. Test threshold verification - Case with threshold lower than aggregated weight
	lowThreshold := 6 // Lower than aggregated signature weight 12
	valid = wtsSystem.gverify(msg, signature, lowThreshold)
	if valid {
		fmt.Printf("✅ Test successful: Threshold(%d) lower than aggregated weight(%d), verification passed\n", lowThreshold, signature.ths)
	} else {
		t.Errorf("❌ Test failed: Threshold(%d) lower than aggregated weight(%d), but verification failed\n", lowThreshold, signature.ths)
	}

	// 10. Test message modification
	differentMsg := []byte("This is a different message")
	valid = wtsSystem.gverify(differentMsg, signature, threshold)
	if !valid {
		fmt.Println("✅ Test successful: Modified message verification failed")
	} else {
		t.Errorf("❌ Test failed: Modified message should fail verification, but passed")
	}

	// 11. Test insufficient weight case
	insufficientSigners := []int{0, 1} // Total weight 1+2=3 < 8
	insufficientSigmas := make([]bls.G2Jac, len(insufficientSigners))
	for i, idx := range insufficientSigners {
		insufficientSigmas[i] = wtsSystem.psign(msg, wtsSystem.signers[idx])
		fmt.Printf("Signer %d (weight: %d) generated signature\n", idx, wtsSystem.weights[idx])
	}

	insufficientSignature := wtsSystem.combine(insufficientSigners, insufficientSigmas)
	fmt.Printf("Insufficient weight aggregated weight: %d\n", insufficientSignature.ths)

	valid = wtsSystem.gverify(msg, insufficientSignature, threshold)
	if !valid {
		fmt.Printf("✅ Test successful: Insufficient weight(%d < %d), verification failed\n", insufficientSignature.ths, threshold)
	} else {
		t.Errorf("❌ Test failed: Insufficient weight(%d < %d), but verification passed\n", insufficientSignature.ths, threshold)
	}

	// 12. Test signer replacement - Using different signers with same total weight
	alternateSigners := []int{1, 3, 4} // Total weight 2+4+5=11 > 8
	alternateSigmas := make([]bls.G2Jac, len(alternateSigners))
	for i, idx := range alternateSigners {
		alternateSigmas[i] = wtsSystem.psign(msg, wtsSystem.signers[idx])
		fmt.Printf("Alternate signer %d (weight: %d) generated signature\n", idx, wtsSystem.weights[idx])
	}

	alternateSignature := wtsSystem.combine(alternateSigners, alternateSigmas)
	fmt.Printf("Alternate signers aggregated weight: %d\n", alternateSignature.ths)

	valid = wtsSystem.gverify(msg, alternateSignature, threshold)
	if valid {
		fmt.Printf("✅ Test successful: Alternate signers verification passed (weight %d > %d)\n", alternateSignature.ths, threshold)
	} else {
		t.Errorf("❌ Test failed: Alternate signers should pass verification, but failed")
	}

	// 13. Test signature tampering
	fmt.Println("Testing signature tampering...")
	tamperedSignature := signature
	// Tamper with a field in the signature
	var tamperedValue bls.G1Jac
	tamperedValue.ScalarMultiplication(&wtsSystem.crs.g1, big.NewInt(123456))
	tamperedSignature.qB = *new(bls.G1Affine).FromJacobian(&tamperedValue)

	valid = wtsSystem.gverify(msg, tamperedSignature, threshold)
	if !valid {
		fmt.Println("✅ Test successful: Tampered signature verification failed")
	} else {
		t.Errorf("❌ Test failed: Tampered signature should fail verification, but passed")
	}

	// 14. Test weight update
	fmt.Println("Testing weight update...")
	newWeights := []int{2, 3, 4, 5, 6} // Increase each signer's weight
	err := wtsSystem.UpdateWeights(newWeights)
	if err != nil {
		t.Errorf("Failed to update weights: %v", err)
	}

	// Generate signatures with new weights
	newSigners := []int{2, 3} // New weights 4+5=9 > 8
	newSigmas := make([]bls.G2Jac, len(newSigners))
	for i, idx := range newSigners {
		newSigmas[i] = wtsSystem.psign(msg, wtsSystem.signers[idx])
		fmt.Printf("Signer %d with new weight (weight: %d) generated signature\n", idx, wtsSystem.weights[idx])
	}

	newSignature := wtsSystem.combine(newSigners, newSigmas)
	fmt.Printf("New weights aggregated weight: %d\n", newSignature.ths)

	valid = wtsSystem.gverify(msg, newSignature, threshold)
	if valid {
		fmt.Printf("✅ Test successful: New weights verification passed (weight %d > %d)\n", newSignature.ths, threshold)
	} else {
		t.Errorf("❌ Test failed: New weights should pass verification, but failed")
	}

	fmt.Println("All tests completed")
}

func TestWTSCriticalPointFinder(t *testing.T) {
	// Test different numbers of signers
	msg := []byte("hello world")

	// Try different values of n, from small to large
	for n := 4; n <= 32; n *= 2 {
		fmt.Printf("\n===== Testing n=%d =====\n", n)

		weights := make([]int, n)
		for i := 0; i < n; i++ {
			weights[i] = i
		}

		crs := GenCRS(n)
		w := NewWTS(n, weights, crs)
		w.preProcess()

		var signers []int
		var sigmas []bls.G2Jac
		ths := 0
		for i := 0; i < n; i++ {
			signers = append(signers, i)
			sigmas = append(sigmas, w.psign(msg, w.signers[i]))
			ths += weights[i]
		}

		sig := w.combine(signers, sigmas)
		fmt.Printf("Aggregated weight: %d\n", sig.ths)

		// Use detailed gverify
		fmt.Println("Using detailed gverify...")
		detailedValid := DetailedGVerify(&w, msg, sig, ths)

		// Use original gverify
		fmt.Println("Using original gverify...")
		originalValid := w.gverify(msg, sig, ths)

		fmt.Printf("n=%d verification results: detailed=%v, original=%v\n", n, detailedValid, originalValid)
	}
}

func TestWTSExact(t *testing.T) {
	// Copy exact parameters and process from TestWTS
	msg := []byte("hello world")
	roMsg, _ := bls.HashToG2(msg, []byte{})

	n := 1 << 7 // 128
	weights := make([]int, n)
	for i := 0; i < n; i++ {
		weights[i] = i
	}

	fmt.Println("Initializing large WTS system (n=128)...")
	crs := GenCRS(n)
	w := NewWTS(n, weights, crs)
	w.preProcess()

	var signers []int
	var sigmas []bls.G2Jac
	ths := 0
	for i := 0; i < n; i++ {
		signers = append(signers, i)
		sigmas = append(sigmas, w.psign(msg, w.signers[i]))
		ths += weights[i]
	}
	fmt.Printf("Total signers: %d, Total weight: %d\n", len(signers), ths)

	// Verify individual signatures
	fmt.Println("Verifying individual signatures...")
	for i, idx := range signers {
		if i%20 == 0 { // Only print some results to reduce output
			isValid := w.pverify(roMsg, sigmas[i], w.signers[idx].pKeyAff)
			fmt.Printf("Signer %d signature verification: %v\n", idx, isValid)
			if !isValid {
				t.Errorf("Signer %d signature verification failed", idx)
			}
		}
	}

	// Aggregate and verify
	fmt.Println("Aggregating and verifying signatures...")
	sig := w.combine(signers, sigmas)
	fmt.Printf("Aggregated weight: %d, Required threshold: %d\n", sig.ths, ths)

	isValid := w.gverify(msg, sig, ths)
	if isValid {
		fmt.Println("✅ Large test successful: Verification passed")
	} else {
		t.Errorf("❌ Large test failed: Verification failed")
	}
}
