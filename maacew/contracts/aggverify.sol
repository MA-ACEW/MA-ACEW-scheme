// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.0;

import "./BN254.sol";

/**
 * @title BLSAggVerifyBenchmark
 * @dev 
 */
contract BLSAggVerifyBenchmark {
    using BN254 for *;
    
   
    struct TestResult {
        uint256 standardGas;       
        uint256 optimizedGas;     
        bool standardSuccess;      
        bool optimizedSuccess;     
        uint256 savingsPercent;   
    }
    
    TestResult public testResult;
    
   
    event DebugLog(string message, uint256 value);
    event TestCompleted(uint256 standardGas, uint256 optimizedGas, bool standardSuccess, bool optimizedSuccess);
    event MultiVerifyResult(uint256 count, uint256 standardGas, uint256 optimizedGas);
    
   
    struct Signature {
        BN254.G1Point h;     
        BN254.G1Point s;     
    }
    
    struct Tag {
        BN254.G1Point hGamma; // h^γ
        BN254.G1Point hDelta; // h^δ
    }
    
    struct VerifierKey {
        BN254.G2Point lvk1;  
        BN254.G2Point lvk2;   
        BN254.G2Point tvk;   
    }
    
    /**
     * @dev 
     */
    function aggVerifyStandard() public view returns (bool) {
        // 
        BN254.G1Point memory g1 = BN254.P1();
        BN254.G2Point memory g2 = BN254.P2();
        
      
        Signature memory aggSig;
        Tag memory tag;
        VerifierKey memory vk;
        
     
        tag.hGamma = BN254.scalarMul(g1, 123);
        tag.hDelta = BN254.scalarMul(g1, 456);
        aggSig.h = tag.hGamma; 
        aggSig.s = BN254.scalarMul(g1, 789);
        
       
        vk.lvk1 = g2; 
        vk.tvk = g2; 
        
        
        BN254.G1Point memory hDeltaJ = tag.hDelta;
        
      
        BN254.G2Point memory negG2 = BN254.G2Point(
            g2.x0,
            g2.x1,
            BN254.P_MOD - g2.y0,
            BN254.P_MOD - g2.y1
        );
        
        // e(h', ∑(lvk1_i + lvk2_i*m_i)) * e((h^δ)^j, ∑Z_i) * e(s, -g2)
        BN254.G1Point[3] memory g1Points;
        BN254.G2Point[3] memory g2Points;
        
        g1Points[0] = aggSig.h;
        g1Points[1] = hDeltaJ;
        g1Points[2] = aggSig.s;
        
        g2Points[0] = vk.lvk1;
        g2Points[1] = vk.tvk;
        g2Points[2] = negG2;
        
       
        return BN254.pairing3(g1Points, g2Points);
    }
    
    /**
     * @dev
     */
    function aggVerifyOptimized() public view returns (bool) {
   
        BN254.G1Point memory g1 = BN254.P1();
        BN254.G2Point memory g2 = BN254.P2();
        
        
        Signature memory aggSig;
        Tag memory tag;
        VerifierKey memory vk;
        
        
        tag.hGamma = BN254.scalarMul(g1, 123);
        tag.hDelta = BN254.scalarMul(g1, 456);
        aggSig.h = tag.hGamma; 
        aggSig.s = BN254.scalarMul(g1, 789);
        
      
        vk.lvk1 = g2; 
        vk.tvk = g2; 
        
      
        BN254.G1Point memory hDeltaJ = tag.hDelta;
        
       
        BN254.G2Point memory negG2 = BN254.G2Point(
            g2.x0,
            g2.x1,
            BN254.P_MOD - g2.y0,
            BN254.P_MOD - g2.y1
        );
        
      
        uint256 seed = uint256(keccak256(abi.encodePacked(block.timestamp, blockhash(block.number - 1))));
        uint256 rho = (uint256(keccak256(abi.encodePacked(seed, uint256(1)))) % (BN254.R_MOD - 1)) + 1;
        uint256 rho_2 = mulmod(rho, rho, BN254.R_MOD);
        uint256 rho_3 = mulmod(rho_2, rho, BN254.R_MOD);
        
    
        BN254.G1Point[3] memory left;
        BN254.G2Point[3] memory right;
        
       
        left[0] = BN254.scalarMul(aggSig.h, rho);
        right[0] = vk.lvk1;
        
       
        left[1] = BN254.scalarMul(hDeltaJ, rho_2);
        right[1] = vk.tvk;
        
      
        left[2] = BN254.scalarMul(aggSig.s, rho_3);
        right[2] = negG2;
        
       
        return BN254.pairing3(left, right);
    }
    
    /**
     * @dev 
     */
    function testStandardVerify() public returns (bool success, uint256 gasUsed) {
        uint256 startGas = gasleft();
        success = aggVerifyStandard();
        gasUsed = startGas - gasleft();
        
        emit DebugLog("Standard verification gas", gasUsed);
        
        return (success, gasUsed);
    }
    
    /**
     * @dev 
     */
    function testOptimizedVerify() public returns (bool success, uint256 gasUsed) {
        uint256 startGas = gasleft();
        success = aggVerifyOptimized();
        gasUsed = startGas - gasleft();
        
        emit DebugLog("Optimized verification gas", gasUsed);
        
        return (success, gasUsed);
    }
    
    /**
     * @dev 
     */
    function runAllTests() public {
        (bool standardSuccess, uint256 standardGas) = testStandardVerify();
        (bool optimizedSuccess, uint256 optimizedGas) = testOptimizedVerify();
        
       
        uint256 savingsPercent = 0;
        if (standardGas > optimizedGas) {
            savingsPercent = ((standardGas - optimizedGas) * 100) / standardGas;
        }
        
     
        testResult = TestResult({
            standardGas: standardGas,
            optimizedGas: optimizedGas,
            standardSuccess: standardSuccess,
            optimizedSuccess: optimizedSuccess,
            savingsPercent: savingsPercent
        });
        
        emit TestCompleted(standardGas, optimizedGas, standardSuccess, optimizedSuccess);
    }
    
    /**
     * @dev 
     */
    function testMultipleVerifications(uint256 count) public returns (uint256 standardTotalGas, uint256 optimizedTotalGas) {

        uint256 startGas = gasleft();
        bool standardSuccess = true;
        for (uint256 i = 0; i < count; i++) {
            standardSuccess = standardSuccess && aggVerifyStandard();
        }
        standardTotalGas = startGas - gasleft();
        
      
        startGas = gasleft();
        bool optimizedSuccess = true;
        for (uint256 i = 0; i < count; i++) {
            optimizedSuccess = optimizedSuccess && aggVerifyOptimized();
        }
        optimizedTotalGas = startGas - gasleft();
        
        emit DebugLog("Standard total gas for multiple verifications", standardTotalGas);
        emit DebugLog("Optimized total gas for multiple verifications", optimizedTotalGas);
        emit MultiVerifyResult(count, standardTotalGas, optimizedTotalGas);
        
        return (standardTotalGas, optimizedTotalGas);
    }
    
    /**
     * @dev 
     */
    function getTestResults() public view returns (
        uint256 standardGas,
        uint256 optimizedGas,
        bool standardSuccess,
        bool optimizedSuccess,
        uint256 savingsPercent
    ) {
        return (
            testResult.standardGas,
            testResult.optimizedGas,
            testResult.standardSuccess,
            testResult.optimizedSuccess,
            testResult.savingsPercent
        );
    }

}
