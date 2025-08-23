// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.0;

import "./BN254.sol";

/**
 * @title BLSVerificationBenchmark
 * @dev 
 */
contract BLSVerificationBenchmark {
    using BN254 for *;
    
 
    struct G2Point {
        uint256 x0;
        uint256 x1;
        uint256 y0;
        uint256 y1;
    }
    
    
    struct TestResult {
        uint256 standardGas1;        
        uint256 optimizedGas1;         
        uint256 standardGas5;        
        uint256 optimizedGas5;        
        uint256 standardGas10;        
        uint256 optimizedGas10;        
        uint256 standardSuccess1;      
        uint256 optimizedSuccess1;    
    }
    
 
    TestResult public testResult;
    
   
    struct Signature {
        BN254.G1Point h;
        BN254.G1Point s;
    }
    
    struct Tag {
        BN254.G1Point hGamma;
        BN254.G1Point hDelta;
    }
    
    struct VerifierKey {
        G2Point lvk1;
        G2Point lvk2;
        G2Point tvk;
    }
    
  
    event DebugLog(string message, uint256 value);
    event TestCompleted(uint256 standard1, uint256 optimized1, uint256 standard5, uint256 optimized5, uint256 standard10, uint256 optimized10);
    
    constructor() {}
    
    
    function standardVerification(
        uint64 j,
        Signature memory aggSig,
        Tag memory tag,
        uint256[] memory messages,
        VerifierKey[] memory verificationKeys
    ) public view returns (bool) {
       
        require(messages.length == verificationKeys.length, "Message and key count mismatch");
        require(messages.length > 0, "No messages to verify");
        
      
        if (isInfinity(aggSig.h)) {
            return false;
        }
        
       
        G2Point memory temp1 = emptyG2Point();
        G2Point memory Z = emptyG2Point();
        
        for (uint i = 0; i < messages.length; i++) {
          
            G2Point memory combined = addG2(
                verificationKeys[i].lvk1,
                scalarMulG2(verificationKeys[i].lvk2, messages[i])
            );
            
            if (i == 0) {
                temp1 = combined;
                Z = verificationKeys[i].tvk;
            } else {
                temp1 = addG2(temp1, combined);
                Z = addG2(Z, verificationKeys[i].tvk);
            }
        }
        
     
        BN254.G1Point memory temp2 = BN254.scalarMul(tag.hDelta, j);
        
       
        return verifyPairing(aggSig.h, convertToG2(temp1), temp2, convertToG2(Z), aggSig.s);
    }
    
  
    function optimizedVerification(
        uint64 j,
        Signature memory aggSig,
        Tag memory tag,
        uint256[] memory messages,
        VerifierKey[] memory verificationKeys
    ) public view returns (bool) {
       
        require(messages.length == verificationKeys.length, "Message and key count mismatch");
        require(messages.length > 0, "No messages to verify");
        
      
        if (isInfinity(aggSig.h)) {
            return false;
        }
        
       
        G2Point memory temp1 = emptyG2Point();
        G2Point memory Z = emptyG2Point();
        
        for (uint i = 0; i < messages.length; i++) {
          
            G2Point memory combined = addG2(
                verificationKeys[i].lvk1,
                scalarMulG2(verificationKeys[i].lvk2, messages[i])
            );
            
            if (i == 0) {
                temp1 = combined;
                Z = verificationKeys[i].tvk;
            } else {
                temp1 = addG2(temp1, combined);
                Z = addG2(Z, verificationKeys[i].tvk);
            }
        }
        
      
        BN254.G1Point memory temp2 = BN254.scalarMul(tag.hDelta, j);
        
       
        uint256 seed = uint256(keccak256(abi.encodePacked(
            block.timestamp,
            aggSig.h.x, 
            aggSig.h.y
        )));
        
       
        uint256 r1 = (uint256(keccak256(abi.encodePacked(seed, uint256(1)))) % (BN254.R_MOD - 1)) + 1;
        uint256 r2 = (uint256(keccak256(abi.encodePacked(seed, uint256(2)))) % (BN254.R_MOD - 1)) + 1;
        
       
        BN254.G1Point memory combinedG1 = aggSig.h;
        combinedG1 = BN254.add(combinedG1, BN254.scalarMul(temp2, r1));
        combinedG1 = BN254.add(combinedG1, BN254.scalarMul(aggSig.s, r2));
        
        
        uint256 r1Inv = BN254.invert(r1);
        uint256 r2Inv = BN254.invert(r2);
        
     
        G2Point memory scaledZ = scalarMulG2(Z, r1Inv);
        G2Point memory negG2 = getNegativeG2Generator();
        G2Point memory scaledNegG2 = scalarMulG2(negG2, r2Inv);
        
        G2Point memory combinedG2 = addG2(temp1, scaledZ);
        combinedG2 = addG2(combinedG2, scaledNegG2);
        
      
        return verifySinglePairing(combinedG1, convertToG2(combinedG2));
    }
    
    /**
     * @dev 
     */
    function verifyPairing(
        BN254.G1Point memory a, BN254.G2Point memory A,
        BN254.G1Point memory b, BN254.G2Point memory B,
        BN254.G1Point memory c
    ) internal view returns (bool) {
        BN254.G1Point[3] memory g1Points;
        BN254.G2Point[3] memory g2Points;
        
        g1Points[0] = a;
        g1Points[1] = b;
        g1Points[2] = c;
        
        g2Points[0] = A;
        g2Points[1] = B;
        g2Points[2] = getNegativeG2Point(); // -g2
        
        return BN254.pairing3(g1Points, g2Points);
    }
    
    /**
     * @dev
     */
    function getNegativeG2Point() internal view returns (BN254.G2Point memory) {
        BN254.G2Point memory g2 = BN254.P2();
       
        return BN254.G2Point({
            x0: g2.x0,
            x1: g2.x1,
            y0: BN254.P_MOD - g2.y0,
            y1: BN254.P_MOD - g2.y1
        });
    }
    
    /**
     * @dev 
     */
    function verifySinglePairing(BN254.G1Point memory p1, BN254.G2Point memory p2) 
        internal view returns (bool) 
    {
        uint256[] memory input = new uint256[](12);
        
        input[0] = p1.x;
        input[1] = p1.y;
        input[2] = p2.x0;
        input[3] = p2.x1;
        input[4] = p2.y0;
        input[5] = p2.y1;
        
      
        input[6] = 0;
        input[7] = 0;
        input[8] = 0;
        input[9] = 0;
        input[10] = 0;
        input[11] = 0;
        
        uint256[1] memory out;
        bool success;
        
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(12, 0x20), out, 0x20)
            switch success case 0 { invalid() }
        }
        
        require(success, "pairing-opcode-failed");
        return out[0] != 0;
    }
    
    /**
     * @dev
     */
    function generateTestData(uint256 count) internal view returns (
        Signature memory aggSig,
        Tag memory tag,
        uint256[] memory messages,
        VerifierKey[] memory verificationKeys
    ) {
       
        BN254.G1Point memory g1 = BN254.P1();
        BN254.G2Point memory g2 = BN254.P2();
        
       
        aggSig = Signature({
            h: g1,
            s: BN254.scalarMul(g1, 123)
        });
        
        tag = Tag({
            hGamma: BN254.scalarMul(g1, 456),
            hDelta: BN254.scalarMul(g1, 789)
        });
        
       
        messages = new uint256[](count);
        for (uint256 i = 0; i < count; i++) {
            messages[i] = i + 1;
        }
        
    
        verificationKeys = new VerifierKey[](count);
        for (uint256 i = 0; i < count; i++) {
        
            G2Point memory lvk1 = G2Point({
                x0: g2.x0,
                x1: g2.x1,
                y0: g2.y0,
                y1: g2.y1
            });
            
            G2Point memory lvk2 = G2Point({
                x0: g2.x0,
                x1: g2.x1,
                y0: g2.y0,
                y1: g2.y1
            });
            
            G2Point memory tvk = G2Point({
                x0: g2.x0,
                x1: g2.x1,
                y0: g2.y0,
                y1: g2.y1
            });
            
            verificationKeys[i] = VerifierKey({
                lvk1: lvk1,
                lvk2: lvk2,
                tvk: tvk
            });
        }
    }
    
    /**
     * @dev 
     */
    function test1MessageVerification() public {
        (
            Signature memory aggSig,
            Tag memory tag,
            uint256[] memory allMessages,
            VerifierKey[] memory allKeys
        ) = generateTestData(10);
        
    
        uint256[] memory messages = new uint256[](1);
        VerifierKey[] memory keys = new VerifierKey[](1);
        messages[0] = allMessages[0];
        keys[0] = allKeys[0];
        
      
        uint256 startGas = gasleft();
        bool standardSuccess = standardVerification(1, aggSig, tag, messages, keys);
        uint256 standardGas = startGas - gasleft();
        
       
        startGas = gasleft();
        bool optimizedSuccess = optimizedVerification(1, aggSig, tag, messages, keys);
        uint256 optimizedGas = startGas - gasleft();
        
       
        testResult.standardGas1 = standardGas;
        testResult.optimizedGas1 = optimizedGas;
        testResult.standardSuccess1 = standardSuccess ? 1 : 0;
        testResult.optimizedSuccess1 = optimizedSuccess ? 1 : 0;
        
        emit DebugLog("Standard 1 gas", standardGas);
        emit DebugLog("Optimized 1 gas", optimizedGas);
    }
    
    /**
     * @dev 
     */
    function test5MessageVerification() public {
        (
            Signature memory aggSig,
            Tag memory tag,
            uint256[] memory allMessages,
            VerifierKey[] memory allKeys
        ) = generateTestData(10);
        
       
        uint256[] memory messages = new uint256[](5);
        VerifierKey[] memory keys = new VerifierKey[](5);
        for (uint i = 0; i < 5; i++) {
            messages[i] = allMessages[i];
            keys[i] = allKeys[i];
        }
        
       
        uint256 startGas = gasleft();
        standardVerification(1, aggSig, tag, messages, keys);
        uint256 standardGas = startGas - gasleft();
        
     
        startGas = gasleft();
        optimizedVerification(1, aggSig, tag, messages, keys);
        uint256 optimizedGas = startGas - gasleft();
        
       
        testResult.standardGas5 = standardGas;
        testResult.optimizedGas5 = optimizedGas;
        
        emit DebugLog("Standard 5 gas", standardGas);
        emit DebugLog("Optimized 5 gas", optimizedGas);
    }
    
    /**
     * @dev 
     */
    function test10MessageVerification() public {
        (
            Signature memory aggSig,
            Tag memory tag,
            uint256[] memory messages,
            VerifierKey[] memory keys
        ) = generateTestData(10);
        
        
        uint256 startGas = gasleft();
        standardVerification(1, aggSig, tag, messages, keys);
        uint256 standardGas = startGas - gasleft();
        
      
        startGas = gasleft();
        optimizedVerification(1, aggSig, tag, messages, keys);
        uint256 optimizedGas = startGas - gasleft();
        
      
        testResult.standardGas10 = standardGas;
        testResult.optimizedGas10 = optimizedGas;
        
        emit DebugLog("Standard 10 gas", standardGas);
        emit DebugLog("Optimized 10 gas", optimizedGas);
    }
    
    /**
     * @dev 
     */
    function runAllTests() public {
        test1MessageVerification();
        test5MessageVerification();
        test10MessageVerification();
        
        emit TestCompleted(
            testResult.standardGas1,
            testResult.optimizedGas1,
            testResult.standardGas5,
            testResult.optimizedGas5,
            testResult.standardGas10,
            testResult.optimizedGas10
        );
    }
    
    /**
     * @dev
     */
    function getTestResults() public view returns (
        uint256 standardGas1,
        uint256 optimizedGas1,
        uint256 standardGas5,
        uint256 optimizedGas5,
        uint256 standardGas10,
        uint256 optimizedGas10,
        uint256 savings1,
        uint256 savings5,
        uint256 savings10
    ) {
      
        uint256 savings1Calc = testResult.standardGas1 > 0 ? 
            ((testResult.standardGas1 - testResult.optimizedGas1) * 100) / testResult.standardGas1 : 0;
            
        uint256 savings5Calc = testResult.standardGas5 > 0 ? 
            ((testResult.standardGas5 - testResult.optimizedGas5) * 100) / testResult.standardGas5 : 0;
            
        uint256 savings10Calc = testResult.standardGas10 > 0 ? 
            ((testResult.standardGas10 - testResult.optimizedGas10) * 100) / testResult.standardGas10 : 0;
        
        return (
            testResult.standardGas1,
            testResult.optimizedGas1,
            testResult.standardGas5,
            testResult.optimizedGas5,
            testResult.standardGas10,
            testResult.optimizedGas10,
            savings1Calc,
            savings5Calc,
            savings10Calc
        );
    }
    
   
    
    function isInfinity(BN254.G1Point memory p) internal pure returns (bool) {
        return (p.x == 0 && p.y == 0);
    }
    
    function emptyG2Point() internal pure returns (G2Point memory) {
        return G2Point({
            x0: 0,
            x1: 0,
            y0: 0,
            y1: 0
        });
    }
    
    function addG2(G2Point memory a, G2Point memory b) internal pure returns (G2Point memory) {
        return G2Point({
            x0: addmod(a.x0, b.x0, BN254.P_MOD),
            x1: addmod(a.x1, b.x1, BN254.P_MOD),
            y0: addmod(a.y0, b.y0, BN254.P_MOD),
            y1: addmod(a.y1, b.y1, BN254.P_MOD)
        });
    }
    
    function scalarMulG2(G2Point memory point, uint256 scalar) internal pure returns (G2Point memory) {
        return G2Point({
            x0: mulmod(point.x0, scalar, BN254.P_MOD),
            x1: mulmod(point.x1, scalar, BN254.P_MOD),
            y0: mulmod(point.y0, scalar, BN254.P_MOD),
            y1: mulmod(point.y1, scalar, BN254.P_MOD)
        });
    }
    
    function getNegativeG2Generator() internal view returns (G2Point memory) {
        BN254.G2Point memory g2 = BN254.P2();
        return G2Point({
            x0: g2.x0,
            x1: g2.x1,
            y0: BN254.P_MOD - g2.y0,
            y1: BN254.P_MOD - g2.y1
        });
    }
    
    function convertToG2(G2Point memory point) internal pure returns (BN254.G2Point memory) {
        return BN254.G2Point({
            x0: point.x0,
            x1: point.x1,
            y0: point.y0,
            y1: point.y1
        });
    }

}
