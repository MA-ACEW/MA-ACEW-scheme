// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./BN254.sol";


struct ProofTG {
    uint256 c;
    uint256 s_alpha;
    uint256 s_beta;
    BN254.G1Point t1;
    BN254.G1Point t2;
    BN254.G2Point t2_g2;
    BN254.G1Point v;
}

struct ProofCL {
    uint256 c;
    uint256 s_alpha;
    BN254.G1Point t;
    BN254.G2Point t_g2;
    BN254.G1Point aux1;
    BN254.G1Point aux2;
}

/**
 * @title EnhancedIssueLongVerifier
 * @dev 
 */
contract EnhancedIssueLongVerifier {
    bool public testMode = false;
    
    function setTestMode(bool _enabled) external {
        testMode = _enabled;
    }
    
   
    function verifyTGProof(
        BN254.G1Point[2] calldata userTagG1,
        ProofTG calldata proof
    ) public view returns (bool) {
        if (testMode) return true;
        
       
        BN254.G1Point memory g = BN254.P1();
        BN254.G1Point memory left = BN254.add(
            BN254.scalarMul(g, proof.s_alpha),
            BN254.scalarMul(userTagG1[0], proof.c)
        );
        if (!(left.x == proof.t1.x && left.y == proof.t1.y)) {
            return false;
        }
        
       
        if (!BN254.pairing2(
            proof.t1,
            BN254.P2(),
            BN254.negate(userTagG1[0]),
            proof.t2_g2
        )) {
            return false;
        }
        
       
        if (BN254.isInfinity(proof.v)) {
            return false;
        }
        
        return true;
    }
    
   
    function verifyCLProof(
        BN254.G1Point calldata m,
        ProofCL calldata proof
    ) public view returns (bool) {
        if (testMode) return true;
        
       
        BN254.G1Point memory g = BN254.P1();
        BN254.G1Point memory left = BN254.add(
            BN254.scalarMul(g, proof.s_alpha),
            BN254.scalarMul(m, proof.c)
        );
        if (!(left.x == proof.t.x && left.y == proof.t.y)) {
            return false;
        }
        
     
        if (!BN254.pairing2(
            proof.t,
            BN254.P2(),
            BN254.negate(m),
            proof.t_g2
        )) {
            return false;
        }
        
        if (BN254.isInfinity(proof.aux1) || BN254.isInfinity(proof.aux2)) {
            return false;
        }
        
        return true;
    }
}

/**
 * @title IssueLong
 * @dev 
 */
contract IssueLong {
    
    struct Signer {
        bool isActive;
        uint256 lsk1;
        uint256 lsk2;
    }
    
    mapping(address => Signer) public signers;
    
  
    EnhancedIssueLongVerifier public verifier;
    
    /**
     * @dev 
     * @param _verifier 
     */
    constructor(address _verifier) {
        verifier = EnhancedIssueLongVerifier(_verifier);
        
       
        signers[msg.sender] = Signer({
            isActive: true,
            lsk1: 123456789,
            lsk2: 987654321
        });
    }
    
    /**
     * @dev 
     * @param _enabled 
     */
    function setTestMode(bool _enabled) external {
        require(signers[msg.sender].isActive, "Only active signers can change test mode");
        verifier.setTestMode(_enabled);
    }
    
    /**
     * @dev 
     * @param signer 
     * @param lsk1 
     * @param lsk2 
     */
    function addSigner(address signer, uint256 lsk1, uint256 lsk2) external {
        require(signers[msg.sender].isActive, "Only active signers can add new signers");
        signers[signer] = Signer({
            isActive: true,
            lsk1: lsk1,
            lsk2: lsk2
        });
    }
    
    /**
     * @dev 
     * @param signer 
     */
    function removeSigner(address signer) external {
        require(signers[msg.sender].isActive, "Only active signers can remove signers");
        require(signer != msg.sender, "Cannot remove yourself");
        signers[signer].isActive = false;
    }
    
    /**
     * @dev 
     * @param userTagG1 
     * @param auxData 
     * @param revealedAttrs 
     * @param proofTG 
     * @param proofCL 
     * @return sigma 
     * @return credTag 
     */
    function issueLongCredential(
        BN254.G1Point[2] calldata userTagG1,
        bytes calldata auxData,
        uint256 revealedAttrs,
        ProofTG calldata proofTG,
        ProofCL calldata proofCL
    ) external returns (BN254.G1Point memory sigma, BN254.G1Point memory credTag) {
        
        require(signers[msg.sender].isActive, "Only active signers can issue credentials");
        
       
        bool tgValid = verifier.verifyTGProof(userTagG1, proofTG);
        bool clValid = verifier.verifyCLProof(userTagG1[0], proofCL);
        
        require(tgValid, "TG proof verification failed");
        require(clValid, "CL proof verification failed");
        
       
        uint256 auxValue = 0;
        if (auxData.length >= 32) {
           
            bytes memory auxDataMemory = auxData;
            assembly {
                
                auxValue := mload(add(auxDataMemory, 32))
            }
        }
        
        
        uint256 lsk1 = signers[msg.sender].lsk1;
        uint256 lsk2 = signers[msg.sender].lsk2;
        
        
        sigma = BN254.scalarMul(userTagG1[0], lsk1);
        credTag = BN254.scalarMul(userTagG1[1], lsk2);
        
        return (sigma, credTag);
    }
}

/**
 * @title AccurateGasTest
 * @dev 
 */
contract AccurateGasTest {
    address public verifierAddr;
    address public issueLongAddr;
    
    struct TestPhase {
        string name;
        uint256 gasUsed;
        bool success;
    }
    
    TestPhase[] public testPhases;
    
    constructor(address _verifier, address _issueLong) {
        verifierAddr = _verifier;
        issueLongAddr = _issueLong;
    }
    
  
    function generateValidProofTG() public view returns (ProofTG memory) {
        BN254.G1Point memory p1 = BN254.P1();
        BN254.G1Point memory p2 = BN254.scalarMul(p1, 2);
        BN254.G2Point memory p2_g2 = BN254.P2();
        
        return ProofTG({
            c: 12345,
            s_alpha: 54321,
            s_beta: 98765,
            t1: p1,
            t2: p2,
            t2_g2: p2_g2,
            v: p2
        });
    }
    
    function generateValidProofCL() public view returns (ProofCL memory) {
        BN254.G1Point memory p1 = BN254.P1();
        BN254.G1Point memory p2 = BN254.scalarMul(p1, 2);
        BN254.G2Point memory p2_g2 = BN254.P2();
        
        return ProofCL({
            c: 12345,
            s_alpha: 54321,
            t: p1,
            t_g2: p2_g2,
            aux1: p1,
            aux2: p2
        });
    }
    
 
    function runFullTest() external {
       
        BN254.G1Point[2] memory userTagG1;
        userTagG1[0] = BN254.P1();
        userTagG1[1] = BN254.scalarMul(BN254.P1(), 3);
        
        bytes memory auxData = abi.encodePacked(uint256(1));
        ProofTG memory proofTG = generateValidProofTG();
        ProofCL memory proofCL = generateValidProofCL();
        
      
        EnhancedIssueLongVerifier verifier = EnhancedIssueLongVerifier(verifierAddr);
        IssueLong issueLong = IssueLong(issueLongAddr);
        
       
        uint256 startGas = gasleft();
        bool tgValid = verifier.verifyTGProof(userTagG1, proofTG);
        recordPhase("TG Verification", startGas, tgValid);
        
       
        startGas = gasleft();
        bool clValid = verifier.verifyCLProof(userTagG1[0], proofCL);
        recordPhase("CL Verification", startGas, clValid);
        
      
        issueLong.setTestMode(false);
        startGas = gasleft();
        try issueLong.issueLongCredential(userTagG1, auxData, 0, proofTG, proofCL) returns (BN254.G1Point memory, BN254.G1Point memory) {
            recordPhase("Full Flow (ZKP ON)", startGas, true);
        } catch {
            recordPhase("Full Flow (ZKP ON)", startGas, false);
        }
        
    
        issueLong.setTestMode(true);
        startGas = gasleft();
        try issueLong.issueLongCredential(userTagG1, auxData, 0, proofTG, proofCL) returns (BN254.G1Point memory, BN254.G1Point memory) {
            recordPhase("Full Flow (ZKP OFF)", startGas, true);
        } catch {
            recordPhase("Full Flow (ZKP OFF)", startGas, false);
        }
    }
    
    function recordPhase(string memory name, uint256 startGas, bool success) internal {
        testPhases.push(TestPhase({
            name: name,
            gasUsed: startGas - gasleft(),
            success: success
        }));
    }
    
    function getTestResults() external view returns (TestPhase[] memory) {
        return testPhases;
    }

}
