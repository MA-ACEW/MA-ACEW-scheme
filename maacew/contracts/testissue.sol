// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./IssueLong.sol";
import "./epoch.sol";

/**
 * @title GasConsumptionTest
 * @dev 
 */
contract GasConsumptionTest {
    IssueLong public issueLong;
    EpochCredentialBatchIssuer public epochIssuer;
    
 
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
    
 
    struct TestResult {
        string testName;
        uint256 gasUsed;
        bool success;
    }
    
  
    TestResult[] public testResults;
    
   
    constructor(address _issueLong, address _epochIssuer) {
        issueLong = IssueLong(_issueLong);
        epochIssuer = EpochCredentialBatchIssuer(_epochIssuer);
    }
    
   
    function generateMockUserTag() internal pure returns (BN254.G1Point[2] memory) {
        BN254.G1Point[2] memory userTagG1;
        userTagG1[0] = BN254.G1Point(
            0x12a5a2113cbd9e6aa9c293bbd1d8763c163967805d54d395f1080f036574cd39,
            0x2972a88ffe710c3a038f1f67ab95e4cee8aef23b8b8971c0ad08297d7645aa77
        );
        userTagG1[1] = BN254.G1Point(
            0x1a30a9eadaa889a69497d5c179e54b324669e13e022d38bbdc3dd1ae25335d0a,
            0x1e33c7ee6367c4c42152b3d681baaf0f36d9ef2cee382a9971f6680053add662
        );
        return userTagG1;
    }
    
   
    function generateMockUserTags(uint256 count) internal pure returns (BN254.G1Point[2][] memory) {
        BN254.G1Point[2][] memory userTags = new BN254.G1Point[2][](count);
        
        for (uint256 i = 0; i < count; i++) {
            userTags[i] = generateMockUserTag();
         
            userTags[i][0].x += i;
            userTags[i][0].y += i;
            userTags[i][1].x += i;
            userTags[i][1].y += i;
        }
        
        return userTags;
    }
    
 
    function generateMockProofTG() internal pure returns (ProofTG memory) {
     
        BN254.G2Point memory t2_g2 = BN254.G2Point(
            11559732032986387107991004021392285783925812861821192530917403151452391805634, 
            10857046999023057135944570762232829481370756359578518086990519993285655852781,
            4082367875863433681332203403145435568316851327593401208105741076214120093531,
            8495653923123431417604973247489272438418190587263600148770280649306958101930
        );
        
        return ProofTG({
            c: 123456,
            s_alpha: 234567,
            s_beta: 345678,
            t1: BN254.G1Point(456789, 567890),
            t2: BN254.G1Point(678901, 789012),
            t2_g2: t2_g2,
            v: BN254.G1Point(890123, 901234)
        });
    }
    
 
    function generateMockProofCL() internal pure returns (ProofCL memory) {
  
        BN254.G2Point memory t_g2 = BN254.G2Point(
            11559732032986387107991004021392285783925812861821192530917403151452391805634, 
            10857046999023057135944570762232829481370756359578518086990519993285655852781,
            4082367875863433681332203403145435568316851327593401208105741076214120093531,
            8495653923123431417604973247489272438418190587263600148770280649306958101930
        );
        
        return ProofCL({
            c: 123456,
            s_alpha: 234567,
            t: BN254.G1Point(456789, 567890),
            t_g2: t_g2,
            aux1: BN254.G1Point(123456, 234567),
            aux2: BN254.G1Point(345678, 456789)
        });
    }
    
    
    function generateMockAuxData() internal pure returns (bytes memory) {
       
        bytes memory count = abi.encodePacked(uint256(2));
        
       
        bytes memory data = "";
        for (uint i = 0; i < 2; i++) {
            // commitment
            data = abi.encodePacked(
                data,
                uint256(0x1000 + i), 
                uint256(0x2000 + i)  
            );
            
            // c1
            data = abi.encodePacked(
                data,
                uint256(0x3000 + i), 
                uint256(0x4000 + i)  
            );
            
            // c2
            data = abi.encodePacked(
                data,
                uint256(0x5000 + i), 
                uint256(0x6000 + i)  
            );
        }
        
        return abi.encodePacked(count, data);
    }
    
   
    function recordResult(string memory testName, uint256 gasUsed, bool success) internal {
        testResults.push(TestResult({
            testName: testName,
            gasUsed: gasUsed,
            success: success
        }));
    }
    
  
    function getAllTestResults() external view returns (TestResult[] memory) {
        return testResults;
    }
    
   
    function getLastTestResult() external view returns (string memory, uint256, bool) {
        require(testResults.length > 0, "No test results yet");
        TestResult memory result = testResults[testResults.length - 1];
        return (result.testName, result.gasUsed, result.success);
    }
    
   
    function clearTestResults() external {
        delete testResults;
    }
    
  
    
    
    function testIssueLongCredential() public returns (uint256) {
        BN254.G1Point[2] memory userTagG1 = generateMockUserTag();
        bytes memory auxData = generateMockAuxData();
        ProofTG memory proofTG = generateMockProofTG();
        ProofCL memory proofCL = generateMockProofCL();
        
        uint256 gasStart = gasleft();
        
        try issueLong.issueLongCredential(userTagG1, auxData, 0, proofTG, proofCL) returns (BN254.G1Point memory, BN254.G1Point memory) {
            uint256 gasUsed = gasStart - gasleft();
            recordResult("IssueLongCredential", gasUsed, true);
            return gasUsed;
        } catch Error(string memory reason) {
            uint256 gasUsed = gasStart - gasleft();
            recordResult(string(abi.encodePacked("IssueLongCredential Error: ", reason)), gasUsed, false);
            return gasUsed;
        } catch (bytes memory) {
            uint256 gasUsed = gasStart - gasleft();
            recordResult("IssueLongCredential Failed (unknown reason)", gasUsed, false);
            return gasUsed;
        }
    }
    
  
    
   
    function testGenerateEpochKey() public returns (uint256) {
        uint256 gasStart = gasleft();
        
        try epochIssuer.generateEpochKey() {
            uint256 gasUsed = gasStart - gasleft();
            recordResult("GenerateEpochKey", gasUsed, true);
            return gasUsed;
        } catch Error(string memory reason) {
            uint256 gasUsed = gasStart - gasleft();
            recordResult(string(abi.encodePacked("GenerateEpochKey Error: ", reason)), gasUsed, false);
            return gasUsed;
        } catch (bytes memory) {
            uint256 gasUsed = gasStart - gasleft();
            recordResult("GenerateEpochKey Failed (unknown reason)", gasUsed, false);
            return gasUsed;
        }
    }
    
   
    function testIssueEpochCredential() public returns (uint256) {
        BN254.G1Point[2] memory userTagG1 = generateMockUserTag();
        
        uint256 gasStart = gasleft();
        
        try epochIssuer.issueEpochCredential(userTagG1, epochIssuer.currentEpoch()) returns (BN254.G1Point memory) {
            uint256 gasUsed = gasStart - gasleft();
            recordResult("IssueEpochCredential", gasUsed, true);
            return gasUsed;
        } catch Error(string memory reason) {
            uint256 gasUsed = gasStart - gasleft();
            recordResult(string(abi.encodePacked("IssueEpochCredential Error: ", reason)), gasUsed, false);
            return gasUsed;
        } catch (bytes memory) {
            uint256 gasUsed = gasStart - gasleft();
            recordResult("IssueEpochCredential Failed (unknown reason)", gasUsed, false);
            return gasUsed;
        }
    }
    
  
    function testBatchIssueEpochCredentials(uint256 count) public returns (uint256) {
        BN254.G1Point[2][] memory userTags = generateMockUserTags(count);
        
        uint256 gasStart = gasleft();
        
        try epochIssuer.batchIssueEpochCredentials(userTags, epochIssuer.currentEpoch()) returns (BN254.G1Point[] memory) {
            uint256 gasUsed = gasStart - gasleft();
            recordResult(
                string(abi.encodePacked("BatchIssueEpochCredentials(", toString(count), ")")), 
                gasUsed, 
                true
            );
            return gasUsed;
        } catch Error(string memory reason) {
            uint256 gasUsed = gasStart - gasleft();
            recordResult(
                string(abi.encodePacked("BatchIssueEpochCredentials(", toString(count), ") Error: ", reason)), 
                gasUsed, 
                false
            );
            return gasUsed;
        } catch (bytes memory) {
            uint256 gasUsed = gasStart - gasleft();
            recordResult(
                string(abi.encodePacked("BatchIssueEpochCredentials(", toString(count), ") Failed (unknown reason)")), 
                gasUsed, 
                false
            );
            return gasUsed;
        }
    }
    
  
    function runAllTests() external returns (bool) {
      
        delete testResults;
        
      
        testGenerateEpochKey();
        testIssueEpochCredential();
        testBatchIssueEpochCredentials(2);
        testBatchIssueEpochCredentials(5);
        testIssueLongCredential();
        
        return true;
    }
    
 
    function toString(uint256 value) internal pure returns (string memory) {
     
        if (value == 0) {
            return "0";
        }
        
       
        uint256 temp = value;
        uint256 digits;
        while (temp != 0) {
            digits++;
            temp /= 10;
        }
        
      
        bytes memory buffer = new bytes(digits);
        
      
        while (value != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));
            value /= 10;
        }
        
        return string(buffer);
    }

}
