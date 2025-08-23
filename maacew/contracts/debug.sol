// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./BN254.sol";

contract ZKPDebug {
    function testPairing() external view returns (bool success, uint256 gasUsed) {
        uint256 startGas = gasleft();
        
     
        BN254.G1Point memory p1 = BN254.P1();
        BN254.G2Point memory p2 = BN254.P2();
        BN254.G1Point memory negP1 = BN254.negate(p1);
        
        success = BN254.pairing2(p1, p2, negP1, p2);
        
        
        gasUsed = startGas - gasleft();
    }
    
   
    function testPairingAssembly() external view returns (bool success, uint256 gasUsed) {
        uint256 startGas = gasleft();
        
       
        uint256[12] memory input = [
           
            uint256(1), uint256(2),
            
          
            uint256(10857046999023057135944570762232829481370756359578518086990519993285655852781),
            uint256(11559732032986387107991004021392285783925812861821192530917403151452391805634),
            uint256(8495653923123431417604973247489272438418190587263600148770280649306958101930),
            uint256(4082367875863433681332203403145435568316851327593401208105741076214120093531),
            
           
            uint256(1), 
            uint256(21888242871839275222246405745257275088696311157297823662689037894645226208581), 
            
           
            uint256(10857046999023057135944570762232829481370756359578518086990519993285655852781),
            uint256(11559732032986387107991004021392285783925812861821192530917403151452391805634),
            uint256(8495653923123431417604973247489272438418190587263600148770280649306958101930),
            uint256(4082367875863433681332203403145435568316851327593401208105741076214120093531)
        ];
        
        assembly {
            
            success := staticcall(gas(), 8, input, 384, 0, 0x20)
        }
        
       
        gasUsed = startGas - gasleft();
    }
    
    
    function testValidBN254Points() external view returns (bool result1, bool result2, uint256 gasUsed) {
        uint256 startGas = gasleft();
        
       
        BN254.G1Point memory g1 = BN254.P1();
        BN254.G2Point memory g2 = BN254.P2();
        
       
        result1 = !BN254.isInfinity(g1);
        
        
        result2 = BN254.pairing2(g1, g2, BN254.negate(g1), g2);
        
       
        gasUsed = startGas - gasleft();
    }

}
