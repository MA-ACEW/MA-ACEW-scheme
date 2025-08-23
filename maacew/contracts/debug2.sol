// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./BN254.sol";

contract BN254PairingTest {
    using BN254 for *;
    

    function testPairing2() public view returns (bool success, uint256 gasUsed) {
        uint256 startGas = gasleft();
        

        BN254.G1Point memory a1 = BN254.P1();
        BN254.G2Point memory a2 = BN254.P2();
        
        // e(P1, P2) * e(-P1, P2) = 1
        BN254.G1Point memory b1 = BN254.negate(BN254.P1());
        BN254.G2Point memory b2 = BN254.P2();
        
      
        success = BN254.pairing2(a1, a2, b1, b2);
        
        gasUsed = startGas - gasleft();
    }
    
  
    function testPairing4() public view returns (bool success, uint256 gasUsed) {
        uint256 startGas = gasleft();
        
      
        BN254.G1Point[4] memory g1Points;
        BN254.G2Point[4] memory g2Points;
        
       
        g1Points[0] = BN254.P1();
        g2Points[0] = BN254.P2();
        
      
        g1Points[1] = BN254.negate(BN254.P1());
        g2Points[1] = BN254.P2();
        
       
        g1Points[2] = BN254.scalarMul(BN254.P1(), 2);
        g2Points[2] = BN254.P2();
        
      
        g1Points[3] = BN254.negate(BN254.scalarMul(BN254.P1(), 2));
        g2Points[3] = BN254.P2();
        
      
        success = BN254.pairing4(g1Points, g2Points);
        
        gasUsed = startGas - gasleft();
    }
    
    
    function testPairing3() public view returns (bool success, uint256 gasUsed) {
        uint256 startGas = gasleft();
        
       
        BN254.G1Point[3] memory g1Points;
        BN254.G2Point[3] memory g2Points;
        
        
        g1Points[0] = BN254.P1();
        g2Points[0] = BN254.P2();
        
       
        g1Points[1] = BN254.negate(BN254.P1());
        g2Points[1] = BN254.P2();
        
        
        g1Points[2] = BN254.P1();
        g2Points[2] = BN254.P2();
        
       
        success = BN254.pairing3(g1Points, g2Points);
        
        gasUsed = startGas - gasleft();
    }
    
   
    function testPairing15() public view returns (bool success, uint256 gasUsed) {
        uint256 startGas = gasleft();
        
       
        BN254.G1Point[15] memory g1Points;
        BN254.G2Point[15] memory g2Points;
        
       
        g1Points[0] = BN254.P1();
        g2Points[0] = BN254.P2();
        
       
        g1Points[1] = BN254.negate(BN254.P1());
        g2Points[1] = BN254.P2();
        
        
        for (uint i = 2; i < 15; i++) {
            g1Points[i] = BN254.P1();
            g2Points[i] = BN254.P2();
        }
        
        
        success = BN254.pairing15(g1Points, g2Points);
        
        gasUsed = startGas - gasleft();
    }
    
    
    function testRawPairing() public view returns (bool success, uint256 gasUsed) {
        uint256 startGas = gasleft();
        
        
        uint256[12] memory input;
        
       
        BN254.G1Point memory a1 = BN254.P1();
        BN254.G2Point memory a2 = BN254.P2();
        
       
        BN254.G1Point memory b1 = BN254.negate(BN254.P1());
        BN254.G2Point memory b2 = BN254.P2();
        
       
        input[0] = a1.x;
        input[1] = a1.y;
        input[2] = a2.x0;
        input[3] = a2.x1;
        input[4] = a2.y0;
        input[5] = a2.y1;
        
        input[6] = b1.x;
        input[7] = b1.y;
        input[8] = b2.x0;
        input[9] = b2.x1;
        input[10] = b2.y0;
        input[11] = b2.y1;
        
        uint256[1] memory out;
        
      
        assembly {
            success := staticcall(
                sub(gas(), 2000), 
                8,          
                input,      
                mul(12, 32), 
                out,        
                32         
            )
        }
        
        
        bool result = out[0] != 0;
        
        gasUsed = startGas - gasleft();
        success = result;
    }
    

    function compareAllPairings() external view returns (
        bool pairing2Success, uint256 pairing2Gas,
        bool pairing3Success, uint256 pairing3Gas,
        bool pairing4Success, uint256 pairing4Gas,
        bool pairing15Success, uint256 pairing15Gas,
        bool rawPairingSuccess, uint256 rawPairingGas
    ) {
        (pairing2Success, pairing2Gas) = testPairing2();
        (pairing3Success, pairing3Gas) = testPairing3();
        (pairing4Success, pairing4Gas) = testPairing4();
        (pairing15Success, pairing15Gas) = testPairing15();
        (rawPairingSuccess, rawPairingGas) = testRawPairing();
    }

}
