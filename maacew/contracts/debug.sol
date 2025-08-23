// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./BN254.sol";

contract ZKPDebug {
    function testPairing() external view returns (bool success, uint256 gasUsed) {
        uint256 startGas = gasleft();
        
        // 使用BN254库的基点
        BN254.G1Point memory p1 = BN254.P1();
        BN254.G2Point memory p2 = BN254.P2();
        BN254.G1Point memory negP1 = BN254.negate(p1);
        
        // 调用BN254.pairing2函数测试配对操作
        success = BN254.pairing2(p1, p2, negP1, p2);
        
        // 计算gas消耗
        gasUsed = startGas - gasleft();
    }
    
    // 纯汇编方式直接调用配对预编译合约
    function testPairingAssembly() external view returns (bool success, uint256 gasUsed) {
        uint256 startGas = gasleft();
        
        // BN254的G1基点和G2基点 (实际值可能需要调整)
        uint256[12] memory input = [
            // G1点 (使用曲线上的一个有效点)
            uint256(1), uint256(2),
            
            // G2点 (使用曲线上的一个有效点)
            uint256(10857046999023057135944570762232829481370756359578518086990519993285655852781),
            uint256(11559732032986387107991004021392285783925812861821192530917403151452391805634),
            uint256(8495653923123431417604973247489272438418190587263600148770280649306958101930),
            uint256(4082367875863433681332203403145435568316851327593401208105741076214120093531),
            
            // 负G1点 (使用曲线上的一个有效点的负值)
            uint256(1), 
            uint256(21888242871839275222246405745257275088696311157297823662689037894645226208581), // p-2，计算-y
            
            // G2点 (使用曲线上的一个有效点)
            uint256(10857046999023057135944570762232829481370756359578518086990519993285655852781),
            uint256(11559732032986387107991004021392285783925812861821192530917403151452391805634),
            uint256(8495653923123431417604973247489272438418190587263600148770280649306958101930),
            uint256(4082367875863433681332203403145435568316851327593401208105741076214120093531)
        ];
        
        assembly {
            // 调用地址为0x8的预编译合约
            success := staticcall(gas(), 8, input, 384, 0, 0x20)
        }
        
        // 计算gas消耗
        gasUsed = startGas - gasleft();
    }
    
    // 使用具体的BN254有效点
    function testValidBN254Points() external view returns (bool result1, bool result2, uint256 gasUsed) {
        uint256 startGas = gasleft();
        
        // 获取曲线上的有效点
        BN254.G1Point memory g1 = BN254.P1();
        BN254.G2Point memory g2 = BN254.P2();
        
        // 测试点是否真的在曲线上
        result1 = !BN254.isInfinity(g1);
        
        // 测试配对结果
        result2 = BN254.pairing2(g1, g2, BN254.negate(g1), g2);
        
        // 计算gas消耗
        gasUsed = startGas - gasleft();
    }
}