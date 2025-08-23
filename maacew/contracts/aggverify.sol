// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.0;

import "./BN254.sol";

/**
 * @title BLSAggVerifyBenchmark
 * @dev 测试BLS聚合验证函数的gas消耗
 */
contract BLSAggVerifyBenchmark {
    using BN254 for *;
    
    // 测试结果结构
    struct TestResult {
        uint256 standardGas;       // 标准方法gas消耗
        uint256 optimizedGas;      // 优化方法gas消耗
        bool standardSuccess;      // 标准方法是否成功
        bool optimizedSuccess;     // 优化方法是否成功
        uint256 savingsPercent;    // 节省百分比
    }
    
    // 存储测试结果
    TestResult public testResult;
    
    // 事件
    event DebugLog(string message, uint256 value);
    event TestCompleted(uint256 standardGas, uint256 optimizedGas, bool standardSuccess, bool optimizedSuccess);
    event MultiVerifyResult(uint256 count, uint256 standardGas, uint256 optimizedGas);
    
    // 聚合验证所需数据结构
    struct Signature {
        BN254.G1Point h;     // h'，聚合签名的第一部分
        BN254.G1Point s;     // 聚合签名的第二部分
    }
    
    struct Tag {
        BN254.G1Point hGamma; // h^γ
        BN254.G1Point hDelta; // h^δ
    }
    
    struct VerifierKey {
        BN254.G2Point lvk1;   // 长期验证密钥1
        BN254.G2Point lvk2;   // 长期验证密钥2
        BN254.G2Point tvk;    // 临时验证密钥
    }
    
    /**
     * @dev 标准聚合验证方法
     */
    function aggVerifyStandard() public view returns (bool) {
        // 获取基本点
        BN254.G1Point memory g1 = BN254.P1();
        BN254.G2Point memory g2 = BN254.P2();
        
        // 创建测试数据
        Signature memory aggSig;
        Tag memory tag;
        VerifierKey memory vk;
        
        // 设置标签和签名
        tag.hGamma = BN254.scalarMul(g1, 123);
        tag.hDelta = BN254.scalarMul(g1, 456);
        aggSig.h = tag.hGamma; // 模拟h'点
        aggSig.s = BN254.scalarMul(g1, 789);
        
        // 设置验证密钥
        vk.lvk1 = g2; // 模拟∑(lvk1_i + lvk2_i*m_i)的结果
        vk.tvk = g2;  // 模拟∑(Z_i)的结果
        
        // 计算h^δ乘以j (模拟j=1)
        BN254.G1Point memory hDeltaJ = tag.hDelta;
        
        // 获取-g2
        BN254.G2Point memory negG2 = BN254.G2Point(
            g2.x0,
            g2.x1,
            BN254.P_MOD - g2.y0,
            BN254.P_MOD - g2.y1
        );
        
        // 准备三个配对 e(h', ∑(lvk1_i + lvk2_i*m_i)) * e((h^δ)^j, ∑Z_i) * e(s, -g2)
        BN254.G1Point[3] memory g1Points;
        BN254.G2Point[3] memory g2Points;
        
        g1Points[0] = aggSig.h;
        g1Points[1] = hDeltaJ;
        g1Points[2] = aggSig.s;
        
        g2Points[0] = vk.lvk1;
        g2Points[1] = vk.tvk;
        g2Points[2] = negG2;
        
        // 执行标准三对配对
        return BN254.pairing3(g1Points, g2Points);
    }
    
    /**
     * @dev 优化聚合验证方法 - 使用随机线性组合，借鉴参考合约的优化策略
     */
    function aggVerifyOptimized() public view returns (bool) {
        // 获取基本点
        BN254.G1Point memory g1 = BN254.P1();
        BN254.G2Point memory g2 = BN254.P2();
        
        // 创建测试数据（与标准方法相同）
        Signature memory aggSig;
        Tag memory tag;
        VerifierKey memory vk;
        
        // 设置标签和签名
        tag.hGamma = BN254.scalarMul(g1, 123);
        tag.hDelta = BN254.scalarMul(g1, 456);
        aggSig.h = tag.hGamma; // 模拟h'点
        aggSig.s = BN254.scalarMul(g1, 789);
        
        // 设置验证密钥
        vk.lvk1 = g2; // 模拟∑(lvk1_i + lvk2_i*m_i)的结果
        vk.tvk = g2;  // 模拟∑(Z_i)的结果
        
        // 计算h^δ乘以j (模拟j=1)
        BN254.G1Point memory hDeltaJ = tag.hDelta;
        
        // 获取-g2
        BN254.G2Point memory negG2 = BN254.G2Point(
            g2.x0,
            g2.x1,
            BN254.P_MOD - g2.y0,
            BN254.P_MOD - g2.y1
        );
        
        // 生成随机系数 - 参考合约中的策略
        uint256 seed = uint256(keccak256(abi.encodePacked(block.timestamp, blockhash(block.number - 1))));
        uint256 rho = (uint256(keccak256(abi.encodePacked(seed, uint256(1)))) % (BN254.R_MOD - 1)) + 1;
        uint256 rho_2 = mulmod(rho, rho, BN254.R_MOD);
        uint256 rho_3 = mulmod(rho_2, rho, BN254.R_MOD);
        
        // 优化1: 在G1点上应用指数，避免G2点标量乘法
        BN254.G1Point[3] memory left;
        BN254.G2Point[3] memory right;
        
        // 第一个配对 e(h', lvk1) 应用rho倍数
        left[0] = BN254.scalarMul(aggSig.h, rho);
        right[0] = vk.lvk1;
        
        // 第二个配对 e(hDeltaJ, tvk) 应用rho^2倍数
        left[1] = BN254.scalarMul(hDeltaJ, rho_2);
        right[1] = vk.tvk;
        
        // 第三个配对 e(s, -g2) 应用rho^3倍数
        left[2] = BN254.scalarMul(aggSig.s, rho_3);
        right[2] = negG2;
        
        // 使用单个配对检查取代三个独立配对
        return BN254.pairing3(left, right);
    }
    
    /**
     * @dev 测试标准聚合验证方法
     */
    function testStandardVerify() public returns (bool success, uint256 gasUsed) {
        uint256 startGas = gasleft();
        success = aggVerifyStandard();
        gasUsed = startGas - gasleft();
        
        emit DebugLog("Standard verification gas", gasUsed);
        
        return (success, gasUsed);
    }
    
    /**
     * @dev 测试优化聚合验证方法
     */
    function testOptimizedVerify() public returns (bool success, uint256 gasUsed) {
        uint256 startGas = gasleft();
        success = aggVerifyOptimized();
        gasUsed = startGas - gasleft();
        
        emit DebugLog("Optimized verification gas", gasUsed);
        
        return (success, gasUsed);
    }
    
    /**
     * @dev 运行所有测试
     */
    function runAllTests() public {
        (bool standardSuccess, uint256 standardGas) = testStandardVerify();
        (bool optimizedSuccess, uint256 optimizedGas) = testOptimizedVerify();
        
        // 计算节省百分比
        uint256 savingsPercent = 0;
        if (standardGas > optimizedGas) {
            savingsPercent = ((standardGas - optimizedGas) * 100) / standardGas;
        }
        
        // 存储结果
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
     * @dev 重复验证测试 - 测试多次验证的gas消耗
     */
    function testMultipleVerifications(uint256 count) public returns (uint256 standardTotalGas, uint256 optimizedTotalGas) {
        // 测试标准方法多次运行
        uint256 startGas = gasleft();
        bool standardSuccess = true;
        for (uint256 i = 0; i < count; i++) {
            standardSuccess = standardSuccess && aggVerifyStandard();
        }
        standardTotalGas = startGas - gasleft();
        
        // 测试优化方法多次运行
        startGas = gasleft();
        bool optimizedSuccess = true;
        for (uint256 i = 0; i < count; i++) {
            optimizedSuccess = optimizedSuccess && aggVerifyOptimized();
        }
        optimizedTotalGas = startGas - gasleft();
        
        // 使用事件记录结果
        emit DebugLog("Standard total gas for multiple verifications", standardTotalGas);
        emit DebugLog("Optimized total gas for multiple verifications", optimizedTotalGas);
        emit MultiVerifyResult(count, standardTotalGas, optimizedTotalGas);
        
        return (standardTotalGas, optimizedTotalGas);
    }
    
    /**
     * @dev 获取测试结果
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