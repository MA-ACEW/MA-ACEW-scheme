// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.0;

import {BN254} from "./BN254.sol";
import {Utils} from "./Utils.sol";

import "./CommonStructs.sol";

/**
 * @title CredVerifyBenchmark
 * @dev 结合BLS聚合签名验证与WTS合约，测试不同验证方法的gas消耗
 */
contract CredVerifyBenchmark {
    uint256 constant FR_BYTES_LEN = 31;
    
    // 测试结果结构
    struct TestResult {
        uint256 wtsGas;               // 原始WTS验证方法gas消耗
        uint256 wtsOptimizedGas;      // 优化的WTS验证方法gas消耗
        uint256 credVerifyGas;        // 我们的CredVerify方法gas消耗
        uint256 credVerifyOptGas;     // 优化的CredVerify方法gas消耗
        uint256 savingsPercent;       // 节省的百分比
    }
    
    // 存储中间计算结果 - 这些是全局变量，不会计入栈深度
    struct CalcHelper {
        uint256 xi;
        uint256 rho;
        uint256 rho_2;
        uint256 rho_3;
        uint256 rho_4;
        uint256 rho_5;
        uint256 xi_times_t_prime;
    }
    
    // 存储测试结果
    TestResult public testResult;
    CalcHelper public helper;
    
    // WTS合约部分变量
    VerifierKey private vk;
    Proof private proof;
    
    // 事件
    event DebugLog(string message, uint256 value);
    event TestCompleted(uint256 wtsGas, uint256 wtsOptimizedGas, uint256 credVerifyGas, uint256 credVerifyOptGas);
    
    /**
     * @dev 计算哈希到域元素
     */
    function hash_to_field(BN254.G1Point memory g_b, BN254.G1Point memory g_mu, uint256 t_prime, uint256 extra)
        public
        view
        returns (uint256)
    {
        bytes32 hash = keccak256(abi.encode(vk.g_s, vk.g_w, g_b, g_mu, t_prime, extra));
        bytes memory hash_bytes = abi.encodePacked(hash);

        uint256 second_field_elem = uint256(uint8(hash_bytes[0]));

        // Remove first byte
        hash_bytes[FR_BYTES_LEN] = 0;
        uint256 first_field_elem = Utils.reverseEndianness(uint256(bytes32(hash_bytes)));

        uint256 res = mulmod(first_field_elem, second_field_elem, BN254.R_MOD);
        return res;
    }
    
    // ----- 重构为更小的函数 -----
    
    /**
     * @dev 辅助函数 - 将动态数组转换为固定大小的数组
     */
    function dynamicToFixed3G1(BN254.G1Point[] memory input) internal pure returns (BN254.G1Point[3] memory output) {
        require(input.length == 3, "Array must have exactly 3 elements");
        output[0] = input[0];
        output[1] = input[1];
        output[2] = input[2];
        return output;
    }
    
    /**
     * @dev 辅助函数 - 将动态数组转换为固定大小的G2数组
     */
    function dynamicToFixed3G2(BN254.G2Point[] memory input) internal pure returns (BN254.G2Point[3] memory output) {
        require(input.length == 3, "Array must have exactly 3 elements");
        output[0] = input[0];
        output[1] = input[1];
        output[2] = input[2];
        return output;
    }
    
    /**
     * @dev 辅助函数 - 将动态数组转换为固定大小的数组 - 4个元素
     */
    function dynamicToFixed4G1(BN254.G1Point[] memory input) internal pure returns (BN254.G1Point[4] memory output) {
        require(input.length == 4, "Array must have exactly 4 elements");
        output[0] = input[0];
        output[1] = input[1];
        output[2] = input[2];
        output[3] = input[3];
        return output;
    }
    
    /**
     * @dev 辅助函数 - 将动态数组转换为固定大小的G2数组 - 4个元素
     */
    function dynamicToFixed4G2(BN254.G2Point[] memory input) internal pure returns (BN254.G2Point[4] memory output) {
        require(input.length == 4, "Array must have exactly 4 elements");
        output[0] = input[0];
        output[1] = input[1];
        output[2] = input[2];
        output[3] = input[3];
        return output;
    }
    
    /**
     * @dev 为BN254库添加pairing13函数，接受动态数组
     */
    function pairing13(BN254.G1Point[] memory p1, BN254.G2Point[] memory p2) internal view returns (bool) {
        require(p1.length == 13 && p2.length == 13, "Array length must be 13");
        uint256 inputSize = 78; // 6 * 13
        uint256[] memory input = new uint256[](inputSize);

        for (uint256 i = 0; i < 13; i++) {
            uint256 j = i * 6;
            input[j + 0] = p1[i].x;
            input[j + 1] = p1[i].y;
            input[j + 2] = p2[i].x0;
            input[j + 3] = p2[i].x1;
            input[j + 4] = p2[i].y0;
            input[j + 5] = p2[i].y1;
        }

        uint256[1] memory out;
        bool success;

        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success
            case 0 { invalid() }
        }

        require(success, "pairing-opcode-failed");

        return out[0] != 0;
    }

    /**
     * @dev 为BN254库添加pairing12函数，接受动态数组
     */
    function pairing12(BN254.G1Point[] memory p1, BN254.G2Point[] memory p2) internal view returns (bool) {
        require(p1.length == 12 && p2.length == 12, "Array length must be 12");
        uint256 inputSize = 72; // 6 * 12
        uint256[] memory input = new uint256[](inputSize);

        for (uint256 i = 0; i < 12; i++) {
            uint256 j = i * 6;
            input[j + 0] = p1[i].x;
            input[j + 1] = p1[i].y;
            input[j + 2] = p2[i].x0;
            input[j + 3] = p2[i].x1;
            input[j + 4] = p2[i].y0;
            input[j + 5] = p2[i].y1;
        }

        uint256[1] memory out;
        bool success;

        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success
            case 0 { invalid() }
        }

        require(success, "pairing-opcode-failed");

        return out[0] != 0;
    }
    
    /**
     * @dev 设置验证密钥
     */
    function set_vk(
        BN254.G1Point memory g1,
        BN254.G2Point memory g2,
        BN254.G2Point memory h2,
        BN254.G2Point memory v2,
        BN254.G1Point memory g_s,
        BN254.G1Point memory g_w,
        BN254.G2Point memory g_tau,
        BN254.G2Point memory h_tau,
        BN254.G2Point memory g_z_H,
        uint256 nb_users
    ) public {
        BN254.G1Point memory neg_g1 = BN254.negate(g1);
        uint256 one_over_n = BN254.invert(nb_users);
        vk = VerifierKey(g1, neg_g1, one_over_n, g2, h2, v2, g_s, g_w, g_tau, h_tau, g_z_H, nb_users);
    }
    
    /**
     * @dev 设置验证证明
     */
    function set_proof(
        BN254.G1Point memory g_mu,
        BN254.G1Point memory g1_b,
        BN254.G2Point memory g2_b,
        BN254.G1Point memory gq_b,
        BN254.G2Point memory sigma_bls,
        BN254.G1Point memory g1_q,
        BN254.G1Point memory g1_r,
        BN254.G1Point memory h1_p,
        BN254.G1Point memory v_mu,
        uint256 t_prime
    ) public {
        proof = Proof(g_mu, g1_b, g2_b, gq_b, sigma_bls, g1_q, g1_r, h1_p, v_mu, t_prime);
    }
    
    /**
     * @dev 计算公共哈希和幂
     */
    function computeHashesAndPowers() public {
        helper.xi = hash_to_field(proof.g1_b, proof.g_mu, proof.t_prime, 0);
        helper.rho = hash_to_field(proof.g1_b, proof.g_mu, proof.t_prime, 1);
        helper.rho_2 = mulmod(helper.rho, helper.rho, BN254.R_MOD);
        helper.rho_3 = mulmod(helper.rho_2, helper.rho, BN254.R_MOD);
        helper.rho_4 = mulmod(helper.rho_3, helper.rho, BN254.R_MOD);
        helper.rho_5 = mulmod(helper.rho_4, helper.rho, BN254.R_MOD);
        helper.xi_times_t_prime = mulmod(helper.xi, proof.t_prime, BN254.R_MOD);
    }
    
    // ===== CredVerify 方法与辅助函数 =====
    
    /**
     * @dev 创建G2的负点
     */
    function createNegG2() internal view returns (BN254.G2Point memory) {
        BN254.G2Point memory g2 = BN254.P2();
        return BN254.G2Point(
            g2.x0,
            g2.x1,
            BN254.P_MOD - g2.y0,
            BN254.P_MOD - g2.y1
        );
    }
    
    /**
     * @dev CredVerify方法 - 用于替换WTS的equation 35
     */
    function credVerify(
        BN254.G1Point memory aggSigH,
        BN254.G1Point memory hDeltaJ, 
        BN254.G1Point memory aggSigS
    ) public view returns (bool) {
        // 获取基本点
        BN254.G2Point memory negG2 = createNegG2();
        
        // 准备三个配对
        BN254.G1Point[3] memory g1Points;
        BN254.G2Point[3] memory g2Points;
        
        g1Points[0] = aggSigH;
        g1Points[1] = hDeltaJ;
        g1Points[2] = aggSigS;
        
        g2Points[0] = vk.g2;        // combinedLvk
        g2Points[1] = vk.g_Z_H;     // combinedTvk
        g2Points[2] = negG2;
        
        // 执行标准三对配对
        return BN254.pairing3(g1Points, g2Points);
    }
    
    /**
     * @dev 优化的CredVerify方法 - 使用随机线性组合
     */
    function credVerifyOptimized(
        BN254.G1Point memory aggSigH,
        BN254.G1Point memory hDeltaJ, 
        BN254.G1Point memory aggSigS
    ) public view returns (bool) {
        // 获取基本点
        BN254.G2Point memory negG2 = createNegG2();
        
        // 生成随机系数
        uint256 seed = uint256(keccak256(abi.encodePacked(block.timestamp, blockhash(block.number - 1))));
        uint256 rho = (uint256(keccak256(abi.encodePacked(seed, uint256(1)))) % (BN254.R_MOD - 1)) + 1;
        uint256 rho_2 = mulmod(rho, rho, BN254.R_MOD);
        uint256 rho_3 = mulmod(rho_2, rho, BN254.R_MOD);
        
        // 优化: 在G1点上应用指数，避免G2点标量乘法
        BN254.G1Point[3] memory left;
        BN254.G2Point[3] memory right;
        
        // 第一个配对 e(h', lvk1) 应用rho倍数
        left[0] = BN254.scalarMul(aggSigH, rho);
        right[0] = vk.g2;
        
        // 第二个配对 e(hDeltaJ, tvk) 应用rho^2倍数
        left[1] = BN254.scalarMul(hDeltaJ, rho_2);
        right[1] = vk.g_Z_H;
        
        // 第三个配对 e(s, -g2) 应用rho^3倍数
        left[2] = BN254.scalarMul(aggSigS, rho_3);
        right[2] = negG2;
        
        // 使用单个配对检查取代三个独立配对
        return BN254.pairing3(left, right);
    }
    
    /**
     * @dev 准备credVerify所需参数
     */
    function prepareCredVerifyParams() internal view returns (
        BN254.G1Point memory aggSigH,
        BN254.G1Point memory hDeltaJ,
        BN254.G1Point memory aggSigS
    ) {
        aggSigH = proof.g1_b;                 // 使用g1_b作为聚合签名H
        hDeltaJ = BN254.negate(proof.gq_b);   // 使用-gq_b作为hDeltaJ 
        aggSigS = BN254.add(vk.g1, BN254.negate(proof.g1_b)); // g1-g1_b作为聚合签名S
        
        return (aggSigH, hDeltaJ, aggSigS);
    }
    
    // ===== WTS 验证方法与辅助函数 =====
    
    /**
     * @dev 处理WTS验证方法中equation 35
     */
    function wtsVerifyEq35() internal view returns (bool) {
        // 首先验证g1_b和g2_b是等价的：e(g1_b,g2)=e(g1,g2_b)
        bool res = BN254.pairing2(proof.g1_b, vk.g2, vk.neg_g1, proof.g2_b);

        // 计算g1-g1_b
        BN254.G1Point memory g1_minus_g1b = BN254.add(vk.g1, BN254.negate(proof.g1_b));

        // 配对检查 - 等式(35)的第二部分
        res = BN254.pairing2(g1_minus_g1b, proof.g2_b, BN254.negate(proof.gq_b), vk.g_Z_H) && res;
        
        return res;
    }
    
    /**
     * @dev 处理WTS验证方法中equation 36
     */
    function wtsVerifyEq36(uint256 xi, uint256 xi_times_t_prime) internal view returns (bool, BN254.G1Point memory) {
        BN254.G1Point memory gs_gw_xi = BN254.add(vk.g_s, BN254.scalarMul(vk.g_w, xi));
        BN254.G1Point[4] memory left_4;
        BN254.G2Point[4] memory right_4;
        left_4[0] = BN254.negate(gs_gw_xi);
        left_4[1] = proof.g1_q;
        left_4[2] = proof.g1_r;

        // 在G1上应用1/n指数，避免G2点标量乘法
        BN254.G1Point memory g_mu_plus_g1_exp_xi_t_prime_exp_one_over_n =
            BN254.scalarMul(BN254.add(proof.g_mu, BN254.scalarMul(vk.g1, xi_times_t_prime)), vk.one_over_n);
        left_4[3] = g_mu_plus_g1_exp_xi_t_prime_exp_one_over_n;

        right_4[0] = proof.g2_b;
        right_4[1] = vk.g_Z_H;
        right_4[2] = vk.g_tau;
        right_4[3] = vk.g2;

        bool res = BN254.pairing4(left_4, right_4);
        
        return (res, g_mu_plus_g1_exp_xi_t_prime_exp_one_over_n);
    }
    
    /**
     * @dev 处理WTS验证方法中equation 37
     */
    function wtsVerifyEq37(BN254.G1Point memory g_mu_plus_g1_xi_t_n) internal view returns (bool) {
        BN254.G1Point[3] memory left_3;
        BN254.G2Point[3] memory right_3;

        left_3[0] = BN254.negate(proof.h1_p);
        left_3[1] = proof.g1_r;
        left_3[2] = g_mu_plus_g1_xi_t_n;

        right_3[0] = vk.g2;
        right_3[1] = vk.h_tau;
        right_3[2] = vk.h2;

        return BN254.pairing3(left_3, right_3);
    }
    
    /**
     * @dev 处理WTS验证方法中equation 38
     */
    function wtsVerifyEq38() internal view returns (bool) {
        return BN254.pairing2(BN254.negate(proof.v_mu), vk.g2, proof.g_mu, vk.v2);
    }
    
    /**
     * @dev 处理WTS验证方法中equation 39
     */
    function wtsVerifyEq39(BN254.G2Point memory message_hash) internal view returns (bool) {
        return BN254.pairing2(BN254.negate(proof.g_mu), message_hash, vk.g1, proof.sigma_bls);
    }
    
    /**
     * @dev 原始WTS验证方法
     */
    function wtsVerify(BN254.G2Point memory message_hash, uint256 t) public view returns (bool) {
        // 检查阈值
        if (proof.t_prime < t) {
            return false;
        }
        
        // 计算哈希
        uint256 xi = hash_to_field(proof.g1_b, proof.g_mu, proof.t_prime, 0);
        uint256 xi_times_t_prime = mulmod(xi, proof.t_prime, BN254.R_MOD);

        // 进行各方程验证
        bool res1 = wtsVerifyEq35();
        
        // eq36返回验证结果和中间计算结果g_mu_plus_g1_xi_t_n
        (bool res2, BN254.G1Point memory g_mu_plus_g1_xi_t_n) = wtsVerifyEq36(xi, xi_times_t_prime);
        
        bool res3 = wtsVerifyEq37(g_mu_plus_g1_xi_t_n);
        bool res4 = wtsVerifyEq38();
        bool res5 = wtsVerifyEq39(message_hash);
        
        // 组合所有结果
        return res1 && res2 && res3 && res4 && res5;
    }
    
    /**
     * @dev 为WTS优化验证准备点 - 第1部分
     */
    function prepareWtsOptPoints1() internal view returns (BN254.G1Point[4] memory left, BN254.G2Point[4] memory right) {
        // 等式(35)(1) coeff = 1 
        left[0] = proof.g1_b;
        right[0] = vk.g2;
        left[1] = vk.neg_g1;
        right[1] = proof.g2_b;

        // 等式(35)(2) coeff = rho
        left[2] = BN254.scalarMul(BN254.add(vk.g1, BN254.negate(proof.g1_b)), helper.rho); 
        right[2] = proof.g2_b;
        left[3] = BN254.scalarMul(BN254.negate(proof.gq_b), helper.rho);
        right[3] = vk.g_Z_H;
        
        return (left, right);
    }
    
    /**
     * @dev 为WTS优化验证准备点 - 第2部分
     */
    function prepareWtsOptPoints2() internal view returns (
        BN254.G1Point[4] memory left, 
        BN254.G2Point[4] memory right,
        BN254.G1Point memory g_mu_xi_t_n
    ) {
        // 计算公共值
        BN254.G1Point memory gs_gw_xi = BN254.add(vk.g_s, BN254.scalarMul(vk.g_w, helper.xi));
        
        // 计算 g_mu + g1*xi_t_prime / n
        BN254.G1Point memory temp = BN254.add(proof.g_mu, BN254.scalarMul(vk.g1, helper.xi_times_t_prime));
        g_mu_xi_t_n = BN254.scalarMul(temp, vk.one_over_n);
        
        // 等式(36) 系数 = rho^2
        left[0] = BN254.scalarMul(BN254.negate(gs_gw_xi), helper.rho_2);
        left[1] = BN254.scalarMul(proof.g1_q, helper.rho_2);
        left[2] = BN254.scalarMul(proof.g1_r, helper.rho_2);
        left[3] = BN254.scalarMul(g_mu_xi_t_n, helper.rho_2);

        right[0] = proof.g2_b;
        right[1] = vk.g_Z_H;
        right[2] = vk.g_tau;
        right[3] = vk.g2;
        
        return (left, right, g_mu_xi_t_n);
    }
    
    /**
     * @dev 为WTS优化验证准备点 - 第3部分
     */
    function prepareWtsOptPoints3(BN254.G1Point memory g_mu_xi_t_n) internal view returns (
        BN254.G1Point[5] memory left, 
        BN254.G2Point[5] memory right
    ) {
        // 等式(37) 系数 = rho^3
        left[0] = BN254.scalarMul(BN254.negate(proof.h1_p), helper.rho_3);
        left[1] = BN254.scalarMul(proof.g1_r, helper.rho_3);
        left[2] = BN254.scalarMul(g_mu_xi_t_n, helper.rho_3);
        
        right[0] = vk.g2;
        right[1] = vk.h_tau;
        right[2] = vk.h2;

        // 等式(38) 系数 = rho^4
        left[3] = BN254.scalarMul(BN254.negate(proof.v_mu), helper.rho_4);
        left[4] = BN254.scalarMul(proof.g_mu, helper.rho_4);
        
        right[3] = vk.g2;
        right[4] = vk.v2;
        
        return (left, right);
    }
    
    /**
     * @dev 处理WTS优化验证方法中equation 39
     */
    function wtsOptVerifyEq39(BN254.G2Point memory message_hash) internal view returns (bool) {
        // 等式(39) coeff = rho^5 - 单独计算
        return BN254.pairing2(
            BN254.scalarMul(BN254.negate(proof.g_mu), helper.rho_5), 
            message_hash, 
            BN254.scalarMul(vk.g1, helper.rho_5), 
            proof.sigma_bls
        );
    }
    
    /**
     * @dev 辅助函数 - 将多个固定大小的数组合并成一个动态数组
     */
    function combineFixedG1Arrays(
        BN254.G1Point[4] memory arr1,
        BN254.G1Point[4] memory arr2,
        BN254.G1Point[5] memory arr3
    ) internal pure returns (BN254.G1Point[] memory) {
        BN254.G1Point[] memory result = new BN254.G1Point[](13);
        
        // 复制第一个数组 (4个元素)
        for (uint i = 0; i < 4; i++) {
            result[i] = arr1[i];
        }
        
        // 复制第二个数组 (4个元素)
        for (uint i = 0; i < 4; i++) {
            result[i+4] = arr2[i];
        }
        
        // 复制第三个数组 (5个元素)
        for (uint i = 0; i < 5; i++) {
            result[i+8] = arr3[i];
        }
        
        return result;
    }
    
    /**
     * @dev 辅助函数 - 将多个固定大小的G2数组合并成一个动态数组
     */
    function combineFixedG2Arrays(
        BN254.G2Point[4] memory arr1,
        BN254.G2Point[4] memory arr2,
        BN254.G2Point[5] memory arr3
    ) internal pure returns (BN254.G2Point[] memory) {
        BN254.G2Point[] memory result = new BN254.G2Point[](13);
        
        // 复制第一个数组 (4个元素)
        for (uint i = 0; i < 4; i++) {
            result[i] = arr1[i];
        }
        
        // 复制第二个数组 (4个元素)
        for (uint i = 0; i < 4; i++) {
            result[i+4] = arr2[i];
        }
        
        // 复制第三个数组 (5个元素)
        for (uint i = 0; i < 5; i++) {
            result[i+8] = arr3[i];
        }
        
        return result;
    }
    
    /**
     * @dev WTS优化验证方法 - 使用随机线性组合
     */
    function wtsVerifyOptimized(BN254.G2Point memory message_hash, uint256 t) public returns (bool) {
        // 检查阈值
        if (proof.t_prime < t) {
            return false;
        }
        
        // 计算哈希和幂
        computeHashesAndPowers();
        
        // 准备三部分点
        (BN254.G1Point[4] memory left1, BN254.G2Point[4] memory right1) = prepareWtsOptPoints1();
        (BN254.G1Point[4] memory left2, BN254.G2Point[4] memory right2, BN254.G1Point memory g_mu_xi_t_n) = prepareWtsOptPoints2();
        (BN254.G1Point[5] memory left3, BN254.G2Point[5] memory right3) = prepareWtsOptPoints3(g_mu_xi_t_n);
        
        // 合并点数组
        BN254.G1Point[] memory allLeft = combineFixedG1Arrays(left1, left2, left3);
        BN254.G2Point[] memory allRight = combineFixedG2Arrays(right1, right2, right3);
        
        // 执行13对配对检查
        bool res = pairing13(allLeft, allRight);
        
        // 执行equation 39
        res = wtsOptVerifyEq39(message_hash) && res;
        
        return res;
    }
    
    /**
     * @dev 使用CredVerify替换equation 35的WTS验证方法 有问题
     */
    function wtsWithCredVerify(BN254.G2Point memory message_hash, uint256 t) public returns (bool) {
        // 检查阈值
        if (proof.t_prime < t) {
            return false;
        }
        
        // 准备credVerify所需参数
        (
            BN254.G1Point memory aggSigH,
            BN254.G1Point memory hDeltaJ,
            BN254.G1Point memory aggSigS
        ) = prepareCredVerifyParams();
        
        // 使用credVerify方法替换equation 35
        bool res = credVerify(aggSigH, hDeltaJ, aggSigS);
        if (!res) return false;
        
        // 计算哈希
        uint256 xi = hash_to_field(proof.g1_b, proof.g_mu, proof.t_prime, 0);
        uint256 xi_times_t_prime = mulmod(xi, proof.t_prime, BN254.R_MOD);
        
        // 进行各方程验证
        (bool res2, BN254.G1Point memory g_mu_plus_g1_xi_t_n) = wtsVerifyEq36(xi, xi_times_t_prime);
        if (!res2) return false;
        
        bool res3 = wtsVerifyEq37(g_mu_plus_g1_xi_t_n);
        if (!res3) return false;
        
        bool res4 = wtsVerifyEq38();
        if (!res4) return false;
        
        bool res5 = wtsVerifyEq39(message_hash);
        if (!res5) return false;
        
        return true;
    }
    
    /**
     * @dev 为优化的CredVerify验证准备点 - 第1部分
     */
    function prepareCredOptPoints1() internal view returns (BN254.G1Point[4] memory left, BN254.G2Point[4] memory right) {
        // 计算公共值
        BN254.G1Point memory gs_gw_xi = BN254.add(vk.g_s, BN254.scalarMul(vk.g_w, helper.xi));
        
        // 计算 g_mu + g1*xi_t_prime / n
        BN254.G1Point memory temp = BN254.add(proof.g_mu, BN254.scalarMul(vk.g1, helper.xi_times_t_prime));
        BN254.G1Point memory g_mu_xi_t_n = BN254.scalarMul(temp, vk.one_over_n);
        
        // 等式(36) 系数 = rho^2
        left[0] = BN254.scalarMul(BN254.negate(gs_gw_xi), helper.rho_2);
        left[1] = BN254.scalarMul(proof.g1_q, helper.rho_2);
        left[2] = BN254.scalarMul(proof.g1_r, helper.rho_2);
        left[3] = BN254.scalarMul(g_mu_xi_t_n, helper.rho_2);

        right[0] = proof.g2_b;
        right[1] = vk.g_Z_H;
        right[2] = vk.g_tau;
        right[3] = vk.g2;
        
        return (left, right);
    }
    
    /**
     * @dev 为优化的CredVerify验证准备点 - 第2部分
     */
    function prepareCredOptPoints2(BN254.G2Point memory message_hash) internal view returns (
        BN254.G1Point[8] memory left, 
        BN254.G2Point[8] memory right
    ) {
        // 计算 g_mu + g1*xi_t_prime / n
        BN254.G1Point memory temp = BN254.add(proof.g_mu, BN254.scalarMul(vk.g1, helper.xi_times_t_prime));
        BN254.G1Point memory g_mu_xi_t_n = BN254.scalarMul(temp, vk.one_over_n);
        
        // 等式(37) 系数 = rho^3
        left[0] = BN254.scalarMul(BN254.negate(proof.h1_p), helper.rho_3);
        left[1] = BN254.scalarMul(proof.g1_r, helper.rho_3);
        left[2] = BN254.scalarMul(g_mu_xi_t_n, helper.rho_3);
        
        right[0] = vk.g2;
        right[1] = vk.h_tau;
        right[2] = vk.h2;

        // 等式(38) 系数 = rho^4
        left[3] = BN254.scalarMul(BN254.negate(proof.v_mu), helper.rho_4);
        left[4] = BN254.scalarMul(proof.g_mu, helper.rho_4);
        
        right[3] = vk.g2;
        right[4] = vk.v2;
        
        // 等式(39) 系数 = rho^5
        left[5] = BN254.scalarMul(BN254.negate(proof.g_mu), helper.rho_5);
        left[6] = BN254.scalarMul(vk.g1, helper.rho_5);
        
        right[5] = message_hash;
        right[6] = proof.sigma_bls;
        
        // 保留一个点用于credVerify
        uint256 rho_c = helper.rho;
        left[7] = BN254.scalarMul(proof.g1_b, rho_c); // aggSigH
        right[7] = vk.g2; // combinedLvk
        
        return (left, right);
    }
    
    /**
     * @dev 辅助函数 - 将两个固定大小的数组合并为一个12元素动态数组
     */
    function combineTo12G1(
        BN254.G1Point[4] memory arr1,
        BN254.G1Point[8] memory arr2
    ) internal pure returns (BN254.G1Point[] memory) {
        BN254.G1Point[] memory result = new BN254.G1Point[](12);
        
        for (uint i = 0; i < 4; i++) {
            result[i] = arr1[i];
        }
        
        for (uint i = 0; i < 8; i++) {
            result[i+4] = arr2[i];
        }
        
        return result;
    }
    
    /**
     * @dev 辅助函数 - 将两个固定大小的G2数组合并为一个12元素动态数组
     */
    function combineTo12G2(
        BN254.G2Point[4] memory arr1,
        BN254.G2Point[8] memory arr2
    ) internal pure returns (BN254.G2Point[] memory) {
        BN254.G2Point[] memory result = new BN254.G2Point[](12);
        
        for (uint i = 0; i < 4; i++) {
            result[i] = arr1[i];
        }
        
        for (uint i = 0; i < 8; i++) {
            result[i+4] = arr2[i];
        }
        
        return result;
    }
    
    /**
     * @dev 使用优化的CredVerify替换equation 35的WTS验证方法 
     */
    function wtsWithCredVerifyOpt(BN254.G2Point memory message_hash, uint256 t) public returns (bool) {
        // 检查阈值
        if (proof.t_prime < t) {
            return false;
        }
        
        // 计算哈希和幂
        computeHashesAndPowers();
        
        // 准备第一部分点
        (BN254.G1Point[4] memory left1, BN254.G2Point[4] memory right1) = prepareCredOptPoints1();
        
        // 准备第二部分点
        (BN254.G1Point[8] memory left2, BN254.G2Point[8] memory right2) = prepareCredOptPoints2(message_hash);
        
        // 合并所有点
        BN254.G1Point[] memory allLeft = combineTo12G1(left1, left2);
        BN254.G2Point[] memory allRight = combineTo12G2(right1, right2);
        
        // 执行pairing12检查
        bool res = pairing12(allLeft, allRight);
        
        // 准备credVerify参数
        (
            BN254.G1Point memory aggSigH,
            BN254.G1Point memory hDeltaJ,
            BN254.G1Point memory aggSigS
        ) = prepareCredVerifyParams();
        
        // 执行credVerifyOptimized
        bool credResult = credVerifyOptimized(aggSigH, hDeltaJ, aggSigS);
        
        // 综合结果
        return res && credResult;
    }
    
    // ===== 测试函数 =====
    
    /**
     * @dev 测试WTS原始验证方法
     */
    function testWTSVerify() public returns (bool success, uint256 gasUsed) {
        // 假设验证密钥和证明已经设置好
        BN254.G2Point memory message_hash = BN254.P2();
        uint256 t = 100; // 示例阈值
        
        uint256 startGas = gasleft();
        success = wtsVerify(message_hash, t);
        gasUsed = startGas - gasleft();
        
        emit DebugLog("WTS original verification gas", gasUsed);
        
        return (success, gasUsed);
    }
    
    /**
     * @dev 测试WTS优化验证方法
     */
    function testWTSVerifyOptimized() public returns (bool success, uint256 gasUsed) {
        // 假设验证密钥和证明已经设置好
        BN254.G2Point memory message_hash = BN254.P2();
        uint256 t = 100; // 示例阈值
        
        uint256 startGas = gasleft();
        success = wtsVerifyOptimized(message_hash, t);
        gasUsed = startGas - gasleft();
        
        emit DebugLog("WTS optimized verification gas", gasUsed);
        
        return (success, gasUsed);
    }
    
    /**
     * @dev 测试使用CredVerify的WTS验证方法
     */
    function testWTSWithCredVerify() public returns (bool success, uint256 gasUsed) {
        // 假设验证密钥和证明已经设置好
        BN254.G2Point memory message_hash = BN254.P2();
        uint256 t = 100; // 示例阈值
        
        uint256 startGas = gasleft();
        success = wtsWithCredVerify(message_hash, t);
        gasUsed = startGas - gasleft();
        
        emit DebugLog("WTS with CredVerify gas", gasUsed);
        
        return (success, gasUsed);
    }
    
    /**
     * @dev 测试使用优化CredVerify的WTS验证方法
     */
    function testWTSWithCredVerifyOpt() public returns (bool success, uint256 gasUsed) {
        // 假设验证密钥和证明已经设置好
        BN254.G2Point memory message_hash = BN254.P2();
        uint256 t = 100; // 示例阈值
        
        uint256 startGas = gasleft();
        success = wtsWithCredVerifyOpt(message_hash, t);
        gasUsed = startGas - gasleft();
        
        emit DebugLog("WTS with optimized CredVerify gas", gasUsed);
        
        return (success, gasUsed);
    }
    
    /**
     * @dev 运行所有测试并记录结果
     */
    function runAllTests() public {
        // 测试原始WTS验证
        (bool wtsSuccess, uint256 wtsGas) = testWTSVerify();
        (bool wtsOptSuccess, uint256 wtsOptGas) = testWTSVerifyOptimized();
        
        // 测试使用CredVerify的WTS验证
        (bool credSuccess, uint256 credGas) = testWTSWithCredVerify();
        (bool credOptSuccess, uint256 credOptGas) = testWTSWithCredVerifyOpt();
        
        // 计算节省百分比 (相对于标准WTS方法)
        uint256 savingsPercent = 0;
        if (wtsGas > credGas) {
            savingsPercent = ((wtsGas - credGas) * 100) / wtsGas;
        }
        
        // 存储结果
        testResult = TestResult({
            wtsGas: wtsGas,
            wtsOptimizedGas: wtsOptGas,
            credVerifyGas: credGas,
            credVerifyOptGas: credOptGas,
            savingsPercent: savingsPercent
        });
        
        emit TestCompleted(wtsGas, wtsOptGas, credGas, credOptGas);
    }
    
    /**
     * @dev 获取测试结果
     */
    function getTestResults() public view returns (
        uint256 wtsGas,
        uint256 wtsOptimizedGas,
        uint256 credVerifyGas,
        uint256 credVerifyOptGas,
        uint256 savingsPercent
    ) {
        return (
            testResult.wtsGas,
            testResult.wtsOptimizedGas,
            testResult.credVerifyGas,
            testResult.credVerifyOptGas,
            testResult.savingsPercent
        );
    }
    
    /**
     * @dev 初始化合约状态用于测试
     * 注意：这只是填充一些值以使测试工作，在真实场景中您会使用实际的密钥和证明
     */
    function initialize() public {
        BN254.G1Point memory g1 = BN254.P1();
        BN254.G2Point memory g2 = BN254.P2();
        
        // 设置验证密钥
        set_vk(
            g1, g2, g2, g2, 
            g1, g1, g2, g2, g2,
            1000 // nb_users
        );
        
        // 设置证明
        set_proof(
            g1, g1, g2, g1, g2,
            g1, g1, g1, g1,
            200 // t_prime
        );
    }
}