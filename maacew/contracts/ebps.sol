// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./BN254.sol";

contract AggregatedBLSVerifier {
    using BN254 for *;
    
    struct Signature {
        BN254.G1Point h;  // 聚合签名的h部分
        BN254.G1Point s;  // 聚合签名的s部分
    }
    
    struct Tag {
        BN254.G1Point hGamma;  // 用户标签的h^gamma部分
        BN254.G1Point hDelta;  // 用户标签的h^delta部分
    }
    
    struct VerifierKey {
        BN254.G2Point lvk1;    // 长期验证密钥1
        BN254.G2Point lvk2;    // 长期验证密钥2
        BN254.G2Point tvk;     // 临时验证密钥
    }
    
    // 存储G2生成元
    BN254.G2Point private generatorG2;
    
    constructor() {
        // 初始化曲线生成元
        generatorG2 = BN254.P2();
    }
    
    // 访问生成元的getter
    function getGeneratorG2() public view returns (BN254.G2Point memory) {
        return generatorG2;
    }

    /**
     * @dev 验证聚合签名，返回结果和gas消耗
     */
    function testVerifyAggregatedSignature(
        uint64 j,
        Signature memory aggSig,
        Tag memory tag,
        uint256[] memory messages,
        VerifierKey[] memory verificationKeys
    ) public view returns (bool success, uint256 gasUsed) {
        uint256 startGas = gasleft();
        
        success = verifyAggregatedSignature(j, aggSig, tag, messages, verificationKeys);
        
        gasUsed = startGas - gasleft();
    }
    
    /**
     * @dev 验证聚合签名
     */
    function verifyAggregatedSignature(
        uint64 j,
        Signature memory aggSig,
        Tag memory tag,
        uint256[] memory messages,
        VerifierKey[] memory verificationKeys
    ) public view returns (bool) {
        // 1. 确保签名的数量匹配
        require(messages.length == verificationKeys.length, "Message and key count mismatch");
        require(messages.length > 0, "No messages to verify");
        
        // 2. 检查聚合签名中h不为单位元
        if (BN254.isInfinity(aggSig.h)) {
            return false;
        }
        
        // 3. 累积所有签名者的lvk1 + lvk2*m
        (BN254.G2Point memory temp1, BN254.G2Point memory Z) = accumulateVerificationComponents(messages, verificationKeys);
        
        // 4. 计算(h^δ)^j
        BN254.G1Point memory temp2 = BN254.scalarMul(tag.hDelta, j);
        
        // 5. 配对验证
        return performPairingCheck(aggSig, temp1, Z, temp2);
    }
    
    /**
     * @dev 累积验证组件
     */
    function accumulateVerificationComponents(
        uint256[] memory messages,
        VerifierKey[] memory verificationKeys
    ) internal pure returns (BN254.G2Point memory temp1, BN254.G2Point memory Z) {
        bool initialized = false;
        
        for (uint i = 0; i < messages.length; i++) {
            // 将消息转换为标量
            uint256 m = messages[i];
            
            // 计算lvk2[i] * m 和 lvk1[i] + lvk2[i] * m
            BN254.G2Point memory combined = combineVerificationKey(verificationKeys[i], m);
            
            if (!initialized) {
                temp1 = combined;
                Z = verificationKeys[i].tvk;
                initialized = true;
            } else {
                // 累加组件
                temp1 = addG2Points(temp1, combined);
                Z = addG2Points(Z, verificationKeys[i].tvk);
            }
        }
    }
    
    /**
     * @dev 组合验证密钥和消息
     */
    function combineVerificationKey(
        VerifierKey memory key, 
        uint256 m
    ) internal pure returns (BN254.G2Point memory result) {
        // 计算lvk2 * m
        BN254.G2Point memory scaledLvk2;
        scaledLvk2.x0 = mulmod(key.lvk2.x0, m, BN254.P_MOD);
        scaledLvk2.x1 = mulmod(key.lvk2.x1, m, BN254.P_MOD);
        scaledLvk2.y0 = mulmod(key.lvk2.y0, m, BN254.P_MOD);
        scaledLvk2.y1 = mulmod(key.lvk2.y1, m, BN254.P_MOD);
        
        // 计算lvk1 + lvk2 * m
        result.x0 = addmod(key.lvk1.x0, scaledLvk2.x0, BN254.P_MOD);
        result.x1 = addmod(key.lvk1.x1, scaledLvk2.x1, BN254.P_MOD);
        result.y0 = addmod(key.lvk1.y0, scaledLvk2.y0, BN254.P_MOD);
        result.y1 = addmod(key.lvk1.y1, scaledLvk2.y1, BN254.P_MOD);
    }
    
    /**
     * @dev 执行配对检查
     */
    function performPairingCheck(
        Signature memory aggSig,
        BN254.G2Point memory temp1,
        BN254.G2Point memory Z,
        BN254.G1Point memory temp2
    ) internal view returns (bool) {
        BN254.G1Point[3] memory g1Points;
        BN254.G2Point[3] memory g2Points;
        
        g1Points[0] = aggSig.h;
        g1Points[1] = temp2;
        g1Points[2] = aggSig.s;
        
        g2Points[0] = temp1;
        g2Points[1] = Z;
        
        // 计算-generatorG2
        BN254.G2Point memory negG2 = generatorG2;
        negG2.y0 = BN254.P_MOD - negG2.y0;
        negG2.y1 = BN254.P_MOD - negG2.y1;
        g2Points[2] = negG2;
        
        return BN254.pairing3(g1Points, g2Points);
    }
    
    /**
     * @dev G2点加法
     */
    function addG2Points(
        BN254.G2Point memory a, 
        BN254.G2Point memory b
    ) internal pure returns (BN254.G2Point memory result) {
        result.x0 = addmod(a.x0, b.x0, BN254.P_MOD);
        result.x1 = addmod(a.x1, b.x1, BN254.P_MOD);
        result.y0 = addmod(a.y0, b.y0, BN254.P_MOD);
        result.y1 = addmod(a.y1, b.y1, BN254.P_MOD);
    }

    /**
     * @dev 测试1个消息的验证
     */
    function testVerify1(
        uint64 j,
        Signature memory aggSig,
        Tag memory tag,
        uint256[] memory messages,
        VerifierKey[] memory verificationKeys
    ) public view returns (bool success, uint256 gasUsed) {
        require(messages.length >= 1, "Need at least 1 message");
        require(verificationKeys.length >= 1, "Need at least 1 verification key");
        
        // 创建长度为1的测试数组
        uint256[] memory msgs = new uint256[](1);
        VerifierKey[] memory vks = new VerifierKey[](1);
        msgs[0] = messages[0];
        vks[0] = verificationKeys[0];
        
        return testVerifyAggregatedSignature(j, aggSig, tag, msgs, vks);
    }
    
    /**
     * @dev 测试2个消息的验证
     */
    function testVerify2(
        uint64 j,
        Signature memory aggSig,
        Tag memory tag,
        uint256[] memory messages,
        VerifierKey[] memory verificationKeys
    ) public view returns (bool success, uint256 gasUsed) {
        require(messages.length >= 2, "Need at least 2 messages");
        require(verificationKeys.length >= 2, "Need at least 2 verification keys");
        
        // 创建长度为2的测试数组
        uint256[] memory msgs = new uint256[](2);
        VerifierKey[] memory vks = new VerifierKey[](2);
        
        for(uint i = 0; i < 2; i++) {
            msgs[i] = messages[i];
            vks[i] = verificationKeys[i];
        }
        
        return testVerifyAggregatedSignature(j, aggSig, tag, msgs, vks);
    }
    
    /**
     * @dev 测试5个消息的验证
     */
    function testVerify5(
        uint64 j,
        Signature memory aggSig,
        Tag memory tag,
        uint256[] memory messages,
        VerifierKey[] memory verificationKeys
    ) public view returns (bool success, uint256 gasUsed) {
        require(messages.length >= 5, "Need at least 5 messages");
        require(verificationKeys.length >= 5, "Need at least 5 verification keys");
        
        // 创建长度为5的测试数组
        uint256[] memory msgs = new uint256[](5);
        VerifierKey[] memory vks = new VerifierKey[](5);
        
        for(uint i = 0; i < 5; i++) {
            msgs[i] = messages[i];
            vks[i] = verificationKeys[i];
        }
        
        return testVerifyAggregatedSignature(j, aggSig, tag, msgs, vks);
    }
    
    /**
     * @dev 测试10个消息的验证
     */
    function testVerify10(
        uint64 j,
        Signature memory aggSig,
        Tag memory tag,
        uint256[] memory messages,
        VerifierKey[] memory verificationKeys
    ) public view returns (bool success, uint256 gasUsed) {
        require(messages.length >= 10, "Need at least 10 messages");
        require(verificationKeys.length >= 10, "Need at least 10 verification keys");
        
        // 创建长度为10的测试数组
        uint256[] memory msgs = new uint256[](10);
        VerifierKey[] memory vks = new VerifierKey[](10);
        
        for(uint i = 0; i < 10; i++) {
            msgs[i] = messages[i];
            vks[i] = verificationKeys[i];
        }
        
        return testVerifyAggregatedSignature(j, aggSig, tag, msgs, vks);
    }
    
    /**
     * @dev 生成测试数据的函数
     */
    function generateTestData() public pure returns (
        Signature memory sig,
        Tag memory tag,
        uint256[] memory messages,
        VerifierKey[] memory keys
    ) {
        // 这只是示例数据，实际使用时需要用有效的测试数据替换
        sig = Signature({
            h: BN254.G1Point(1, 2),
            s: BN254.G1Point(3, 4)
        });
        
        tag = Tag({
            hGamma: BN254.G1Point(5, 6),
            hDelta: BN254.G1Point(7, 8)
        });
        
        messages = new uint256[](10);
        for(uint i = 0; i < 10; i++) {
            messages[i] = i + 1; // 简单的测试消息
        }
        
        keys = new VerifierKey[](10);
        for(uint i = 0; i < 10; i++) {
            keys[i] = VerifierKey({
                lvk1: BN254.G2Point(9, 10, 11, 12),
                lvk2: BN254.G2Point(13, 14, 15, 16),
                tvk: BN254.G2Point(17, 18, 19, 20)
            });
        }
    }
    
    /**
     * @dev 直接测试配对操作的gas消耗
     */
    function testPairingOperation() public view returns (bool success, uint256 gasUsed) {
        uint256 startGas = gasleft();
        
        BN254.G1Point[3] memory g1Points;
        BN254.G2Point[3] memory g2Points;
        
        // 创建一些测试点
        g1Points[0] = BN254.P1();
        g1Points[1] = BN254.P1();
        g1Points[2] = BN254.P1();
        
        g2Points[0] = BN254.P2();
        g2Points[1] = BN254.P2();
        g2Points[2] = BN254.P2();
        
        // 执行配对
        success = BN254.pairing3(g1Points, g2Points);
        
        gasUsed = startGas - gasleft();
    }
}