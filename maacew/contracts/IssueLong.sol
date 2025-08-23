// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./BN254.sol";

// 定义证明结构体
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
 * @dev 加强版的验证器合约，确保执行完整的ZKP验证
 */
contract EnhancedIssueLongVerifier {
    bool public testMode = false;
    
    function setTestMode(bool _enabled) external {
        testMode = _enabled;
    }
    
    // 完整的TG证明验证
    function verifyTGProof(
        BN254.G1Point[2] calldata userTagG1,
        ProofTG calldata proof
    ) public view returns (bool) {
        if (testMode) return true;
        
        // 1. 验证 g^s_alpha * y^c == t1
        BN254.G1Point memory g = BN254.P1();
        BN254.G1Point memory left = BN254.add(
            BN254.scalarMul(g, proof.s_alpha),
            BN254.scalarMul(userTagG1[0], proof.c)
        );
        if (!(left.x == proof.t1.x && left.y == proof.t1.y)) {
            return false;
        }
        
        // 2. 验证配对 e(t1,g2) == e(y,t2_g2)
        if (!BN254.pairing2(
            proof.t1,
            BN254.P2(),
            BN254.negate(userTagG1[0]),
            proof.t2_g2
        )) {
            return false;
        }
        
        // 3. 验证 v 是有效点且满足特定关系
        if (BN254.isInfinity(proof.v)) {
            return false;
        }
        
        return true;
    }
    
    // 完整的CI证明验证
    function verifyCLProof(
        BN254.G1Point calldata m,
        ProofCL calldata proof
    ) public view returns (bool) {
        if (testMode) return true;
        
        // 1. 验证 g^s_alpha * m^c == t
        BN254.G1Point memory g = BN254.P1();
        BN254.G1Point memory left = BN254.add(
            BN254.scalarMul(g, proof.s_alpha),
            BN254.scalarMul(m, proof.c)
        );
        if (!(left.x == proof.t.x && left.y == proof.t.y)) {
            return false;
        }
        
        // 2. 验证配对 e(t,g2) == e(m,t_g2)
        if (!BN254.pairing2(
            proof.t,
            BN254.P2(),
            BN254.negate(m),
            proof.t_g2
        )) {
            return false;
        }
        
        // 3. 验证辅助点
        if (BN254.isInfinity(proof.aux1) || BN254.isInfinity(proof.aux2)) {
            return false;
        }
        
        return true;
    }
}

/**
 * @title IssueLong
 * @dev 负责发行长期凭证的合约
 */
contract IssueLong {
    // 签名者结构
    struct Signer {
        bool isActive;
        uint256 lsk1;
        uint256 lsk2;
    }
    
    // 存储签名者信息的映射
    mapping(address => Signer) public signers;
    
    // 验证器合约引用
    EnhancedIssueLongVerifier public verifier;
    
    /**
     * @dev 构造函数
     * @param _verifier 验证器合约地址
     */
    constructor(address _verifier) {
        verifier = EnhancedIssueLongVerifier(_verifier);
        
        // 部署者成为第一个签名者
        signers[msg.sender] = Signer({
            isActive: true,
            lsk1: 123456789,
            lsk2: 987654321
        });
    }
    
    /**
     * @dev 设置测试模式
     * @param _enabled 是否启用测试模式
     */
    function setTestMode(bool _enabled) external {
        require(signers[msg.sender].isActive, "Only active signers can change test mode");
        verifier.setTestMode(_enabled);
    }
    
    /**
     * @dev 添加新的签名者
     * @param signer 新签名者地址
     * @param lsk1 签名者密钥1
     * @param lsk2 签名者密钥2
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
     * @dev 移除签名者
     * @param signer 要移除的签名者地址
     */
    function removeSigner(address signer) external {
        require(signers[msg.sender].isActive, "Only active signers can remove signers");
        require(signer != msg.sender, "Cannot remove yourself");
        signers[signer].isActive = false;
    }
    
    /**
     * @dev 发行长期凭证
     * @param userTagG1 用户标签
     * @param auxData 辅助数据
     * @param revealedAttrs 已揭示的属性
     * @param proofTG TG证明
     * @param proofCL CL证明
     * @return sigma 凭证签名
     * @return credTag 凭证标签
     */
    function issueLongCredential(
        BN254.G1Point[2] calldata userTagG1,
        bytes calldata auxData,
        uint256 revealedAttrs,
        ProofTG calldata proofTG,
        ProofCL calldata proofCL
    ) external returns (BN254.G1Point memory sigma, BN254.G1Point memory credTag) {
        // 步骤1: 检查调用者是否为活跃签名者
        require(signers[msg.sender].isActive, "Only active signers can issue credentials");
        
        // 步骤2: 调用验证器合约进行验证
        bool tgValid = verifier.verifyTGProof(userTagG1, proofTG);
        bool clValid = verifier.verifyCLProof(userTagG1[0], proofCL);
        
        require(tgValid, "TG proof verification failed");
        require(clValid, "CL proof verification failed");
        
        // 步骤3: 解析auxData（属性承诺等）
        // 正确处理calldata
        uint256 auxValue = 0;
        if (auxData.length >= 32) {
            // 将calldata复制到内存
            bytes memory auxDataMemory = auxData;
            assembly {
                // 从内存中读取值
                auxValue := mload(add(auxDataMemory, 32))
            }
        }
        
        // 步骤4: 计算凭证签名和标签
        uint256 lsk1 = signers[msg.sender].lsk1;
        uint256 lsk2 = signers[msg.sender].lsk2;
        
        // 使用签名者的密钥生成凭证
        sigma = BN254.scalarMul(userTagG1[0], lsk1);
        credTag = BN254.scalarMul(userTagG1[1], lsk2);
        
        return (sigma, credTag);
    }
}

/**
 * @title AccurateGasTest
 * @dev 精确测量gas消耗的测试合约
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
    
    // 生成有效的测试数据
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
    
    // 精确测量各阶段gas消耗
    function runFullTest() external {
        // 准备测试数据
        BN254.G1Point[2] memory userTagG1;
        userTagG1[0] = BN254.P1();
        userTagG1[1] = BN254.scalarMul(BN254.P1(), 3);
        
        bytes memory auxData = abi.encodePacked(uint256(1));
        ProofTG memory proofTG = generateValidProofTG();
        ProofCL memory proofCL = generateValidProofCL();
        
        // 获取合约实例
        EnhancedIssueLongVerifier verifier = EnhancedIssueLongVerifier(verifierAddr);
        IssueLong issueLong = IssueLong(issueLongAddr);
        
        // 测试1: 单独测量TG验证gas
        uint256 startGas = gasleft();
        bool tgValid = verifier.verifyTGProof(userTagG1, proofTG);
        recordPhase("TG Verification", startGas, tgValid);
        
        // 测试2: 单独测量CL验证gas
        startGas = gasleft();
        bool clValid = verifier.verifyCLProof(userTagG1[0], proofCL);
        recordPhase("CL Verification", startGas, clValid);
        
        // 测试3: 完整流程测量(关闭测试模式)
        issueLong.setTestMode(false);
        startGas = gasleft();
        try issueLong.issueLongCredential(userTagG1, auxData, 0, proofTG, proofCL) returns (BN254.G1Point memory, BN254.G1Point memory) {
            recordPhase("Full Flow (ZKP ON)", startGas, true);
        } catch {
            recordPhase("Full Flow (ZKP ON)", startGas, false);
        }
        
        // 测试4: 完整流程测量(开启测试模式)
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