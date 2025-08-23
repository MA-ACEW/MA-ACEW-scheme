// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.0;

/**
 * @title BN254
 * @dev BN254椭圆曲线操作的简化库
 */
library BN254 {
    // BN254曲线的模数
    uint256 public constant P_MOD = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;
    uint256 public constant R_MOD = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
    
    // 曲线上的点
    struct G1Point {
        uint256 x;
        uint256 y;
    }
    
    // 判断点是否为无穷远点
    function isInfinity(G1Point memory point) internal pure returns (bool) {
        return point.x == 0 && point.y == 0;
    }
    
    // 标量乘法（简化版，实际应使用更高效的实现）
    function scalarMul(G1Point memory p, uint256 scalar) internal view returns (G1Point memory r) {
        // 注意：这是一个非常简化的实现
        // 实际中应使用更高效的标量乘法算法
        if (scalar == 0 || isInfinity(p)) {
            return G1Point(0, 0); // 返回无穷远点
        }
        
        // 这里简化为假设我们有一个预编译合约来处理标量乘法
        // 在实际实现中，您需要使用真正的EC乘法算法或预编译合约
        // 这里仅作为示例，返回一个有效点
        r.x = mulmod(p.x, scalar, P_MOD);
        r.y = mulmod(p.y, scalar, P_MOD);
        
        return r;
    }
}

/**
 * @title EpochCredentialIssuer
 * @dev 负责发行epoch凭证，不依赖外部合约
 */
contract EpochCredentialIssuer {
    // 系统参数
    struct EbpsParams {
        BN254.G1Point ua; // G1上的生成元u
        BN254.G1Point va; // G1上的生成元v
    }
    
    // 存储系统参数
    EbpsParams public pp;
    
    // 存储签名者的临时密钥
    struct EpochKeys {
        uint256 tsk;      // 临时私钥 (z_i)
        uint256 epochId;  // epoch ID
        bool isSet;       // 是否已设置
    }
    
    // 签名者映射表 address => EpochKeys
    mapping(address => EpochKeys) public signerEpochKeys;
    
    // 有效签名者映射表
    mapping(address => bool) public validSigners;
    
    // 签名者长期密钥
    mapping(address => uint256) public signerLongKeys;
    
    // 当前epoch值
    uint256 public currentEpoch;
    
    // 已经处理过的用户请求的标记 (防止重放攻击)
    mapping(bytes32 => bool) public processedRequests;
    
    // 管理员地址
    address public admin;
    
    // epoch凭证发行事件
    event EpochCredentialIssued(
        address indexed issuer,
        bytes32 indexed userTagHash,
        uint256 epochId,
        uint256 timestamp
    );
    
    // 签名者注册事件
    event SignerRegistered(
        address indexed signer,
        uint256 timestamp
    );
    
    // 修饰符：仅管理员
    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin can call this function");
        _;
    }
    
    // 默认初始化合约
    constructor() {
        // 设置默认的系统参数
        // 这些值仅用于演示，实际应用中应使用安全生成的值
        pp.ua = BN254.G1Point(
            0x2f3a1269f6b4e9bd9b5b8cad54c01acb9ac999a3323ed92dbffc61863cd19934,
            0x1b00a5f83eba4d96c29c0f352315d4efafae15842c1a816f46c341eb0ab4d91e
        );
        pp.va = BN254.G1Point(
            0x1d69968e978583b01316f45a96b4d7c2d92cef9e4dad1dfa1b6d1d5b7d9a7ba2,
            0x17bd63730ef8f30e31cb311ff9b2c6330c5f73628be58c0bf1da405c1d9cf0db
        );
        
        admin = msg.sender;
        currentEpoch = block.timestamp / (30 days); // 每30天更新一次epoch
        
        // 将管理员设为默认的有效签名者（用于测试）
        validSigners[msg.sender] = true;
        signerLongKeys[msg.sender] = 0x1234567890; // 示例长期密钥
    }
    
    // 注册新的签名者（仅管理员可调用）
    function registerSigner(address signer, uint256 longKey) external onlyAdmin {
        validSigners[signer] = true;
        signerLongKeys[signer] = longKey;
        
        emit SignerRegistered(signer, block.timestamp);
    }
    
    // 取消签名者注册
    function deregisterSigner(address signer) external onlyAdmin {
        validSigners[signer] = false;
    }
    
    // 更新当前epoch
    function updateCurrentEpoch() public {
        uint256 newEpoch = block.timestamp / (30 days);
        if (newEpoch > currentEpoch) {
            currentEpoch = newEpoch;
        }
    }
    
    // 生成或更新签名者的epoch密钥
    function generateEpochKey() external {
        // 检查调用者是否为有效签名者
        require(validSigners[msg.sender], "Not a valid signer");
        uint256 lsk1 = signerLongKeys[msg.sender];
        
        // 确保当前epoch是最新的
        updateCurrentEpoch();
        
        // 派生epoch密钥
        uint256 epochSeed = uint256(keccak256(abi.encodePacked(currentEpoch, lsk1))) % BN254.R_MOD;
        
        // 存储epoch密钥
        signerEpochKeys[msg.sender] = EpochKeys({
            tsk: epochSeed,
            epochId: currentEpoch,
            isSet: true
        });
    }
    
    // 为测试目的手动设置epoch密钥
    function setEpochKey(uint256 tsk) external {
        require(validSigners[msg.sender], "Not a valid signer");
        
        // 确保当前epoch是最新的
        updateCurrentEpoch();
        
        // 存储epoch密钥
        signerEpochKeys[msg.sender] = EpochKeys({
            tsk: tsk,
            epochId: currentEpoch,
            isSet: true
        });
    }
    
    // 用于计算epoch凭证的内部函数
    function _calculateEpochCredential(
        BN254.G1Point[2] memory userTagG1,
        uint256 epochId,
        bytes32 requestId
    ) 
        internal 
        returns (BN254.G1Point memory) 
    {
        // 确保这个请求没有被处理过
        require(!processedRequests[requestId], "Request already processed");
        processedRequests[requestId] = true;
        
        // 获取签名者的epoch密钥
        uint256 tsk = signerEpochKeys[msg.sender].tsk;
        
        // 计算epoch凭证: cred_ep,i,j = (h^δ)^{j·z_i,j}
        uint256 epochExp = mulmod(epochId, tsk, BN254.R_MOD);
        
        // 确保不使用零作为乘数
        if (epochExp == 0) {
            epochExp = 1; // 默认值
        }
        
        // 计算 (h^δ)^{epoch·z_i}
        BN254.G1Point memory epochCredG1 = BN254.scalarMul(userTagG1[1], epochExp);
        
        // 验证结果不是无穷远点
        require(!BN254.isInfinity(epochCredG1), "Generated credential is infinity point");
        
        return epochCredG1;
    }
    
    /**
     * @dev 发行epoch凭证
     * @param userTagG1 用户的标签 [hGamma, hDelta]
     * @param epochId 指定的epoch ID
     * @return epochCredG1 epoch凭证
     */
    function issueEpochCredential(
        BN254.G1Point[2] memory userTagG1, // [hGamma, hDelta]
        uint256 epochId
    ) 
        public 
        returns (BN254.G1Point memory epochCredG1) 
    {
        // 确保当前epoch是最新的
        updateCurrentEpoch();
        
        // 确保请求的epoch ID有效
        require(epochId <= currentEpoch, "Future epoch not supported");
        require(epochId > 0, "Invalid epoch ID");
        
        // 确保签名者有效
        require(validSigners[msg.sender], "Not a valid signer");
        
        // 确保签名者有有效的epoch密钥
        require(signerEpochKeys[msg.sender].isSet, "Epoch key not set");
        require(signerEpochKeys[msg.sender].epochId == currentEpoch, "Epoch key outdated");
        
        // 计算请求的唯一标识，防止重放攻击
        bytes32 requestId = keccak256(abi.encodePacked(
            userTagG1[0].x, userTagG1[0].y,
            userTagG1[1].x, userTagG1[1].y,
            epochId,
            msg.sender
        ));
        
        // 计算凭证
        epochCredG1 = _calculateEpochCredential(userTagG1, epochId, requestId);
        
        // 发出凭证发行事件
        bytes32 userTagHash = keccak256(abi.encodePacked(
            userTagG1[0].x, userTagG1[0].y, 
            userTagG1[1].x, userTagG1[1].y
        ));
        
        emit EpochCredentialIssued(
            msg.sender,
            userTagHash,
            epochId,
            block.timestamp
        );
        
        return epochCredG1;
    }
    
    // 批量发行epoch凭证
    function batchIssueEpochCredentials(
        BN254.G1Point[2][] memory userTags,
        uint256 epochId
    ) 
        external 
        returns (BN254.G1Point[] memory epochCreds) 
    {
        require(userTags.length > 0, "Empty user tags array");
        
        epochCreds = new BN254.G1Point[](userTags.length);
        
        for (uint256 i = 0; i < userTags.length; i++) {
            epochCreds[i] = issueEpochCredential(userTags[i], epochId);
        }
        
        return epochCreds;
    }
    
    // 测试函数：测试mulmod操作
    function testMulMod(uint256 a, uint256 b) public pure returns (uint256) {
        return mulmod(a, b, BN254.R_MOD);
    }
}