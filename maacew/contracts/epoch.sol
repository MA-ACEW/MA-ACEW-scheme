// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.0;

/**
 * @title BN254
 * @dev 
 */
library BN254 {
  
    uint256 public constant P_MOD = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;
    uint256 public constant R_MOD = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
    
   
    struct G1Point {
        uint256 x;
        uint256 y;
    }
    
    
    function isInfinity(G1Point memory point) internal pure returns (bool) {
        return point.x == 0 && point.y == 0;
    }
    
   
    function scalarMul(G1Point memory p, uint256 scalar) internal view returns (G1Point memory r) {
       
        if (scalar == 0 || isInfinity(p)) {
            return G1Point(0, 0); 
        }
        
      
        r.x = mulmod(p.x, scalar, P_MOD);
        r.y = mulmod(p.y, scalar, P_MOD);
        
        return r;
    }
}

/**
 * @title EpochCredentialIssuer
 * @dev 
 */
contract EpochCredentialIssuer {
   
    struct EbpsParams {
        BN254.G1Point ua; 
        BN254.G1Point va; 
    }
    
   
    EbpsParams public pp;
    
   
    struct EpochKeys {
        uint256 tsk;      
        uint256 epochId;  
        bool isSet;       
    }
    
    
    mapping(address => EpochKeys) public signerEpochKeys;
    
   
    mapping(address => bool) public validSigners;
    
   
    mapping(address => uint256) public signerLongKeys;
    
   
    uint256 public currentEpoch;
    
 
    mapping(bytes32 => bool) public processedRequests;
    
    
    address public admin;
    
  
    event EpochCredentialIssued(
        address indexed issuer,
        bytes32 indexed userTagHash,
        uint256 epochId,
        uint256 timestamp
    );
    
   
    event SignerRegistered(
        address indexed signer,
        uint256 timestamp
    );
    
   
    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin can call this function");
        _;
    }
    
   
    constructor() {
       
        pp.ua = BN254.G1Point(
            0x2f3a1269f6b4e9bd9b5b8cad54c01acb9ac999a3323ed92dbffc61863cd19934,
            0x1b00a5f83eba4d96c29c0f352315d4efafae15842c1a816f46c341eb0ab4d91e
        );
        pp.va = BN254.G1Point(
            0x1d69968e978583b01316f45a96b4d7c2d92cef9e4dad1dfa1b6d1d5b7d9a7ba2,
            0x17bd63730ef8f30e31cb311ff9b2c6330c5f73628be58c0bf1da405c1d9cf0db
        );
        
        admin = msg.sender;
        currentEpoch = block.timestamp / (30 days); 
        
       
        validSigners[msg.sender] = true;
        signerLongKeys[msg.sender] = 0x1234567890; 
    }
    
    
    function registerSigner(address signer, uint256 longKey) external onlyAdmin {
        validSigners[signer] = true;
        signerLongKeys[signer] = longKey;
        
        emit SignerRegistered(signer, block.timestamp);
    }
    
   
    function deregisterSigner(address signer) external onlyAdmin {
        validSigners[signer] = false;
    }
    
    
    function updateCurrentEpoch() public {
        uint256 newEpoch = block.timestamp / (30 days);
        if (newEpoch > currentEpoch) {
            currentEpoch = newEpoch;
        }
    }
    
   
    function generateEpochKey() external {
      
        require(validSigners[msg.sender], "Not a valid signer");
        uint256 lsk1 = signerLongKeys[msg.sender];
        
        
        updateCurrentEpoch();
        
       
        uint256 epochSeed = uint256(keccak256(abi.encodePacked(currentEpoch, lsk1))) % BN254.R_MOD;
        
      
        signerEpochKeys[msg.sender] = EpochKeys({
            tsk: epochSeed,
            epochId: currentEpoch,
            isSet: true
        });
    }
    
    
    function setEpochKey(uint256 tsk) external {
        require(validSigners[msg.sender], "Not a valid signer");
        
       
        updateCurrentEpoch();
        
        
        signerEpochKeys[msg.sender] = EpochKeys({
            tsk: tsk,
            epochId: currentEpoch,
            isSet: true
        });
    }
    
   
    function _calculateEpochCredential(
        BN254.G1Point[2] memory userTagG1,
        uint256 epochId,
        bytes32 requestId
    ) 
        internal 
        returns (BN254.G1Point memory) 
    {
       
        require(!processedRequests[requestId], "Request already processed");
        processedRequests[requestId] = true;
        
        
        uint256 tsk = signerEpochKeys[msg.sender].tsk;
        
       
        uint256 epochExp = mulmod(epochId, tsk, BN254.R_MOD);
        
        
        if (epochExp == 0) {
            epochExp = 1; 
        }
        
        
        BN254.G1Point memory epochCredG1 = BN254.scalarMul(userTagG1[1], epochExp);
        
       
        require(!BN254.isInfinity(epochCredG1), "Generated credential is infinity point");
        
        return epochCredG1;
    }
    
    
    function issueEpochCredential(
        BN254.G1Point[2] memory userTagG1, // [hGamma, hDelta]
        uint256 epochId
    ) 
        public 
        returns (BN254.G1Point memory epochCredG1) 
    {
      
        updateCurrentEpoch();
        
     
        require(epochId <= currentEpoch, "Future epoch not supported");
        require(epochId > 0, "Invalid epoch ID");
        
       
        require(validSigners[msg.sender], "Not a valid signer");
        
       
        require(signerEpochKeys[msg.sender].isSet, "Epoch key not set");
        require(signerEpochKeys[msg.sender].epochId == currentEpoch, "Epoch key outdated");
        
       
        bytes32 requestId = keccak256(abi.encodePacked(
            userTagG1[0].x, userTagG1[0].y,
            userTagG1[1].x, userTagG1[1].y,
            epochId,
            msg.sender
        ));
        
       
        epochCredG1 = _calculateEpochCredential(userTagG1, epochId, requestId);
        
      
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
    
  
    function testMulMod(uint256 a, uint256 b) public pure returns (uint256) {
        return mulmod(a, b, BN254.R_MOD);
    }

}
