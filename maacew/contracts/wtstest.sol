// SPDX-License-Identifier: UNLICENSED
//This is not our code, the source code is from https://github.com/sourav1547/wts.
pragma solidity ^0.8.13;

import "./wts.sol";
import {BN254} from "./BN254.sol";
import {Utils} from "./Utils.sol";
import "./CommonStructs.sol";

contract WTSTest {
    WTS wts;
    
    constructor(address wtsAddress) {
        wts = WTS(wtsAddress);
    }
    
  
    function testScalarMulGas() public returns (BN254.G1Point memory) {
     
        BN254.G1Point memory p = BN254.G1Point(
            0x2f1c88f236869a9ba3ffb3a7405b21a3f4ce1f5a86ca39d179f383017a6a311a,
            0x1fb86a5d382b5d95bb9cb4ba9b7bad3ca5bd5519413d187fb6c9ff15a12282d4
        );
        uint256 scalar = 123456789;
        
        return wts.callScalarMul(p, scalar);
    }
    
  
    function testPairingCheckGas() public returns (bool) {
        BN254.G1Point memory p1 = BN254.G1Point(
            0x2f1c88f236869a9ba3ffb3a7405b21a3f4ce1f5a86ca39d179f383017a6a311a,
            0x1fb86a5d382b5d95bb9cb4ba9b7bad3ca5bd5519413d187fb6c9ff15a12282d4
        );
        
        BN254.G2Point memory p2 = BN254.G2Point(
            0x22553b3a9e75c481b85051d82c0d071d2645c48f5c6bf3cdfbb9cc3ecda72454, 
            0x20b3dbbfa9ed46d1d09cde3a88216b5ed3f53a5ed9b7a125265a8bc600f72756,
            0x0af1ea3c9970151c44058a2049c3a69d37f141e3496f82e6f6dbfb85a672d47f, 
            0x17fb0aba62a17d5aa18a7937a28c5a6958a33a5a195f5b8eb2fb15843cbc9b2a
        );
        
        return wts.simple_pairing_check(p1, p2);
    }
    
  
    function testHashToFieldGas() public view returns (uint256) {
        BN254.G1Point memory g_b = BN254.G1Point(
            0x2f1c88f236869a9ba3ffb3a7405b21a3f4ce1f5a86ca39d179f383017a6a311a,
            0x1fb86a5d382b5d95bb9cb4ba9b7bad3ca5bd5519413d187fb6c9ff15a12282d4
        );
        
        BN254.G1Point memory g_mu = BN254.G1Point(
            0x1c76bc3f82db1a8d989067937a9b3ae0a5b217c8355c0c475ea0e04689117054,
            0x11a4fd5bd3b97a933bf9f9861d2ac12e38b60d37d1f60c116b6f6f17da2e8964
        );
        
        uint256 t_prime = 1000;
        uint256 extra = 0;
        
        return wts.hash_to_field(g_b, g_mu, t_prime, extra);
    }
    
  
    function testSetVkGas() public {
        BN254.G1Point memory g1 = BN254.G1Point(
            0x2f1c88f236869a9ba3ffb3a7405b21a3f4ce1f5a86ca39d179f383017a6a311a,
            0x1fb86a5d382b5d95bb9cb4ba9b7bad3ca5bd5519413d187fb6c9ff15a12282d4
        );
        
        BN254.G2Point memory g2 = BN254.G2Point(
            0x22553b3a9e75c481b85051d82c0d071d2645c48f5c6bf3cdfbb9cc3ecda72454, 
            0x20b3dbbfa9ed46d1d09cde3a88216b5ed3f53a5ed9b7a125265a8bc600f72756,
            0x0af1ea3c9970151c44058a2049c3a69d37f141e3496f82e6f6dbfb85a672d47f, 
            0x17fb0aba62a17d5aa18a7937a28c5a6958a33a5a195f5b8eb2fb15843cbc9b2a
        );
        
        BN254.G2Point memory h2 = BN254.G2Point(
            0x0b8e0094c886487870372eb6264613a6a087c7eb9804fab789be4e47a57b29eb, 
            0x0c0ae4e8a52dfe8d77eefd095273720c0b0fcd5e674ac41a32f5f3afc0d30d4c,
            0x2d89298d62b3add206bc0eda765907f25070f06d771d221fe5e8b786970c42e8, 
            0x0be0fa922012bc150e53eb73e5d1852c78890eb8bd3946e485c995c8340747ac
        );
        
        BN254.G2Point memory v2 = BN254.G2Point(
            0x19565c6c3d9a03618e98e89fbec1aad7794ca1d8d8021ad4ce1c592d5b210d63, 
            0x17c9c57893e02e07e6cb33ebe288315e298d234ae4dfae403337a16e228b4c29,
            0x03fbd96c4dc5a3c45096c99da1cb6b2e979532bf622386ac91d5c659a9c5a715, 
            0x2cd5f2d0b9f8d226eaa52d2fa46bb97d3423bbe0a5a560e54ad9a521ce157594
        );
        
        BN254.G1Point memory g_s = BN254.G1Point(
            0x1c76bc3f82db1a8d989067937a9b3ae0a5b217c8355c0c475ea0e04689117054,
            0x11a4fd5bd3b97a933bf9f9861d2ac12e38b60d37d1f60c116b6f6f17da2e8964
        );
        
        BN254.G1Point memory g_w = BN254.G1Point(
            0x0a41654b300a1f2784b3c145fa4828118c82c8c6081ace53d11fca5351343f3b,
            0x28a793d25ae0e28fb45bb7cf3c78d80472ec31ba059bdcd3d6d43e37910c0b3e
        );
        
        BN254.G2Point memory g_tau = BN254.G2Point(
            0x0afdc6f862d0a97f10f6a1fa3efc4f1c3ce38239d794a2e48e3432df11e49858, 
            0x09fe8e66555fa4e14af3055efef2a8efda1ae5154ab7862e6ad1ee562c4eef37,
            0x1f6a01bef740ee87f2f8e0e5160b0d61f6d5ca412a09f7d65c566ebdbe3dd7f0, 
            0x0e3dcf89329bb85a731f21a88db7d952daa983a9c7954bf37ff7d9bf9ab146a1
        );
        
        BN254.G2Point memory h_tau = BN254.G2Point(
            0x1a0f0bb550b67a6042f3d4f5d43fae98ae5109b6eac35d76dce27a9db9be58d4, 
            0x086ca80d7b0a58adcd1456ad8fa023879029fb6f16e816170a46d60013335384,
            0x0c1fba423a2e899d57ea82636e90c4117e333447a81b94751d77d8ef267be485, 
            0x295c58eade14b9ec4d9769c3a65bf7d16d0228da9c4f004f3a8e9d03f3f2c52c
        );
        
        BN254.G2Point memory g_z_H = BN254.G2Point(
            0x042b525e566e1a38cce5acfa129c95b181dd9f3148920f886cb143b44dfc47a0, 
            0x23e0079aa7f5d1a5e2f65812ce51137af422258b407f33ce2637e2e9c2833256,
            0x0fc2f9af0c2f7a5b5c0bbab693d604c9d1c66eceb8842a3a5234fbcc23b34b5a, 
            0x2e9e97eb4a593e9b5b756a2e69a73323191c6983427aa11def46367e2c640f76
        );
        
        uint256 nb_users = 10;
        
        wts.set_vk(g1, g2, h2, v2, g_s, g_w, g_tau, h_tau, g_z_H, nb_users);
    }
    
   
    function testSetProofGas() public {
        BN254.G1Point memory g_mu = BN254.G1Point(
            0x1c76bc3f82db1a8d989067937a9b3ae0a5b217c8355c0c475ea0e04689117054,
            0x11a4fd5bd3b97a933bf9f9861d2ac12e38b60d37d1f60c116b6f6f17da2e8964
        );
        
        BN254.G1Point memory g1_b = BN254.G1Point(
            0x2f1c88f236869a9ba3ffb3a7405b21a3f4ce1f5a86ca39d179f383017a6a311a,
            0x1fb86a5d382b5d95bb9cb4ba9b7bad3ca5bd5519413d187fb6c9ff15a12282d4
        );
        
        BN254.G2Point memory g2_b = BN254.G2Point(
            0x22553b3a9e75c481b85051d82c0d071d2645c48f5c6bf3cdfbb9cc3ecda72454, 
            0x20b3dbbfa9ed46d1d09cde3a88216b5ed3f53a5ed9b7a125265a8bc600f72756,
            0x0af1ea3c9970151c44058a2049c3a69d37f141e3496f82e6f6dbfb85a672d47f, 
            0x17fb0aba62a17d5aa18a7937a28c5a6958a33a5a195f5b8eb2fb15843cbc9b2a
        );
        
        BN254.G1Point memory gq_b = BN254.G1Point(
            0x0a41654b300a1f2784b3c145fa4828118c82c8c6081ace53d11fca5351343f3b,
            0x28a793d25ae0e28fb45bb7cf3c78d80472ec31ba059bdcd3d6d43e37910c0b3e
        );
        
        BN254.G2Point memory sigma_bls = BN254.G2Point(
            0x19565c6c3d9a03618e98e89fbec1aad7794ca1d8d8021ad4ce1c592d5b210d63, 
            0x17c9c57893e02e07e6cb33ebe288315e298d234ae4dfae403337a16e228b4c29,
            0x03fbd96c4dc5a3c45096c99da1cb6b2e979532bf622386ac91d5c659a9c5a715, 
            0x2cd5f2d0b9f8d226eaa52d2fa46bb97d3423bbe0a5a560e54ad9a521ce157594
        );
        
        BN254.G1Point memory g1_q = BN254.G1Point(
            0x15793235fcade1cfa75f2e10797a8c15a7ec8a9d3e88a8d9685970af99e8d150,
            0x2aa650ffaede7c0108c20bf1395d63f7312462bf9dcc73da35fa39302adc3d3c
        );
        
        BN254.G1Point memory g1_r = BN254.G1Point(
            0x2bbcf394db79ab6dc724feafec1252b8f57047e73fd51d24c1cfd3717b2cbe62,
            0x2d98bb1c203783144c0778a3e15461bf9e3ba942daa94b56f51f2869c4107546
        );
        
        BN254.G1Point memory h1_p = BN254.G1Point(
            0x17d61c178996c531ecb003bd851620a93f88098c99d3c5dedac7f7caf7e2a09e,
            0x204a0aac5e61358e98f3b279de5f4838a6d55b832083e13ac4addc8abc78a100
        );
        
        BN254.G1Point memory v_mu = BN254.G1Point(
            0x21ff686e82c70c2af3c40c4cebd5e264cc41a89a28b3d497723f38e729fcb902,
            0x1be2c7ef465bd6745ddd46d852d4edc9a13fa0ec16f1a7caf87aae13abb01278
        );
        
        uint256 t_prime = 7; 
        
        wts.set_proof(g_mu, g1_b, g2_b, gq_b, sigma_bls, g1_q, g1_r, h1_p, v_mu, t_prime);
    }
    
   
    function testVerifyGas() public view returns (bool) {
       
        
        BN254.G2Point memory message_hash = BN254.G2Point(
            0x1aa3c95bdb7f18dcdaef9e8946334b54610d17dd73a45b5ae170e48b34745903, 
            0x18da6baddbacf5d0bedb652e601b49834db3c7ce5ff9a57d11b3767a052b58a2,
            0x006109436c5ecc748b72e948cc5b8b0db8eafc83cd0d66efcd317d27b05c429a, 
            0x0ee0e8fba4f3a8d2afe9f68e4c85cefe8a3e55c1a1e7153d37ad9a5816c2e81d
        );
        
        uint256 threshold = 5;
        
        return wts.verify(message_hash, threshold);
    }

}

