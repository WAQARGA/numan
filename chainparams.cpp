// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2022-2024 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <iostream>
#include "arith_uint256.h"
#include "chainparams.h"
#include "consensus/merkle.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "chainparamsseeds.h"

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block.
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    // NEW TIMESTAMP FOR AURAXCOIN
    const char* pszTimestamp = "AuraXcoin Launched Dec 2025 - Future of Crypto";
    const CScript genesisOutputScript = CScript() << ParseHex("040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
class CMainParams : public CChainParams {
private:
    Consensus::Params digishieldConsensus;
    Consensus::Params auxpowConsensus;
public:
    CMainParams() {
        strNetworkID = "main";

        // Blocks 0 - 144999 are conventional difficulty calculation
        consensus.nSubsidyHalvingInterval = 800000; // Adjusted for 80M supply logic approx
        consensus.nMajorityEnforceBlockUpgrade = 1500;
        consensus.nMajorityRejectBlockOutdated = 1900;
        consensus.nMajorityWindow = 2000;
        
        // BIPs not enforced yet for new coin
        consensus.BIP34Height = 1; 
        consensus.BIP34Hash = uint256S("0x0"); // Needs New Genesis Hash
        consensus.BIP65Height = 1; 
        consensus.BIP66Height = 1; 
        
        consensus.powLimit = uint256S("0x00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); 
        consensus.nPowTargetTimespan = 4 * 60 * 60; 
        consensus.nPowTargetSpacing = 60; // 1 minute block time
        consensus.fDigishieldDifficultyCalculation = false;
        consensus.nCoinbaseMaturity = 30;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowAllowDigishieldMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 9576; 
        consensus.nMinerConfirmationWindow = 10080; 
        
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; 
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; 

        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1462060800; 
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800; 

        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1479168000; 
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 0; 

        consensus.nMinimumChainWork = uint256S("0x00"); // Reset for new coin
        consensus.defaultAssumeValid = uint256S("0x00"); // Reset for new coin

        // AuxPoW parameters - ENABLED FOR LITECOIN MINING COMPATIBILITY
        consensus.nAuxpowChainId = 0x0096; // Changed ID to 150 (Unique for AuraXcoin)
        consensus.fStrictChainId = true;
        consensus.fAllowLegacyBlocks = true;
        
        // IMMEDIATE AUXPOW ACTIVATION
        consensus.nHeightEffective = 0;

        digishieldConsensus = consensus;
        digishieldConsensus.nHeightEffective = 20; // Activate Digishield early
        digishieldConsensus.fSimplifiedRewards = true;
        digishieldConsensus.fDigishieldDifficultyCalculation = true;
        digishieldConsensus.nPowTargetTimespan = 60; 
        digishieldConsensus.nCoinbaseMaturity = 30;

        // AuxPoW Activation
        auxpowConsensus = digishieldConsensus;
        auxpowConsensus.nHeightEffective = 1; // Enable Merged Mining from Block 1
        auxpowConsensus.fAllowLegacyBlocks = false;

        pConsensusRoot = &digishieldConsensus;
        digishieldConsensus.pLeft = &consensus;
        digishieldConsensus.pRight = &auxpowConsensus;

        // NEW MAGIC BYTES for AuraXcoin (ARX1)
        pchMessageStart[0] = 0x61; // a
        pchMessageStart[1] = 0x72; // r
        pchMessageStart[2] = 0x78; // x
        pchMessageStart[3] = 0x01; // 1
        
        // NEW PORT
        nDefaultPort = 45557;
        nPruneAfterHeight = 100000;

        // !!!!!!!!!!!!! IMPORTANT !!!!!!!!!!!!!
        // You MUST run a Genesis Block Generator script to get new Nonce and Time.
        // These values below are PLACEHOLDERS. The coin will not start until these are updated.
        // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        
        // nTime, nNonce, nBits, nVersion, Reward (50 COIN)
        // 1. Yahan Nayi Values Daalein (Time: 1733930000, Nonce: 2, Bits: 0x207fffff)
        // 1. Yahan Nayi Values Daalein (Time: 1734000001, Nonce: 2083236895, Bits: 0x207fffff)
genesis = CreateGenesisBlock(1734000001, 2083236895, 0x207fffff, 1, 50 * COIN);

// 2. Hash Set Karein (Ye line theek hai, isko rehne dein)
consensus.hashGenesisBlock = genesis.GetHash();
digishieldConsensus.hashGenesisBlock = consensus.hashGenesisBlock;
auxpowConsensus.hashGenesisBlock = consensus.hashGenesisBlock;

// 3. Naye Hash aur Merkle Root ko Verify Karein
assert(consensus.hashGenesisBlock == uint256S("0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"));
assert(genesis.hashMerkleRoot == uint256S("0x4c01b59a3e0495193bd57e8a3cc3d9be92c0c93139fb9a03755988e31ec7139d"));

        // REPLACE THESE ASSERTS WITH YOUR NEW HASHES AFTER GENERATING GENESIS BLOCK
        // assert(consensus.hashGenesisBlock == uint256S("0x...NEW_HASH..."));
        // assert(genesis.hashMerkleRoot == uint256S("0x...NEW_MERKLE..."));

        vSeeds.clear();
        // vSeeds.push_back(CDNSSeedData("auraxcoin.com", "seed.auraxcoin.com"));

// 1. Yahan Nayi Values Daalein (Time: 1734000001, Nonce: 2083236895, Bits: 0x207fffff)
genesis = CreateGenesisBlock(1734000001, 2083236895, 0x207fffff, 1, 50 * COIN);

// 2. Hash Set Karein (Ye line theek hai, isko rehne dein)
consensus.hashGenesisBlock = genesis.GetHash();
digishieldConsensus.hashGenesisBlock = consensus.hashGenesisBlock;
auxpowConsensus.hashGenesisBlock = consensus.hashGenesisBlock;

// 3. Naye Hash aur Merkle Root ko Verify Karein
assert(consensus.hashGenesisBlock == uint256S("0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"));
assert(genesis.hashMerkleRoot == uint256S("0x4c01b59a3e0495193bd57e8a3cc3d9be92c0c93139fb9a03755988e31ec7139d"));        // Address Prefix 'A' = 23
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 23);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 22);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1, 158);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds.clear();

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        // Cleared old checkpoints
        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            ( 0, consensus.hashGenesisBlock)
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
private:
    Consensus::Params digishieldConsensus;
    Consensus::Params auxpowConsensus;
    Consensus::Params minDifficultyConsensus;
public:
    CTestNetParams() {
        strNetworkID = "test";

        consensus.nHeightEffective = 0;
        consensus.nPowTargetTimespan = 4 * 60 * 60; 
        consensus.fDigishieldDifficultyCalculation = false;
        consensus.nCoinbaseMaturity = 30;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowAllowDigishieldMinDifficultyBlocks = false;
        consensus.nSubsidyHalvingInterval = 100000;
        consensus.nMajorityEnforceBlockUpgrade = 501;
        consensus.nMajorityRejectBlockOutdated = 750;
        consensus.nMajorityWindow = 1000;
        
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1; 
        consensus.BIP66Height = 1; 
        
        consensus.powLimit = uint256S("0x00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); 
        consensus.nPowTargetTimespan = 4 * 60 * 60; 
        consensus.nPowTargetSpacing = 60; 
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 2880; 
        consensus.nMinerConfirmationWindow = 10080; 
        
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; 
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; 

        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1456790400; 
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800; 

        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1462060800; 
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 0; 

        consensus.nMinimumChainWork = uint256S("0x00");
        consensus.defaultAssumeValid = uint256S("0x00");

        // AuxPoW parameters
        consensus.nAuxpowChainId = 0x0096; // Same as mainnet
        consensus.fStrictChainId = false;
        consensus.nHeightEffective = 0;
        consensus.fAllowLegacyBlocks = true;

        digishieldConsensus = consensus;
        digishieldConsensus.nHeightEffective = 50;
        digishieldConsensus.nPowTargetTimespan = 60; 
        digishieldConsensus.fDigishieldDifficultyCalculation = true;
        digishieldConsensus.fSimplifiedRewards = true;
        digishieldConsensus.fPowAllowMinDifficultyBlocks = false;
        digishieldConsensus.nCoinbaseMaturity = 30;

        minDifficultyConsensus = digishieldConsensus;
        minDifficultyConsensus.nHeightEffective = 100;
        minDifficultyConsensus.fPowAllowDigishieldMinDifficultyBlocks = true;
        minDifficultyConsensus.fPowAllowMinDifficultyBlocks = true;

        auxpowConsensus = minDifficultyConsensus;
        auxpowConsensus.nHeightEffective = 150;
        auxpowConsensus.fPowAllowDigishieldMinDifficultyBlocks = true;
        auxpowConsensus.fAllowLegacyBlocks = false;

        pConsensusRoot = &digishieldConsensus;
        digishieldConsensus.pLeft = &consensus;
        digishieldConsensus.pRight = &minDifficultyConsensus;
        minDifficultyConsensus.pRight = &auxpowConsensus;

        // Testnet Magic Bytes
        pchMessageStart[0] = 0xfc;
        pchMessageStart[1] = 0xc1;
        pchMessageStart[2] = 0xb7;
        pchMessageStart[3] = 0xdd; // Changed last byte
        
        nDefaultPort = 45558; // New Testnet Port
        nPruneAfterHeight = 1000;

        // Testnet Genesis Placeholder
        genesis = CreateGenesisBlock(1733800000, 54321, 0x1e0ffff0, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        digishieldConsensus.hashGenesisBlock = consensus.hashGenesisBlock;
        minDifficultyConsensus.hashGenesisBlock = consensus.hashGenesisBlock;
        auxpowConsensus.hashGenesisBlock = consensus.hashGenesisBlock;

        vSeeds.clear();
        vFixedSeeds.clear();

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            ( 0, consensus.hashGenesisBlock)
        };

        chainTxData = ChainTxData{
            0, 0, 0
        };

    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
private:
    Consensus::Params digishieldConsensus;
    Consensus::Params auxpowConsensus;
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.BIP34Height = 100000000; 
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1351; 
        consensus.BIP66Height = 1251; 
        consensus.powLimit = uint256S("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); 
        consensus.nPowTargetTimespan = 4 * 60 * 60; 
        consensus.nPowTargetSpacing = 1; 
        consensus.fDigishieldDifficultyCalculation = false;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 540; 
        consensus.nMinerConfirmationWindow = 720; 
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 999999999999ULL;

        consensus.nMinimumChainWork = uint256S("0x00");
        consensus.defaultAssumeValid = uint256S("0x00");

        consensus.nAuxpowChainId = 0x0096; 
        consensus.fStrictChainId = true;
        consensus.fAllowLegacyBlocks = true;

        consensus.fSimplifiedRewards = true;
        consensus.nCoinbaseMaturity = 60; 

        digishieldConsensus = consensus;
        digishieldConsensus.nHeightEffective = 10;
        digishieldConsensus.nPowTargetTimespan = 1; 
        digishieldConsensus.fDigishieldDifficultyCalculation = true;

        auxpowConsensus = digishieldConsensus;
        auxpowConsensus.fAllowLegacyBlocks = false;
        auxpowConsensus.nHeightEffective = 20;

        digishieldConsensus.pLeft = &consensus;
        digishieldConsensus.pRight = &auxpowConsensus;
        pConsensusRoot = &digishieldConsensus;

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        nDefaultPort = 18445; // New Regtest Port
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1296688602, 2, 0x207fffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        digishieldConsensus.hashGenesisBlock = consensus.hashGenesisBlock;
        auxpowConsensus.hashGenesisBlock = consensus.hashGenesisBlock;

        vFixedSeeds.clear(); 
        vSeeds.clear();      

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
            ( 0, consensus.hashGenesisBlock)
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();
    }

    void UpdateBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

const Consensus::Params *Consensus::Params::GetConsensus(uint32_t nTargetHeight) const {
    if (nTargetHeight < this -> nHeightEffective && this -> pLeft != NULL) {
        return this -> pLeft -> GetConsensus(nTargetHeight);
    } else if (nTargetHeight > this -> nHeightEffective && this -> pRight != NULL) {
        const Consensus::Params *pCandidate = this -> pRight -> GetConsensus(nTargetHeight);
        if (pCandidate->nHeightEffective <= nTargetHeight) {
            return pCandidate;
        }
    }
    return this;
}

CChainParams& Params(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
            return mainParams;
    else if (chain == CBaseChainParams::TESTNET)
            return testNetParams;
    else if (chain == CBaseChainParams::REGTEST)
            return regTestParams;
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

void UpdateRegtestBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    regTestParams.UpdateBIP9Parameters(d, nStartTime, nTimeout);
}

