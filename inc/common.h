/* This file defines all the constants that are used by the protocol and also defines the structure for bulletin board.
*/
#ifndef COMMON_H
#define COMMON_H

#include <bits/stdc++.h>
#include <linux/mman.h>
#include <boost/interprocess/shared_memory_object.hpp>
#include <boost/interprocess/mapped_region.hpp>
#include <cstdint>
#include <openssl/sha.h>
#include "group.h"



using namespace std;
using namespace boost::interprocess;



typedef unsigned int uint;

// Change the following for varying the number of bidders and length of bit string.
// Note that this change recompiles all files.

#define MAX_BIT_LENGTH 4
#define MAX_BIDDERS 2


#define D 1000
#define ADDR_Verify 999

typedef bool bit_t;


typedef struct publicParam
{
	zqPoint q; // Order of the group Z_q
	GrpPoint g; // Generator of the group G
	GrpPoint h; // Group element to be used in Commitments
	uint l; // Number of bits used in binary representation
}PParam;

struct  KnowledgeProof
{
	zqPoint pz1;
	zqPoint pz2;
	zqPoint pch;
};

typedef enum ProtocolStage
{
	setupStage = 1,
	computeStage,
	verifyStage,
	outputStage

}PStage;

typedef enum ProcessTypes
{
	pEvaluator = 0,
	pBidder,
	pVerifier
} PType;

struct BBMemoryBidder
{
	GrpPoint commitment;
	GrpPoint pubKey[MAX_BIT_LENGTH];
	
	// OT Parameters
	GrpPoint msgEnc_0[MAX_BIT_LENGTH];
	GrpPoint msgEnc_1[MAX_BIT_LENGTH];
	GrpPoint eta[MAX_BIT_LENGTH];
	GrpPoint G[MAX_BIT_LENGTH];
	GrpPoint H[MAX_BIT_LENGTH];
	GrpPoint zeta[MAX_BIT_LENGTH];
	GrpPoint z[MAX_BIT_LENGTH];
	GrpPoint T;
	GrpPoint bitCode[MAX_BIT_LENGTH];
	bool bidBits[MAX_BIT_LENGTH];
};

struct BulletinBoard
{
	struct BBMemoryBidder bidderBB[MAX_BIDDERS];
	uint OTParamsUpdated[MAX_BIDDERS][MAX_BIT_LENGTH];
	uint bidderUpdatedRound[MAX_BIDDERS];
	bool sentBitCodes[MAX_BIDDERS][MAX_BIT_LENGTH];
	bool setupStageDone[MAX_BIDDERS];
	bool computeStageDone[MAX_BIDDERS];
	bool verifyStageDone[MAX_BIDDERS];

	bool computeBit[MAX_BIDDERS][MAX_BIT_LENGTH]; // All bidders
	bool winBit[MAX_BIT_LENGTH];
	uint winningBid;
	zqPoint bidderWinProof[MAX_BIDDERS];
	KnowledgeProof kProof[MAX_BIDDERS];
	zqPoint evalWinProof[MAX_BIT_LENGTH];
	GrpPoint proofOfComputation[MAX_BIDDERS][MAX_BIT_LENGTH];
	int winnerClaim;
	zqPoint bidderKeyHash[MAX_BIDDERS];
	zqPoint xWinner[MAX_BIT_LENGTH]; // Winner's private key for 0 bit code.
	zqPoint rWinner[MAX_BIT_LENGTH]; // Winner's private key for 1 bit code.

// Winner's OT 2nd msg randomness.
	zqPoint sWinner[MAX_BIT_LENGTH]; 
	zqPoint tWinner[MAX_BIT_LENGTH]; 

};

struct shm_remove
{
    shm_remove() { shared_memory_object::remove("Bulletin Board"); }
    ~shm_remove(){ shared_memory_object::remove("Bulletin Board"); }
};

#endif
