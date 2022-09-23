#ifndef BIDDER_H
#define BIDDER_H
#include "common.h"
#include "group.h"
#include "commit.h"
#include "encoder.h"
#include "otengine.h"
#include <semaphore.h>


class Bidder
{
public:
	uint addr_sc; // Address of the Smart Token to reach out
	uint deposit; // Security deposit
	PParam pp; //Public Parameters
	uint id; 
	BulletinBoard* bb;
	uint currentRound;
	bool auctionLost;
	void printBidBits()
	{
		printf("Bits of the bid %X for bidder %d are: ",bidval, id);
		
		for(uint j = 0; j < MAX_BIT_LENGTH; j++)
		{
			printf("%i\t", bitsOfBid[j] );
		}
		cout << endl;
	}
	Bidder(){}

	Bidder(uint v, uint b, uint d, uint addr, uint _id, BulletinBoard* _bb)
	{

		grp = new Group(NID_secp256k1);
		enc = new Encoder(grp);
		commitObj = new commitment(grp); 
		
		bidCommit = new GroupElement(grp);
	
		value = v;
		bidval = b;
		deposit = d;
		addr_sc = addr;
		id = _id;
		uint mask = 1;
		bb = static_cast<struct BulletinBoard *>(_bb);
		auctionLost = false;
		currentRound = 0; // The round 0 is invalid value. Valid range for rounds is [1,...,l]

		


		if(id != 0) // Not the evaluator
		{
			bidderBB = static_cast<struct BBMemoryBidder *>(&bb->bidderBB[id]);
			uint n = b;
			for(uint j = 0; j < MAX_BIT_LENGTH; j++)
			{
        		bitsOfBid[MAX_BIT_LENGTH-1-j] = static_cast<bool>(n % 2);
        		n = n / 2;      
			}	
			GroupElement e = GroupElement(grp);
			GroupElement f = GroupElement(grp);
			for(uint j = 0; j < MAX_BIT_LENGTH; j++)
			{
				s[j] = grp->getRandomNumber();
				t[j] = grp->getRandomNumber();
				grp->power(&e, grp->g, s[j]);
				grp->power(&f, grp->h, t[j]);
				grp->elementMultiply(&e,&e,&f);
				bidderBB->z[j] = e.gpt;
			}

		}
		for(uint k = 0; k < MAX_BIT_LENGTH; k++)
		{
			bitcode[k] = new GroupElement(grp);	

		}

		char name[16];

		sprintf(name, "bidderThr-%d",id); // Each semaphore has a name of the form "bidder-<id>". E.g.: Bidder 12 has name "bidder-12"

		bidder_thr_sem = sem_open(name, O_CREAT, 0777, MAX_BIDDERS-1);
		if(bidder_thr_sem == SEM_FAILED)
    	{
        	perror("bidder_thr_sem: Semaphore creation failed");
    	}
    	sprintf(name, "bidderSyn-%d",id); // Each semaphore has a name of the form "bidder-<id>". E.g.: Bidder 12 has name "bidder-12"

		bidder_sync_sem = sem_open(name, O_CREAT, 0777, 0);
		if(bidder_sync_sem == SEM_FAILED)
    	{
        	perror("bidder_sync_sem: Semaphore creation failed");
    	}

		comp_stg_sem = sem_open("sem_comp_stg", O_CREAT, 0777, 0);
		if(comp_stg_sem == SEM_FAILED)
    	{
        	perror("sem_comp_stg: Semaphore creation failed");
    	}

	}
	~Bidder()
	{
		for(uint j = 0; j < MAX_BIT_LENGTH; j++)
		{
			BN_free(s[j]);
			BN_free(t[j]);
			
			delete bitcode[j];	
		}	
		delete bidCommit;
		delete grp;	

		sem_close(bidder_thr_sem);
		sem_close(comp_stg_sem);
		sem_close(bidder_sync_sem);

	}

	void printBuffer(unsigned char *buffer, uint n);

	// Following functions need to be reimplemented for inherited classes.
	virtual PStage protocolSetupStage();	
	virtual PStage protocolComputeStageBidder();
	virtual void protocolVerificationStage();
	


	PStage currentState;

	uint utility()
	{
		return value - bidval;
	}
	bool getABPbit(uint j)
	{
		bool b;
		
		if(auctionLost)
			b = false;
		else
		 	b= bitsOfBid[j];
		return b;
	}

	uint bidval;

	bool bitsOfBid[MAX_BIT_LENGTH];

	uint value;
	Group *grp; // The Group on which all crypto primitives are based
	BBMemoryBidder *bidderBB; // Pointer to the bulletin board where bidder can write its artefacts
	BBMemoryEval *evalBB; // Pointer to the bulletin board where evaluator writes its artefacts
	Encoder *enc;

	// Pedersen Commitment
	commitment *commitObj; // Class containaing commitment methods
	GroupElement *bidCommit; // GroupElement that acts as the commitment to a bid value
	BIGNUM *rcommit;  // Randomness used in commitment
	BIGNUM *bid; // Bid value represented as BIGNUM

	BIGNUM* x[MAX_BIT_LENGTH]; // Private key for computing the 0-bit code
	BIGNUM* r[MAX_BIT_LENGTH]; // Private key for computing the 1-bit code

	unsigned char keyHash[SHA256_DIGEST_LENGTH]; // Hash of the private keys

	BIGNUM* s[MAX_BIT_LENGTH]; // Randomness used during OT 2nd message
	BIGNUM* t[MAX_BIT_LENGTH]; // Randomness used during OT 2nd message

	GroupElement *bitcode[MAX_BIT_LENGTH]; // Bit codes used during the computation stage
	sem_t *bidder_thr_sem; // Semaphore held by the bidder
	sem_t *comp_stg_sem; // Semaphore used during the computation stage
	sem_t *bidder_sync_sem; // Semaphore used by bidder for general sync with Eval
};

class Eval: public Bidder
{
public:
	Eval(){}
	Eval(uint v, uint b, uint d, uint addr, uint _id, BulletinBoard* _bb) 
		:Bidder( v,  b,  d,  addr,  _id, _bb)
	{

		uint mask = 1;

		auctionLost = false;
		currentRound = 0; // The round 0 is invalid value. Valid range for rounds is [1,...,l]

		evalBB  = static_cast<struct BBMemoryEval *>(&bb->evalBB);


		uint n = b;
		for(uint j = 0; j < MAX_BIT_LENGTH; j++)
		{
			    	    
 		 // storing remainder in binary array
        	bitsOfBid[MAX_BIT_LENGTH-1-j] = static_cast<bool>(n % 2);
        	n = n / 2;    	
		}	
#ifdef COMMENT
		// Allocate OT parameters and write them on to BB
    	BIGNUM *num;
    	GroupElement e  = GroupElement(grp);  
		GroupElement f  = GroupElement(grp);  

		T1 = new GroupElement(grp);
		num = grp->getRandomNumber() ;
		grp->power(T1, grp->g, num);
		evalBB->T1 = T1->gpt;

		// Pre-allocate the OT first messages for both 0 and 1. Use bit specific messages during computation
		for(uint i = 0; i < MAX_BIDDERS+1; i++)
		{
			for(uint j = 0; j < MAX_BIT_LENGTH; j++)
			{
				beta[i][j] = grp->getRandomNumber();
				invbeta[i][j] = BN_new();
				BN_sub(invbeta[i][j],grp->q,beta[i][j]);

				num = grp->getRandomNumber() ;
            	grp->power(&f, grp->g, num);

            	evalBB->T2[i][j] = f.gpt; // Write T2 values to BB
				
				grp->power(&e,grp->g, beta[i][j]); // G0 = g^beta
				G0[i][j] = e.gpt;

				grp->elementMultiply(&e, &e, T1); // G1 = g^beta.T1
				G1[i][j] = e.gpt;
				
				grp->power(&e,grp->h, beta[i][j]); // H0 = h^beta
				H0[i][j] = e.gpt;

				grp->elementMultiply(&e, &e, &f); // H1 = h^beta.T2
				H1[i][j] = e.gpt;
			}
			
		}
		for(uint i = 0; i < MAX_BIDDERS; i++)
		{
			bidderBitcode[i] = new GroupElement(grp);			
		}		
		for(uint j = 0; j < MAX_BIT_LENGTH; j++)
		{
			delta[j] = BN_new();
		}
		// Following is dummy OT second message values - required only for commitment
		for(uint j = 0; j < MAX_BIT_LENGTH; j++)
		{
			s[j] = grp->getRandomNumber();
			t[j] = grp->getRandomNumber();
		}

#endif //COMMENT
	}

	~Eval()
	{
		for(uint i = 0; i < MAX_BIDDERS+1; i++)
		{
			for(uint j = 0; j < MAX_BIT_LENGTH; j++)
			{
				BN_free(beta[i][j]);
				BN_free(invbeta[i][j]);

			}
			sem_close(&eval_init_sem[i]);

			sem_close(&eval_thr_sem[i]);
			sem_close(eval_sync_sem[i]);
		}
		for(uint j = 0; j < MAX_BIT_LENGTH; j++)
		{
			BN_free(delta[j]);
		}
		
	}
	void printEvalParams()
	{
		for(uint i = 0; i < MAX_BIDDERS+1; i++)
		{
			for(uint j = 0; j < MAX_BIT_LENGTH; j++)
			{
				printf("\nalpha[%d][%d]:\n",i,j);
				BN_print_fp(stdout,beta[i][j]);
				printf("\ninvalpha[%d][%d]:\n",i,j);
				BN_print_fp(stdout,invbeta[i][j]);
			}
		}
		cout << endl;
	}
	void initEval();

	virtual PStage protocolSetupStage();	

	virtual PStage protocolComputeStageEval();
	virtual void protocolVerificationStage();

	void announceWinner();
	bool verifyWinnerClaim();

	uint  exp(int a, int n) 
	{ 
		uint e = 1;
		for(uint i =1; i <=n; i++)
		{
			e = e * a;
		}
		return e;
	}


	GroupElement* bidderBitcode[MAX_BIDDERS];

	struct BBMemoryEval *evalBB ;
	BIGNUM * beta[MAX_BIDDERS+1][MAX_BIT_LENGTH];          // OT first message randomness
	BIGNUM * invbeta[MAX_BIDDERS+1][MAX_BIT_LENGTH];       // Inverse value - used during message retrieval
	BIGNUM * delta[MAX_BIT_LENGTH];							// Used for proof of computation

	// OT first message parameters
	GrpPoint G0[MAX_BIDDERS+1][MAX_BIT_LENGTH];
	GrpPoint H0[MAX_BIDDERS+1][MAX_BIT_LENGTH];
	GrpPoint G1[MAX_BIDDERS+1][MAX_BIT_LENGTH];
	GrpPoint H1[MAX_BIDDERS+1][MAX_BIT_LENGTH];
	GroupElement *T1;			

	// Bits used during computation by Evaluator					
	uint evalComputeBit[MAX_BIT_LENGTH];
	sem_t eval_thr_sem[MAX_BIDDERS+1];
	sem_t eval_init_sem[MAX_BIDDERS+1];
	sem_t *eval_sync_sem[MAX_BIDDERS+1];

};



#endif
