#ifndef NIZK_H
#define NIZK_H

#include "group.h"

#define NUM_PROOF_CLAUSES  	3
#define NUM_PROOF_TOKENS	11
#define NUM_RAND 8

struct  ProofPack
{
	BIGNUM *gamma[NUM_PROOF_CLAUSES]; // Corresponds to gamma in the paper
	BIGNUM *sToken[NUM_PROOF_TOKENS]; // Corresponds to tokens s in the paper
};
struct ProofData
{
	BIGNUM * vRand[NUM_RAND];
	BIGNUM * wRand[NUM_PROOF_CLAUSES];
	// Group Elements
	GroupElement *cj; // Commitment to jth bit
	GroupElement *Bj; // Bit code for jth bit
	GroupElement *Bj_prev; // Bit code for bit during previous decider round to j
	GroupElement *Yj ; // Y variable for jth round
	GroupElement *Yj_prev; // Y variable for previous decider round to j
	GroupElement *Xj; // Public key for jth round
	GroupElement *Xj_prev; // Public key for previous decider round to j

	// Z_q elements
	BIGNUM * Rj; // Randomness used for commiting to jth bit
	BIGNUM * xj; // Secret key used for encoding jth bit, if it is 0
	BIGNUM * xj_prev; // Secret key used for encoding bit during previous decider round, if it is 0
	BIGNUM * rj; // Secret key used for encoding jth bit, if it is 1
	BIGNUM * rj_prev; // Secret key used for encoding bit during previous decider round, if it is 1
	
};

class NIZKProof
{
public:
	NIZKProof(Group *_grp)
	{
		grp = _grp;
		g = grp->g;
		h = grp->h;
    	// SHA256_Init(&sha256);

    	uint i;
    	for(i = 0; i < NUM_PROOF_TOKENS; i++)
    	{
    		pPack.sToken[i] = BN_new();
    	}
    	for(i = 0; i < NUM_PROOF_CLAUSES; i++)
    	{
    		pPack.gamma[i] = BN_new();
    	}

    	for(i = 0; i < NUM_PROOF_TOKENS; i++)
    	{
    		t[i] = new GroupElement(grp);    
    	}
	}
	~NIZKProof()
	{
		uint i;
    	for(i = 0; i < NUM_PROOF_TOKENS; i++)
    	{
    		BN_free(pPack.sToken[i]); 
    	}
    	for(i = 0; i < NUM_PROOF_CLAUSES; i++)
    	{
    		BN_free(pPack.gamma[i]);
    	}
    	for(i = 0; i < NUM_PROOF_TOKENS; i++)
    	{
    		delete t[i];    
    	}
	}

	void generateNIZKProof(ProofData *pData)
	{
		GroupElement t = GroupElement(grp);
		
		generateNIZKCommitment(pData);

		BIGNUM *chal = BN_new();
		generateRandomChallenge(pData, chal);
		generateNIZKResponse(pData, chal);
		BN_free(chal);

	}
	// The following function generateNIZKCommitment generates the commitment tokens for the NIZK proof.

	void generateNIZKCommitment(ProofData *pData)
	{
		uint i;

		GroupElement e = GroupElement(grp);
		GroupElement f = GroupElement(grp);
		

		
		if(pData->wRand[0]) // for w0
		{
			// Need to perform exponentiation

			grp->power(&e, pData->cj, pData->wRand[0]); // cj^w0
			grp->power(&f, h, pData->vRand[0]); // h^v1
			grp->elementMultiply(t[0], &e, &f); // t0 = cj^w0.h^v0

			grp->power(&e, pData->Bj, pData->wRand[0]); // Bj^w0
			grp->power(&f, pData->Yj, pData->vRand[1]); // Yj^v1
			grp->elementMultiply(t[1], &e, &f); // t1 = Bj^w0.Yj^v1			

			grp->power(&e, pData->Xj, pData->wRand[0]); // Xj^w0
			grp->power(&f, g, pData->vRand[1]); // g^v1
			grp->elementMultiply(t[2], &e, &f); // t2 = Xj^w0.g^v1

		}
		else
		{
			grp->power(t[0], h, pData->vRand[0]); // t0 = cj^0.h^v0
			grp->power(t[1], pData->Yj, pData->vRand[1]); // t1 = Bj^0.Yj^v1
			grp->power(t[2], g, pData->vRand[1]); // t2 = Xj^0.g^v1
		}

		if(pData->wRand[1]) // For w1
		{
			// Need to perform exponentiation

			grp->elementMultiply(&e, pData->cj, gInv); // cj/g
			grp->power(&e, &e, pData->wRand[1]); // (cj/g)^w1
			grp->power(&f, h, pData->vRand[2]); // h^v2
			grp->elementMultiply(t[3], &e, &f); // t3 = (cj/g)^w1.h^v2

			grp->power(&e, pData->Bj_prev, pData->wRand[1]); // Bj_prev^w1
			grp->power(&f, g, pData->vRand[3]); // g^v4
			grp->elementMultiply(t[4], &e, &f); // t4 = Bj_prev^w1.g^v3		

			grp->power(&e, pData->Bj, pData->wRand[1]); // Bj^w1
			grp->power(&f, g, pData->vRand[4]); // g^v4
			grp->elementMultiply(t[5], &e, &f); // t5 = Bj^w1.g^v4

		}
		else
		{
			grp->power(t[3], h, pData->vRand[2]); // t3 = (cj/g)^0.h^v2
			grp->power(t[4], g, pData->vRand[3]); // t4 = Bj_pre^0.g^v3			
			grp->power(t[5], g, pData->vRand[4]); // t5 = Bj^0.g^v4
		}


		if(pData->wRand[2]) // For w2
		{
			// Need to perform exponentiation

			grp->elementMultiply(&e, pData->cj, gInv); // cj/g


			grp->power(&e, &e, pData->wRand[2]); // (cj/g)^w2
			grp->power(&f, h, pData->vRand[5]); // h^v5
			grp->elementMultiply(t[6], &e, &f); // t6 = (cj/g)^w2.h^v5

			grp->power(&e, pData->Bj_prev, pData->wRand[2]); // Bj_prev^w2
			grp->power(&f, pData->Yj_prev, pData->vRand[6]); // Yj_prev^v6
			grp->elementMultiply(t[7], &e, &f); // t7 = Bj_prev^w2.Yj_prev^v6			

			grp->power(&e, pData->Xj_prev, pData->wRand[2]); // Xj_prev^w2
			grp->power(&f, g, pData->vRand[6]); // g^v7
			grp->elementMultiply(t[8], &e, &f); // t8 = Xj_prev^w2.g^v6

			grp->power(&e, pData->Bj, pData->wRand[2]); // Bj^w2
			grp->power(&f, pData->Yj, pData->vRand[7]); // Yj^v7
			grp->elementMultiply(t[9], &e, &f); // t9 = Bj^w2.Yj^v7

			grp->power(&e, pData->Xj, pData->wRand[2]); // Xj^w2
			grp->power(&f, g, pData->vRand[7]); // g^v7
			grp->elementMultiply(t[10], &e, &f); // t10 = Xj^w2.g^v7

		}
		else
		{
			grp->power(t[6], h, pData->vRand[5]); // t6 = (cj/g)^0.h^v5

			grp->power(t[7], pData->Yj_prev, pData->vRand[6]); // t7 = Bj_prev^0.Yj_prev^v6
			grp->power(t[8], g, pData->vRand[6]); // t8 = Xj_prev^0.g^v6

			grp->power(t[9], pData->Yj, pData->vRand[7]); // t9 = Bj^0.Yj^v7
			grp->power(t[10], g, pData->vRand[7]); // t10 = Xj^0.g^v7
		}

	}

	void generateNIZKResponse(ProofData *pData, BIGNUM* chal)
	{
		BIGNUM *tmp = BN_new();
		BIGNUM *u0 = BN_new();
		BIGNUM *u1 = BN_new();
		BIGNUM *u2 = BN_new();
		BIGNUM *u3 = BN_new();
		BIGNUM *u4 = BN_new();
		BIGNUM *u5 = BN_new();
		BIGNUM *u6 = BN_new();
		BIGNUM *u7 = BN_new();
		
		BIGNUM *gamma_k = BN_new();

		BN_CTX *ctx = BN_CTX_new();

		if(pData->wRand[0])
		{
			pPack.gamma[0] = pData->wRand[0]; // gamma0 = w0, since w0 != 0
			

		}
		else
		{
			BN_mod_add(tmp, pData->wRand[1], pData->wRand[2], grp->q, ctx); // tmp = (w1 + w2) mod q
			BN_mod_sub(pPack.gamma[0], chal, tmp, grp->q, ctx); // gamma0 = (chal - tmp) mod q

			BN_copy(u0, pData->rj); // u0 = rj
			BN_copy(u1, pData->xj); // u1 = xj
			BN_zero(u2);
			BN_zero(u3);
			BN_zero(u4);
			BN_zero(u5);
			BN_zero(u6);
			BN_zero(u7);

			BN_copy(gamma_k, pPack.gamma[0]); // k = 0
		}

		if(pData->wRand[1])
		{
			pPack.gamma[1] = pData->wRand[1]; // gamma1 = w1, since w1 != 0
			
		}
		else
		{
			BN_mod_add(tmp, pData->wRand[0], pData->wRand[2], grp->q, ctx); // tmp = (w0 + w2) mod q
			BN_mod_sub(pPack.gamma[1], chal, tmp, grp->q, ctx); // gamma1 = (chal - tmp) mod q

			BN_zero(u0);
			BN_zero(u1);
			BN_copy(u2, pData->Rj); // u2 = Rj
			BN_copy(u3, pData->rj_prev); //u3 = rj_prev
			BN_copy(u4, pData->rj); // u4 = rj
			BN_zero(u5);
			BN_zero(u6);
			BN_zero(u7);

			BN_copy(gamma_k, pPack.gamma[1]); // k = 2
		}

		if(pData->wRand[2])
		{
			pPack.gamma[2] = pData->wRand[2]; // gamma2 = w2, since w2 != 0
		}
		else
		{
			BN_mod_add(tmp, pData->wRand[0], pData->wRand[1], grp->q, ctx); // tmp = (w0 + w1) mod q
			BN_mod_sub(pPack.gamma[2], chal, tmp, grp->q, ctx); // gamma2 = (chal - tmp) mod q
			BN_zero(u0);
			BN_zero(u1);
			BN_zero(u2);
			BN_zero(u3);
			BN_zero(u4);
			BN_copy(u5, pData->Rj); // u5 = Rj
			BN_copy(u6, pData->xj_prev); //u6 = xj_prev
			BN_copy(u7, pData->xj); // u7 = xj

			BN_copy(gamma_k, pPack.gamma[2]); // k = 3

		}

		//printf("q is: \n");
		//BN_print_fp(stdout, grp->q);
		
		BN_mod_mul(tmp, gamma_k, u0, grp->q, ctx); // tmp = (gamma_k . u0) mod q
		BN_mod_sub(pPack.sToken[0], pData->vRand[0], tmp, grp->q, ctx); // s0 = (v0 - tmp) mod q

		BN_mod_mul(tmp, gamma_k, u1, grp->q, ctx); // tmp = (gamma_k . u1) mod q
		BN_mod_sub(pPack.sToken[1], pData->vRand[1], tmp, grp->q, ctx); // s1 = (v1 - tmp) mod q
		BN_copy(pPack.sToken[2], pPack.sToken[1]); // s2 = s1

		BN_mod_mul(tmp, gamma_k, u2, grp->q, ctx); // tmp = (gamma_k . u2) mod q
		BN_mod_sub(pPack.sToken[3], pData->vRand[2], tmp, grp->q, ctx); // s3 = (v2 - tmp) mod q

		BN_mod_mul(tmp, gamma_k, u3, grp->q, ctx); // tmp = (gamma_k . u3) mod q
		BN_mod_sub(pPack.sToken[4], pData->vRand[3], tmp, grp->q, ctx); // s4 = (v3 - tmp) mod q

		BN_mod_mul(tmp, gamma_k, u4, grp->q, ctx); // tmp = (gamma_k . u4) mod q
		BN_mod_sub(pPack.sToken[5], pData->vRand[4], tmp, grp->q, ctx); // s5 = (v4 - tmp) mod q

		BN_mod_mul(tmp, gamma_k, u5, grp->q, ctx); // tmp = (gamma_k . u5) mod q
		BN_mod_sub(pPack.sToken[6], pData->vRand[5], tmp, grp->q, ctx); // s6 = (v5 - tmp) mod q

		BN_mod_mul(tmp, gamma_k, u3, grp->q, ctx); // tmp = (gamma_k . u6) mod q
		BN_mod_sub(pPack.sToken[7], pData->vRand[6], tmp, grp->q, ctx); // s7 = (v3 - tmp) mod q
		BN_copy(pPack.sToken[8], pPack.sToken[7]); // s8 = s7

		BN_mod_mul(tmp, gamma_k, u7, grp->q, ctx); // tmp = (gamma_k . u7) mod q
		BN_mod_sub(pPack.sToken[9], pData->vRand[7], tmp, grp->q, ctx); // s9 = (v7 - tmp) mod q
		BN_copy(pPack.sToken[10], pPack.sToken[9]); // s10 = s9		


		BN_free(tmp);
		BN_CTX_free(ctx);
	}
	void generateRandomChallenge(ProofData *pData, BIGNUM *chal)
	{

		BIGNUM *gx, *gy, *hx, *hy, *tx[NUM_PROOF_TOKENS], *ty[NUM_PROOF_TOKENS], *cx, *cy;
		BIGNUM *Xjx, *Xjy, *Xj_prev_x, *Xj_prev_y, *Yjx, *Yjy, *Yj_prev_x, *Yj_prev_y, *Bjx, *Bjy, *Bj_prev_x, *Bj_prev_y;
		uint i;

		gx = BN_new();
		gy = BN_new();

		hx = BN_new();
		hy = BN_new();

		cx = BN_new();
		cy = BN_new();

		Xjx = BN_new();
		Xjy = BN_new();

		Xj_prev_x = BN_new();
		Xj_prev_y = BN_new();

		Yjx = BN_new();
		Yjy = BN_new();

		Yj_prev_x = BN_new();
		Yj_prev_y = BN_new();

		Bjx = BN_new();
		Bjy = BN_new();

		Bj_prev_x = BN_new();
		Bj_prev_y = BN_new();

		for(i = 0; i < NUM_PROOF_TOKENS; i++)
		{
			tx[i] = BN_new();
			ty[i] = BN_new();
		}


		EC_POINT_get_affine_coordinates(grp->ecg, g->ep, gx, gy, NULL);
		EC_POINT_get_affine_coordinates(grp->ecg, h->ep, hx, hy, NULL);
		EC_POINT_get_affine_coordinates(grp->ecg, pData->cj->ep, cx, cy, NULL);

		
		EC_POINT_get_affine_coordinates(grp->ecg, pData->Xj->ep, Xjx, Xjy, NULL);
		EC_POINT_get_affine_coordinates(grp->ecg, pData->Xj_prev->ep, Xj_prev_x, Xj_prev_y, NULL);
		EC_POINT_get_affine_coordinates(grp->ecg, pData->Yj->ep, Yjx, Yjy, NULL);

		EC_POINT_get_affine_coordinates(grp->ecg, pData->Yj_prev->ep, Yj_prev_x, Yj_prev_y, NULL);
		EC_POINT_get_affine_coordinates(grp->ecg, pData->Bj->ep, Bjx, Bjy, NULL);
		EC_POINT_get_affine_coordinates(grp->ecg, pData->Bj_prev->ep, Bj_prev_x, Bj_prev_y, NULL);


		for(i = 0; i < NUM_PROOF_TOKENS; i++)
		{
			EC_POINT_get_affine_coordinates(grp->ecg, t[i]->ep, tx[i], ty[i], NULL);
		}

		unsigned char hash[SHA256_DIGEST_LENGTH];
		
		// Concatenate the inputs

		uint msglen = BN_num_bytes(gx) + BN_num_bytes(gy) +
					  BN_num_bytes(hx) + BN_num_bytes(hy) +
					  BN_num_bytes(cx) + BN_num_bytes(cy) +
  					  BN_num_bytes(Xjx) + BN_num_bytes(Xjy) + 
  					  BN_num_bytes(Xj_prev_x) + BN_num_bytes(Xj_prev_y) + 
  					  BN_num_bytes(Yjx) + BN_num_bytes(Yjy) + 
  					  BN_num_bytes(Yj_prev_x) + BN_num_bytes(Yj_prev_y) + 
  					  BN_num_bytes(Bjx) + BN_num_bytes(Bjy) + 
  					  BN_num_bytes(Bj_prev_x) + BN_num_bytes(Bj_prev_y)  ;

  		for(i = 0; i < NUM_PROOF_TOKENS; i++)
		{
			msglen = msglen + BN_num_bytes(tx[i]) + BN_num_bytes(ty[i]);
		}

		
		unsigned char *buffer= new unsigned char[msglen];

		uint size = 0, n = 0;

		n = BN_bn2bin(gx, buffer);
		size = size + n;
		n = BN_bn2bin(gy, &buffer[size]);
		size = size + n;
		
		n = BN_bn2bin(hx, buffer);
		size = size + n;
		n = BN_bn2bin(hy, &buffer[size]);
		size = size + n;
		
		n = BN_bn2bin(cx, &buffer[size]);
		size = size + n;
		n = BN_bn2bin(cy, &buffer[size]);
		size = size + n;

		n = BN_bn2bin(Xjx, &buffer[size]);
		size = size + n;
		n = BN_bn2bin(Xjy, &buffer[size]);
		size = size + n;

		n = BN_bn2bin(Xj_prev_x, &buffer[size]);
		size = size + n;
		n = BN_bn2bin(Xj_prev_y, &buffer[size]);
		size = size + n;

		n = BN_bn2bin(Yjx, &buffer[size]);
		size = size + n;
		n = BN_bn2bin(Yjy, &buffer[size]);
		size = size + n;

		n = BN_bn2bin(Yj_prev_x, &buffer[size]);
		size = size + n;
		n = BN_bn2bin(Yj_prev_y, &buffer[size]);
		size = size + n;

		n = BN_bn2bin(Bjx, &buffer[size]);
		size = size + n;
		n = BN_bn2bin(Bjy, &buffer[size]);
		size = size + n;

		n = BN_bn2bin(Bj_prev_x, &buffer[size]);
		size = size + n;
		n = BN_bn2bin(Bj_prev_y, &buffer[size]);
		size = size + n;

		for(i = 0; i < NUM_PROOF_TOKENS; i++)
		{
			n = BN_bn2bin(tx[i], &buffer[size]);
			size = size + n;
			n = BN_bn2bin(ty[i], &buffer[size]);
			size = size + n;
		}
		
		//printf("The content of buffer is:\n");
		for(uint k = 0; k < size; k++)
		{
			//printf("%d\t",buffer[k]);
		}
		cout << endl;
		
		// Call the Hash function
		SHA256(buffer, size, hash);
		
		
		// Convert into BIGNUM
		for(uint k = 0; k < SHA256_DIGEST_LENGTH; k++)
		{
		//	printf("%0X\t",hash[k]);
		}
		cout << endl;
    	BN_bin2bn(hash,SHA256_DIGEST_LENGTH,chal);
    	cout << "Hash = ";
    	BN_print_fp(stdout, chal);
    	cout << endl;	

    	delete buffer;


    	BN_free(gx);
    	BN_free(gy);
    	BN_free(hx);
    	BN_free(hy);
    	BN_free(cx);
    	BN_free(cy);
    	BN_free(Xjx);
    	BN_free(Xjy);
    	BN_free(Xj_prev_x);
    	BN_free(Xj_prev_y);
    	BN_free(Yjx);
    	BN_free(Yjy);
    	BN_free(Yj_prev_x);
    	BN_free(Yj_prev_y);
    	BN_free(Bjx);
    	BN_free(Bjy);
    	BN_free(Bj_prev_x);
    	BN_free(Bj_prev_y);

    	for(i = 0; i < NUM_PROOF_TOKENS; i++)
		{
			BN_free(tx[i]);
			BN_free(ty[i]);
		}
    }
	uint verifyNIZKProof(ProofPack *p, GroupElement *c)
	{
	
		BIGNUM *hash = BN_new();

		return 1;

	}
	void printNIZKProof(ProofPack *p)
	{
		printf("\nThe NIZK Proof generated is:\n");

		cout << endl;
	}

private: 
	NIZKProof(){}
   	ProofPack pPack;

	GroupElement *g;
	GroupElement *gInv;
	GroupElement *h;
	Group *grp;
	GroupElement *T;
	GroupElement *t[NUM_PROOF_TOKENS];

};
#endif