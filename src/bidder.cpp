#include <iostream>
#include <cstdlib>
#include <pthread.h>

// include<emp-tool/emp-tool.h> 
// #include<emp-ot/emp-ot.h>    for OTs

#include "common.h"
#include "bidder.h"

/* This procedure implements the setup stage of the protocol. It proceeds as follows:
 * Bidder registers for the auction by sending the security deposit D.
 * After obtaining the public parameters, bidder initializes its internal parameters.
 * Generates the commitment for its private bid value.
 * Selects private keys for the auction rounds.
 * Generates corresponding public keys. 
 * Write commitments and public keys on to the bulletin board.
*/
PStage Bidder::protocolSetupStage()
{
	//cout << "Inside bidder SetupStage" << endl;
    //printf("Bid value for bidder %d is %X\n", id, bidval);
    

    bid = BN_new();
    BN_set_word(bid, bidval);
    //printf("The bid value is:\n");
    //BN_print_fp(stdout, bid);
    //cout << endl;
#ifdef DEBUG    
    printBidBits();
#endif

    BN_set_word(bid, bidval);
    

    GroupElement e = GroupElement(grp);

    // Generate Public/Private keys for each round
    for(int j = 0; j < MAX_BIT_LENGTH; j++)
    {

        
        x[j] = grp->getRandomNumber() ;
        r[j] = grp->getRandomNumber() ;
        grp->power(&e, grp->g, x[j]); //pubKey = g^x

        bidderBB->pubKey[j] = e.gpt; // Write public keys to BB
        
        // printf("Bidder public key [%d][%d]:\n",id,j);
        // e.printGroupPoint(&bidderBB->common.pubKey[j]);
        // printf("Bidder private key [%d]:\n",j);
        // BN_print_fp(stdout, x[j]);
        // cout << endl;    
    }

    initBidder();

    
    
    bb->setupStageDone[id] = true;

    
    for(uint i = 0; i < MAX_BIDDERS; i++)
    {
        while(!bb->setupStageDone[i]) 
            usleep(1);    
    }
    
	return computeStage;
 
}


struct thread_data
{
    uint id; // Bidder who owns the threads
    uint i; // Bidder id
    uint j; // auction round
    bool bit; // Bit being encoded
    Bidder *bidder; // Pointer to Bidder class.
};

// The following function initializes the Bidder object
void Bidder::initBidder()
{

    auto ststart = std::chrono::high_resolution_clock::now();
    
    // Allocate OT parameters and write them on to BB
    BIGNUM *num;
    GroupElement e  = GroupElement(grp);  
    GroupElement f  = GroupElement(grp);  


    int rc = 0;

    for(uint i = 0; i < MAX_BIDDERS; i++)
    {

        for(uint j = 0; j < MAX_BIT_LENGTH; j ++)
        {
            beta[j] = grp->getRandomNumber();
            invbeta[j] = BN_new();
            BN_sub(invbeta[j],grp->q,beta[j]);

            num = grp->getRandomNumber() ;
            auto pstart = std::chrono::high_resolution_clock::now();

            grp->power(&f, grp->g, num); // Choose random num from Z_q and raise g^num to get zeta.

            bidderBB->zeta[j] = f.gpt; // Write zeta values to BB
                
            grp->power(&e,grp->g, beta[j]); // G0 = g^beta
            G0[j] = e.gpt;


            grp->elementMultiply(&e, &e, &f); // G1 = G0.zeta = g^beta.zeta
            G1[j] = e.gpt;
                
            grp->power(&e,grp->h, beta[j]); // H0 = h^beta
            H0[j] = e.gpt;

            grp->elementMultiply(&e, &e, grp->T1); // H1 = H0.T1 = h^beta.T1
            H1[j] = e.gpt;

        }
    
    }
    

    for(uint i = 0; i < MAX_BIDDERS; i++)
    {
        bidderBitcode[i] = new GroupElement(grp);           
    }       
}



void * OTUpdate(void *input)
{
    struct thread_data *td = (struct thread_data *) input;
    uint id = td->id;
    uint i = td->i;
    uint j = td->j;

    Bidder *bidder = (Bidder *)td->bidder;

    //cout << "Inside thread " << i<< " for bidder " << id << " j = " << j << endl;
    //bidder->grp->printGroupElement(bidder->grp->g);
    //bidder->grp->power(&e,bidder->grp->g, bidder->beta[i][j]);
    //BN_print_fp(stdout, bidder->beta[i][j]);
    //cout << endl;

    if(td->bit == 0) // OT params for choice bit = 0
    {
        bidder->bidderBB[id].G[j] = bidder->G0[j] ; 

        bidder->bidderBB[id].H[j] = bidder->H0[j] ; 

    }
    else if(td->bit == 1) // OT params for choice bit = 1
    {
        bidder->bidderBB[id].G[j] = bidder->G1[j] ;    
        bidder->bidderBB[id].H[j] = bidder->H1[j] ; 
    }
    GroupElement *e  = new GroupElement(bidder->grp, &bidder->bidderBB[id].G[j]);   
    GroupElement *f  = new GroupElement(bidder->grp, &bidder->bidderBB[id].H[j]);   

#ifdef DEBUG
    printf("Values of G and H %d,%d are:\n", i,j);
    bidder->grp->printGroupElement(e);
    bidder->grp->printGroupElement(f);
#endif    

    bidder->bb->OTParamsUpdated[id][j] = true;   

    BBMemoryBidder *bidderBB = static_cast<struct BBMemoryBidder *>(&bidder->bb->bidderBB[i]);

// Now wait for individual bidders to get back     

    //printf("Inside thread %d\n",i);

    char name[16];
    sprintf(name, "bidderSyn-%d",i); // Each semaphore has a name of the form "bidder-<id>". E.g.: Bidder 12 has name "bidder-12"


    sem_t *sem = sem_open(name, O_CREAT, 0777, 0);
    if(sem == SEM_FAILED)
    {
        perror("sem: Semaphore creation failed");
    }
    //sem_wait(sem); // Wait to hear back from bidder i

    int sval = 0;
    sem_getvalue(sem, &sval);
    //printf("Value of sync semaphore %d is %d\n", i, sval);
    
    // while(bidder->bb->bidderUpdatedRound[i] != j+1)


    sem_post(&bidder->eval_thr_sem[i]); // Increment the counting semaphore

    pthread_exit(NULL);    
}


/* This procedure implements the computation stage of the protocol - for the bidder.
 * The bidder computes the ABP bit.
 * Uses BES to enode the bit to generate the bit code.
 * Generates the OT encryption for the bit, using the randomness shared by Eval.
 * Writes the encrypted messages for msg-0 and msg-1 of OT to the BB
 *  
*/
PStage Bidder::protocolComputeStageBidder()
{
	//cout << "Inside ComputeStageBidder" << endl;
    bool computeBit, testBit, highestBidder = false ;
    int rc;

    for(uint j = 0; j < MAX_BIT_LENGTH; j++)
    {    
        pthread_t threads[MAX_BIDDERS];
        struct thread_data td[MAX_BIDDERS];
                
        GroupElement e  = GroupElement(grp);   
        GroupElement f  = GroupElement(grp);

#ifdef THREADS        
        for(uint i = 0; i < MAX_BIDDERS; i++)
        {
            
            if (i == id)
                continue; // No need to create a OT thread for itself.

            sem_init(&eval_thr_sem[i], 0, 1);

            // sem_wait(&eval_thr_sem[i]); // Wait for semaphore

            td[i].id = id;
            td[i].i = i;
            td[i].j = j;
            td[i].bit = evalComputeBit[j] ;
            td[i].bidder = this;
            rc = pthread_create(&threads[i], NULL, &OTUpdate, (void *)&td[i]);
            if(rc)
            {
                cout << "Error in creating threads for OTUpdate" << rc << endl;
            }

        }     
#endif // THREADS        

        if(highestBidder) 
            computeBit = true; // Highest bidder sends only 1-bit codes through OT
        else
            computeBit = getABPbit(j);

        if (computeBit)
        {
            enc->oneBitEncode(bitcode[j], r[j]);
            
            //enc->zeroBitEncode(&zeroBitCode,x[j],id,j, bb); 

            // printf("Constructed onebitcode[%d][%d] is :\n",id,j);            
        }
        else 
        {
            enc->zeroBitEncode(bitcode[j],x[j],id,j, bb); 
            //enc->zeroBitEncode(&zeroBitCode,x[j],id,j, bb); 
            // printf("Constructed zerobitcode[%d][%d] is :\n",id,j);
        }

        // grp->printGroupElement(bitcode[j]);

        if(computeBit == 0) // OT params for choice bit = 0
        {
            bidderBB->G[j] = G0[j] ; 

            bidderBB->H[j] = H0[j] ; 

        }
        else if(computeBit == 1) // OT params for choice bit = 1
        {
            bidderBB->G[j] = G1[j] ;    
            bidderBB->H[j] = H1[j] ; 
        }
        bb->OTParamsUpdated[id][j] = true;   

// Run OT to send  the bit code to other bidders
        for(uint i = 0; i < MAX_BIDDERS; i++)
        {
            if(i == id)
                continue; // Ignore self

            while(bb->OTParamsUpdated[i][j] != true) // Wait for Bidder i to update the OT parameters.
                usleep(100);

            // Retrieve the OT parameters for bidder[i] (to whom bidder[id] needs to send): zeta, G, H

            GroupElement zeta_i = GroupElement(grp, &bb->bidderBB[i].zeta[j]);
            grp->getInverse(&zeta_i); // We are not going to use zeta; Only its inverse is useful

            GroupElement G_ij = GroupElement(grp, &bb->bidderBB[i].G[j]);
            GroupElement H_ij = GroupElement(grp, &bb->bidderBB[i].H[j]);

            // The encoding for M_1 is: C_1 = (G/zeta)^s . (H/T1)^t . B_ij

            // printf("Used G and H are:\n");
            // grp->printGroupElement(&G);
            // grp->printGroupElement(&H);
        
            grp->elementMultiply(&e, &G_ij, &zeta_i); // Perform (G/zeta)
            grp->elementMultiply(&f, &H_ij, grp->invT1); // Perform (H/T1)

            // s and t values are that of sender, bidder[id]

            grp->power(&e, &e, s[j]); // Perform (G/zeta)^s
            grp->power(&f, &f, t[j]); // Perform (H/T1)^t 

            grp->elementMultiply(&e, &e, &f);
            grp->elementMultiply(&e, &e, bitcode[j]);

            bb->bidderBB[i].OTPostBox[id][j] = e.gpt; // Post the OT message to Bidder_i's postbox, at the entry (id,j)

        //   printf("C1[%d][%d] point written is:\n", id, j);
        //   e.printGroupPoint(&bb->bidderBB[i].OTPostBox[id][j]);

        //   printf("Bidder's z[%d][%d] is : \n",id, j);
        //   e.printGroupPoint(&bidderBB->z[j]); 
        
        }    

        bb->sentBitCodes[id][j] = true;

        
        if(computeBit) // If computeBit is 1, receive bit codes from all other parties
        {
            // Having sent the j'th bit code to all other bidders, receive the bit codes from other bidders
            //printf("Bidder %d is contributing a 1 bit in round %d. So need to check what others have.\n",id,j);
            for(uint i = 0; i < MAX_BIDDERS; i++)
            {
                if(i == id)
                {
                    //grp->dupGroupElement(bidderBitcode[i],&zeroBitCode);
                    enc->zeroBitEncode(bidderBitcode[i],x[j],id,j, bb); // Copy own zero bit for this round code to i'th position where i = id
                    //bidderBitcode[i]->gpt = zeroBitCode.gpt; 
                    continue; // Ignore self
                }
                //printf("Bidder %d is waiting for bidder %d to send bit code in round %d\n",id, i,j);

                while(bb->sentBitCodes[i][j] == false)
                    usleep(100); // Wait for all other bidders to send their bit codes    

                GroupElement C1 = GroupElement(grp, &bidderBB->OTPostBox[i][j]); // Retrieve the message C1 sent by bidder[i] for round j

                GroupElement z  = GroupElement(grp, &bb->bidderBB[i].z[j]); // Retrive the value of z for this round for bidder[i]

                // printf("Bidder[%d]: Retrieved z[%d][%d] is :\n",id,i,j);
                // grp->printGroupElement(&z);
                //printf("Rx: beta, invbeta[%d][%d] are:\n", i,j);
                //BN_print_fp(stdout, beta[j]);
                //cout << endl;
                //BN_print_fp(stdout, invbeta[j]);
                //cout << endl;

                GroupElement a  = GroupElement(grp);
                grp->power(&a,&z,invbeta[j]);

                grp->elementMultiply(bidderBitcode[i],&C1,&a);
                // printf("The received bit code[%d][%d] is:\n",i,j);

                // grp->printGroupElement(bidderBitcode[i]);

            }    
            // Compute the winning bit by setting own bit code to 0.
            // If the winning bit is 1, that means, some other party is also contributing a 1 bit code in this round
            // Else if winning bit is 0, that means, the party is indeed the winner
            
            testBit = enc->decodeBitcode(j, this); 
            //printf("testBit computed by %d in round %d is %d\n", id, j, testBit);
            if((testBit == false) && (highestBidder == false) && (computeBit == true))
            {
                //printf("Bidder %d is the highest bidder\n", id);
                highestBidder = true;
            }
        }

        if(highestBidder) 
        {
            // Write the same bitcode to BB as that of second highest bidder - i.e. bit code for testBit
            if(testBit)
            {
                printf("Winner is writing 1 in round %d\n",j);
                enc->oneBitEncode(bitcode[j], r[j]);
            }
            else
            {
                printf("Winner is writing 0 in round %d\n",j);
                enc->zeroBitEncode(bitcode[j],x[j],id,j, bb); 

            }
        }


        // Write the bit code to BB
        bb->bidderBB[id].bitCode[j] = bitcode[j]->gpt;
        //printf("Bidder %d: Written Bit code[%d][%d] is:\n",id, id,j);
        //grp->printGroupElement(bitcode[j]);
        


        bb->updatedBB[id][j] = true;

        //printf("Bidder %d has updated updatedBB flag in round %d\n",id, j);

        // Wait till all bidders have written to BB
        for(uint i = 0; i < MAX_BIDDERS; i++)
        {
            if(i == id)
                continue;
            //printf("Bidder %d is waiting for bidder %d to write bit code to BB in round %d\n",id, i,j);
            while(!bb->updatedBB[i][j])
                usleep(100);
        }
        

        // Compute the winning bit for this round
        for(uint i = 0; i < MAX_BIDDERS; i++)
        {
            delete bidderBitcode[i]; // Cleanup the existing bit codes and get afresh from BB 
            bidderBitcode[i] = new GroupElement(grp, &bb->bidderBB[i].bitCode[j]);

            //printf("Bidder %d: Retrieved Bit code[%d][%d] is:\n",id, i,j);
            //grp->printGroupElement(bidderBitcode[i]);

        }    

        winBit[j] = enc->decodeBitcode(j, this);

        //if(highestBidder)

            printf("Bidder %d: Winning bit for round %d is %d\n",id, j, winBit[j]);

        sem_post(bidder_thr_sem); 

        //printf("Bidder %d is waiting for computeStage in round %d\n",id,j);

        //sem_wait(bidder_sync_sem); // Wait till Evaluator has completed tasks in round j

        //while(bb->evalUpdatedRound != k);
        
        
        if((winBit[j] == 1) && (computeBit == false) && (highestBidder == false))
            auctionLost = true;
        //cout << "Round " << j << " is completed for bidder " << id << endl;
        
    }

    uint winBid = 0;
    
    for(uint j = 0; j < MAX_BIT_LENGTH; j++)
    {
        //printf("%d\t",winBit[j]);
        if(winBit[j])
        {
            winBid = winBid + exp(2, MAX_BIT_LENGTH-j-1);
        }
        //printf("Computed winning bid value is %d\n", winBid);
    }
    
    printf("Second highest bid value computed by bidder %d is %d\n", id, winBid);

	return verifyStage;
}

void Bidder::protocolVerificationStage()
{
    /*
    // In this stage computation has been completed and need to check the 
    // validity of claims. A winner of the auction is expected to provide proof 
    // of winning. 
    // Winner should provide the randomness used for commitment
    // An evalutor who wins the auction needs to provide sum of beta values used 
    // for OT durng the last decider round. 
    // For this, Eval writes $\delta_j = \sum_{i=1}^n \alpha_{ij}$ for $j \in [l]$ to BB.
    // 
    */
    //grp->printGroupParams();

    char name[16];
    
    sprintf(name, "bidderSyn-%d",id); // Each semaphore has a name of the form "bidder-<id>". E.g.: Bidder 12 has name "bidder-12"

    bidder_sync_sem = sem_open(name, O_CREAT, 0777, 0);
    if(bidder_sync_sem == SEM_FAILED)
    {
        perror("bidder_sync_sem: Semaphore creation failed");
    }
    
    if(bb->winningBid != bidval) //Not a winner, so quit
    {
        sem_post(bidder_sync_sem);
        bb->verifyStageDone[id] = true;
        return;
    }

    printf("Bidder %d is the claimed winner\n", id);
        

    //printf("Bidder %d's buffer is:\n", id);

    // Write all private keys to the BB
    for(uint j = 0; j < MAX_BIT_LENGTH; j++)
    {
        BN_bn2bin(x[j], bb->xWinner[j]);
       // printBuffer(bb->xWinner[j], MAX_BIG_NUM_SIZE);

        BN_bn2bin(r[j], bb->rWinner[j]);
       // printBuffer(bb->rWinner[j], MAX_BIG_NUM_SIZE);

        BN_bn2bin(s[j], bb->sWinner[j]);

        BN_bn2bin(t[j], bb->tWinner[j]);

    }

    

    bb->winnerClaim = id; // Claim victory
    sem_post(bidder_sync_sem);
    bb->verifyStageDone[id] = true;
}


#ifdef COMMENT

void Eval::protocolVerificationStage()
{
    /*
    // In this stage computation has been completed and need to check the 
    // validity of claims. A winner of the auction is expected to provide proof 
    // of winning. 
    // Winner should provide the randomness used for commitment 
    // An evalutor who wins the auction needs to provide sum of beta values used 
    // for OT durng the last decider round. 
    // For this, Eval writes $\delta_j = \sum_{i=1}^n \alpha_{ij}$ for $j \in [l]$ to BB.
    // 
    */
    //grp->printGroupParams();
    

    if(bb->winningBid == bidval) //Winner!
    {
        BN_CTX *ctx = BN_CTX_new();

        bb->winnerClaim = id;

        // Write all private keys to the BB
        for(uint j = 0; j < MAX_BIT_LENGTH; j++)
        {
            BN_bn2bin(x[j], bb->xWinner[j]);
        // printBuffer(bb->xWinner[j], MAX_BIG_NUM_SIZE);

            BN_bn2bin(r[j], bb->rWinner[j]);
        // printBuffer(bb->rWinner[j], MAX_BIG_NUM_SIZE);
            BN_bn2bin(s[j], bb->sWinner[j]);

            BN_bn2bin(t[j], bb->tWinner[j]);
        }

        GroupElement e = GroupElement(grp);


        if(id == 0)
        {
            for(uint j=0; j < MAX_BIT_LENGTH; j++)
            {
                BN_set_word(delta[j], 0);
                for(uint i = 1; i < MAX_BIDDERS; i++)
                {
                    BN_mod_add(delta[j], delta[j], beta[i][j], grp->q, ctx);
                }
                n = BN_num_bytes(delta[j]);
#ifdef DEBUG                
                printf("\nEval's delta[%d] is \n", j);
                BN_print_fp(stdout, delta[j]);
#endif                
                BN_bn2bin(delta[j], bb->evalWinProof[j]); // Write proof to BB
            }
        }

        BN_CTX_free(ctx);
    }
    bb->verifyStageDone[id] = true;
}
void Bidder::announceWinner()
{
    uint winBid = 0;
    uint lastDecider = 0;
    for(uint j = 0; j < MAX_BIT_LENGTH; j++)
    {
        if(bb->winBit[j])
        {
            winBid = winBid + exp(2, MAX_BIT_LENGTH-j-1);
            lastDecider = j;
        }
        //printf("Computed winning bid value is %d\n", winBid);
    }
    bb->winningBid = winBid;

    printf("Winning bid value is %d\n", winBid);
    printf("Last decider round is %d\n", lastDecider);
}

/*
 * This function interacts with the winner to verify that the bit codes used by the winner during each round
 * correspond the bits of winning bid.
*/
bool Bidder::verifyWinnerClaim()
{

    bool retval = false;
    
    uint winId = -1;
    /*
     The evaluator also needs to retrieve the bitcodes used by the winner;
     Construct fresh bit codes using the private keys shared.
     And compare the two.
    */

    char name[16];

    for(uint i = 1; i < MAX_BIDDERS; i++)
    {
        if(bb->winnerClaim != -1)
        {
            winId = bb->winnerClaim;
            break;
        }
        usleep(100);
        sprintf(name, "bidderSyn-%d",i); // Each semaphore has a name of the form "bidder-<id>". E.g.: Bidder 12 has name "bidder-12"

        eval_sync_sem[i] = sem_open(name, O_CREAT, 0777, 1);
        if(eval_sync_sem[i] == SEM_FAILED)
        {
            perror("eval_sync_sem: Semaphore creation failed");
        }
        // sem_wait(eval_sync_sem[i]);
        while(!bb->verifyStageDone[i]); // Wait till ith bidder is done with verification stage.
    }
    printf("Winner Id is %d\n", winId);

    if(winId == 0)
    {
        return true;
    }

    // Retrieval of bit codes used by winner during OT
    // B_j = C_j^0 * G^{-s} * H^{-t}
    GroupElement e = GroupElement(grp);
    GroupElement f = GroupElement(grp);
    GroupElement u = GroupElement(grp);
    GroupElement v = GroupElement(grp);
    GrpPoint G,H;

    GroupElement *origBitCode[MAX_BIT_LENGTH];
    GroupElement *claimBitCode[MAX_BIT_LENGTH];


    BIGNUM * sj = BN_new();
    BIGNUM * tj = BN_new();
    for(uint j =0; j < MAX_BIT_LENGTH; j++)
    {

        origBitCode[j] = new GroupElement(grp);

        if(evalComputeBit[j])
        {

            G = G1[winId][j];
            H = H1[winId][j];
        }
        else
        {
            //printf("G0[%d][%d] = \n",winId,j);
            //e.printGroupPoint(&G0[winId][j]);
            G = G0[winId][j];
            H = H0[winId][j];
        }

        GroupElement d = GroupElement(grp, &G);
        GroupElement e = GroupElement(grp, &H);



        //printf("element G[%d][%d] is \n",winId,j);
        //grp->printGroupElement(&d);

        //printf("element H[%d] is \n",j);
        //grp->printGroupElement(&e);

        BN_bin2bn(bb->sWinner[j],MAX_BIG_NUM_SIZE,sj);
        BN_bin2bn(bb->tWinner[j],MAX_BIG_NUM_SIZE,tj);

        //printf("sj = \n");
        //BN_print_fp(stdout, sj);
        //cout << endl;
        //printf("tj = \n");
        //BN_print_fp(stdout, tj);
        //cout << endl;

        grp->getInverse(&d);
        grp->getInverse(&e);
        //printf("element G inverse[%d][%d] is \n",winId,j);
        //grp->printGroupElement(&d);

        grp->power(&u,&d, sj);
        grp->power(&v,&e, tj);
        grp->elementMultiply(&f, &u, &v);

        GroupElement a = GroupElement(grp, &bb->bidderBB[winId].msgEnc_1[j]);

        grp->elementMultiply(origBitCode[j], &f, &a);
    }

    // Compute the claimed bit codes for winner
    BIGNUM * xj = BN_new();
    BIGNUM * rj = BN_new();
    for(uint j=0; j < MAX_BIT_LENGTH; j++)
    {
        claimBitCode[j] = new GroupElement(grp);
        if(bb->winBit[j])
        {
            BN_bin2bn(bb->rWinner[j], MAX_BIG_NUM_SIZE,rj);
            enc->oneBitEncode(claimBitCode[j], rj);
        }
        else
        {
            BN_bin2bn(bb->xWinner[j], MAX_BIG_NUM_SIZE,xj);
            enc->zeroBitEncode(claimBitCode[j], xj, winId, j, bb);
        }
    }

    // Compare the claimed vs original bit codes
    for(uint j=0; j < MAX_BIT_LENGTH; j++)
    {
        //printf("Claimed %d bit code %d is \n",evalComputeBit[j], j);
        //grp->printGroupElement(claimBitCode[j]);

        //printf("Original %d bit code %d is \n",evalComputeBit[j],j);
        //grp->printGroupElement(origBitCode[j]);

        if(grp->compareElements(claimBitCode[j],origBitCode[j]) == 0)
        {
            //printf("The claimed bit code %d for winner %d is same as original bit code\n", j, winId);
            retval = true;

        }
        else
        {
            printf("The claimed bit code %d for winner %d is not same as original bit code\n",j, winId); 
            BN_bn2bin(beta[winId][j], bb->evalAlpha);
            retval = false;
            goto cleanup;
        }

    }    
cleanup:

    BN_free(sj);
    BN_free(tj);
    BN_free(xj);
    BN_free(rj);
    for(uint j=0; j < MAX_BIT_LENGTH; j++)
    {
        delete claimBitCode[j];
        delete origBitCode[j];for(uint j=0; j < MAX_BIT_LENGTH; j++);
    }
    return retval;
        
}
#endif // COMMENT

void Bidder::printBuffer(unsigned char *buffer, uint n)
{
    cout << endl;
    for(uint k = 0; k < n; k++)
    {
        printf("%0X", buffer[k]);
    }
    cout << endl;
}