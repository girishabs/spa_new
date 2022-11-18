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
    

    rcommit = grp->getRandomNumber() ;
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

    uint msglen = 0;


    for(int j = 0; j < MAX_BIT_LENGTH; j++)
    {
        msglen = msglen + BN_num_bytes(x[j]);
        msglen = msglen + BN_num_bytes(r[j]);
        msglen = msglen + BN_num_bytes(s[j]);
        msglen = msglen + BN_num_bytes(t[j]);
        msglen = msglen + BN_num_bytes(beta[j]);
    }    
    
    unsigned char *buffer= new unsigned char[msglen];

    uint size = 0, n = 0;
    for(int j = 0; j < MAX_BIT_LENGTH; j++)
    {
        n = BN_bn2bin(x[j], &buffer[size]);
        size = size + n;
    }

    for(int j = 0; j < MAX_BIT_LENGTH; j++)
    {
        n = BN_bn2bin(r[j], &buffer[size]);
        size = size + n;
    }
    for(int j = 0; j < MAX_BIT_LENGTH; j++)
    {
        n = BN_bn2bin(s[j], &buffer[size]);
        size = size + n;
    }
    for(int j = 0; j < MAX_BIT_LENGTH; j++)
    {
        n = BN_bn2bin(t[j], &buffer[size]);
        size = size + n;
    }
    for(int j = 0; j < MAX_BIT_LENGTH; j++)
    {
        n = BN_bn2bin(beta[j], &buffer[size]);
        size = size + n;
    }


#ifdef DEBUG
    printf("Original buffer for bidder %d is:\n", id);
    printBuffer(buffer, size);
#endif    

    
    unsigned char hashString[SHA256_DIGEST_LENGTH];

    SHA256(buffer, size, hashString);

    BIGNUM *hash = BN_new();

    BN_bin2bn(hashString,MAX_BIG_NUM_SIZE,hash);

    
    commitObj->Commit(bidCommit, bid,hash, rcommit); // Generate Commitment

#ifdef DEBUG
    printf("The bid value is:\n");
    BN_print_fp(stdout, bid);
    cout << endl;
    printf("with commitment:\n");
    grp->printGroupElement(bidCommit);
    printf("The hash value is:\n");
    BN_print_fp(stdout, hash);
    printf("The randomness is:\n");
    BN_print_fp(stdout, rcommit);
#endif

    bidderBB->commitment = bidCommit->gpt; // Write to BB    
        
    
    bb->setupStageDone[id] = true;

    // usleep(100000);
    //sem_wait(bidder_sync_sem);

    // printf("Bidder %d is waiting in round \n",id);

    
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

void * buildBidderData(void *input)
{
    struct thread_data *td = (struct thread_data *) input;
    uint i = td->i;

    Bidder *bidder = (Bidder *)td->bidder;

    BIGNUM *num;
    GroupElement e  = GroupElement(bidder->grp);  
    GroupElement f  = GroupElement(bidder->grp);  

    // cout << "Inside buildBidderData thread " << i << endl;
    
    // Pre-allocate the OT first messages for both 0 and 1. Use bit specific messages during computation

    for(uint j = 0; j < MAX_BIT_LENGTH; j ++)
    {
        bidder->beta[j] = bidder->grp->getRandomNumber();
        bidder->invbeta[j] = BN_new();
        BN_sub(bidder->invbeta[j],bidder->grp->q,bidder->beta[j]);
        num = bidder->grp->getRandomNumber() ;
        bidder->grp->power(&f, bidder->grp->g, num);
        bidder->bidderBB->zeta[j] = f.gpt; // Write zeta values to BB
                
        bidder->grp->power(&e,bidder->grp->g, bidder->beta[j]); // G0 = g^beta
        bidder->G0[j] = e.gpt;

        bidder->grp->elementMultiply(&e, &e, bidder->T); // G1 = g^beta.T
        bidder->G1[j] = e.gpt;
                
        bidder->grp->power(&e,bidder->grp->h, bidder->beta[j]); // H0 = h^beta
        bidder->H0[j] = e.gpt;

        bidder->grp->elementMultiply(&e, &e, &f); // H1 = h^beta.T2
        bidder->H1[j] = e.gpt;
    }

//    sem_post(&bidder->bidder_init_sem[i]); // Increment the counting semaphore

    pthread_exit(NULL);    
}


// The following function initializes the Bidder object
void Bidder::initBidder()
{

    auto ststart = std::chrono::high_resolution_clock::now();
    
    // Allocate OT parameters and write them on to BB
    BIGNUM *num;
    GroupElement e  = GroupElement(grp);  
    GroupElement f  = GroupElement(grp);  


    int rc = 0;

    pthread_t threads[MAX_BIDDERS];
    struct thread_data td[MAX_BIDDERS];

    for(uint i = 0; i < MAX_BIDDERS; i++)
    {

        for(uint j = 0; j < MAX_BIT_LENGTH; j ++)
        {
            beta[j] = grp->getRandomNumber();
            invbeta[j] = BN_new();
            BN_sub(invbeta[j],grp->q,beta[j]);

            num = grp->getRandomNumber() ;
            auto pstart = std::chrono::high_resolution_clock::now();

            grp->power(&f, grp->g, num);

            auto stend = std::chrono::high_resolution_clock::now();

            std::chrono::duration<double, std::milli> stfloat_ms = stend - pstart;

            // printf("Exponentiation time for %d,%d is ", i, j ); 
            // cout << stfloat_ms.count() << " milliseconds" << std::endl;

            bidderBB->zeta[j] = f.gpt; // Write zeta values to BB
                
            grp->power(&e,grp->g, beta[j]); // G0 = g^beta
            G0[j] = e.gpt;


            auto mstart = std::chrono::high_resolution_clock::now();


            grp->elementMultiply(&e, &e, grp->T1); // G1 = g^beta.T1

            stend = std::chrono::high_resolution_clock::now();

            stfloat_ms = stend - mstart;

            // printf("Element multiplication time for %d,%d is ", i, j ); 
            // cout << stfloat_ms.count() << " milliseconds" << std::endl;


            G1[j] = e.gpt;
                
            grp->power(&e,grp->h, beta[j]); // H0 = h^beta
            H0[j] = e.gpt;

            grp->elementMultiply(&e, &e, &f); // H1 = h^beta.T2
            H1[j] = e.gpt;

            stend = std::chrono::high_resolution_clock::now();

            stfloat_ms = stend - ststart;

            //printf("Elapsed time for %d,%d is ", i, j ); 
            //cout << stfloat_ms.count() << " milliseconds" << std::endl;
        }


    
    }
    

    for(uint i = 0; i < MAX_BIDDERS; i++)
    {
        bidderBitcode[i] = new GroupElement(grp);           
    }       

#ifdef INIT_THREAD
    for(uint i = 0; i < MAX_BIDDERS+1; i++)
    {
        //printf("Waiting for init thread %d to complete\n",i);
        sem_wait(&eval_init_sem[i]); // Wait for semaphore
    }
#endif // INIT_THREAD    
    auto stend = std::chrono::high_resolution_clock::now();

    std::chrono::duration<double, std::milli> stfloat_ms = stend - ststart;

    // std::cout << "Total eval init stage elapsed time is " << 
    // stfloat_ms.count() << " milliseconds" << std::endl;
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
        bidder->bidderBB[i].G[j] = bidder->G0[j] ; 

        bidder->bidderBB[i].H[j] = bidder->H0[j] ; 

    }
    else if(td->bit == 1) // OT params for choice bit = 1
    {
        bidder->bidderBB[i].G[j] = bidder->G1[j] ;    
        bidder->bidderBB[i].H[j] = bidder->H1[j] ; 
    }
    GroupElement *e  = new GroupElement(bidder->grp, &bidder->bidderBB[i].G[j]);   
    GroupElement *f  = new GroupElement(bidder->grp, &bidder->bidderBB[i].H[j]);   

#ifdef DEBUG
    printf("Values of G and H %d,%d are:\n", i,j);
    bidder->grp->printGroupElement(e);
    bidder->grp->printGroupElement(f);
#endif    

    bidder->bb->OTParamsUpdated[i][j] = true;   

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
    GroupElement e  = GroupElement(grp);
    GroupElement f  = GroupElement(grp);
    int rc;

    for(uint k = 1; k <= MAX_BIT_LENGTH; k++)
    {    
        uint j = k-1;

        pthread_t threads[MAX_BIDDERS];
        struct thread_data td[MAX_BIDDERS];
                
        GroupElement e  = GroupElement(grp);   
        for(uint i = 0; i < MAX_BIDDERS; i++)
        {
            
            // printf("Tx: beta, invbeta[%d][%d] are:\n", i,j);
            // BN_print_fp(stdout, beta[i][j]);
            // cout << endl;
            // BN_print_fp(stdout, invbeta[i][j]);
            // cout << endl;
            // OT first message computation

            if (i == id)
                continue; // No need to create a OT thread for itself.

            sem_init(&eval_thr_sem[i], 0, 1);

            sem_wait(&eval_thr_sem[i]); // Wait for semaphore

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

        if(highestBidder) // Highest bidder only sends zero bit codes through OT
            computeBit = false; 
        else
            computeBit = getABPbit(j);

        if (computeBit)
        {
            enc->oneBitEncode(bitcode[j], r[j]);
            
            enc->zeroBitEncode(zeroBitCode,x[j],id,j, bb); 

            // printf("Constructed onebitcode[%d][%d] is :\n",id,j);            
        }
        else 
        {
            enc->zeroBitEncode(bitcode[j],x[j],id,j, bb); 
            // printf("Constructed zerobitcode[%d][%d] is :\n",id,j);
        }
        // grp->printGroupElement(bitcode[j]);
        {
            auto start = std::chrono::high_resolution_clock::now();
            //while(!bb->OTParamsUpdated[id][j]) 
                usleep(10); 
                // Wait till Eval updates OT params
            auto end = std::chrono::high_resolution_clock::now();

            std::chrono::duration<double, std::milli> float_ms = end - start;

            //std::cout << "OT wait time is " << 
            //    float_ms.count() << " ms for bidder " << id << std::endl;
        }        
    
            
            
        // printf("Bidder %d Received OT Params for round %d\n", id, j);

// Run OT to send  the bit code to other bidders
        for(uint i = 0; i < MAX_BIDDERS; i++)
        {
            if(i == id)
                continue; // Ignore self

            GroupElement zeta = GroupElement(grp, &bb->bidderBB[i].zeta[j]);
            grp->getInverse(&zeta); // We are not going to use zeta; Only its inverse is useful

            GroupElement G = GroupElement(grp, &bb->bidderBB[i].G[j]);
            GroupElement H = GroupElement(grp, &bb->bidderBB[i].H[j]);

            // The encoding for M_1 is: C_1 = (G/zeta)^s . (H/T)^t . B_ij

            // printf("Used G and H are:\n");
            // grp->printGroupElement(&G);
            // grp->printGroupElement(&H);
        
            grp->power(&e, &G, s[j]);
            grp->power(&f, &H, t[j]);

            grp->elementMultiply(&e, &e, &f);
            grp->elementMultiply(&e, &e, bitcode[j]);

            bidderBB->msgEnc_1[j] = e.gpt; // Write OT message to BB
        //   printf("C0[%d][%d] point written is:\n", id, j);
        //   e.printGroupPoint(&bidderBB->msgEnc_1[j]);

        //   printf("Bidder's z[%d][%d] is : \n",id, j);
        //   e.printGroupPoint(&bidderBB->z[j]); 
        
        }    

        bb->sentBitCodes[id][j] = true;

        for(uint i = 0; i < MAX_BIDDERS; i++)
        {
            while(!bb->sentBitCodes[id][j])
                usleep(1);
            //printf("Bidder %d received from bidder %d bit codes in round %d\n", id,i,j);
        } // Wait for all other bidders to send their bit codes    

        if(!computeBit && !highestBidder) // If contributing 0 bit and not the winner, 
                                          //skip rest of computation in this round
            goto endOfRound;

        // Having sent the j'th bit code to all other bidders, receive the bit codes from other bidders
        printf("Bidder %d is contributing a 1 bit. So need to check what others have.\n",id);
        for(uint i = 0; i < MAX_BIDDERS; i++)
        {
            if(i == id)
            {
                bidderBitcode[i] = zeroBitCode; // Copy own zero bit for this round code to i'th position where i = id
                continue; // Ignore self
            }

            GroupElement C1 = GroupElement(grp, &bidderBB[i].msgEnc_1[j]);
            //C0.printGroupPoint(&bidderBB->msgEnc_1[j]);

            GroupElement z  = GroupElement(grp, &bidderBB[i].z[j]);
            //printf("Eval:Retrieved z[%d][%d] is \n:",i,j);
            //bidder->grp->printGroupElement(&z);
            //printf("Rx: beta, invbeta[%d][%d] are:\n", i,j);
            //BN_print_fp(stdout, beta[j]);
            //cout << endl;
            //BN_print_fp(stdout, invbeta[j]);
            //cout << endl;

            GroupElement a  = GroupElement(grp);
            grp->power(&a,&z,invbeta[j]);

            grp->elementMultiply(bidderBitcode[i],&C1,&a);

        }    
        // Compute the winning bit by setting own bit code to 0.
        // If the winning bit is 1, that means, some other party is also contributing a 1 bit code in this round
        // Else if winning bit is 0, that means, the party is indeed the winner
        testBit = enc->decodeBitcode(j, this); 
        if(!testBit && !highestBidder)
        {
            printf("Bidder %d is the highest bidder\n", id);
            highestBidder = true;
        }

        if(highestBidder) 
        {
            // Write the same bitcode to BB as that of second highest bidder - i.e. bit code for testBit
            if(testBit)
                enc->oneBitEncode(bitcode[j], r[j]);
            else
                enc->zeroBitEncode(bitcode[j],x[j],id,j,bb); 
        }

endOfRound:
        // Write the bit code to BB
        bidderBB[id].bitCode[j] = bitcode[j]->gpt;
        bb->updatedBB[id][j] = true;

        // Wait till all bidders have written to BB
        for(uint i = 0; i < MAX_BIDDERS; i++)
        {
            //printf("Waiting for bidder %d to write bit code to BB in round %d\n",i,j);
            while(!bb->updatedBB[i][j])
                usleep(1);
        }
        

        // Compute the winning bit for this round
        for(uint i = 0; i < MAX_BIDDERS; i++)
        {
            bidderBitcode[i]->gpt = bidderBB[i].bitCode[j];
        }    

        winBit[j] = enc->decodeBitcode(j, this);

        //if(highestBidder)

            printf("Bidder %d: Winning bit for round %d is %d\n",id, j, winBit[j]);

        sem_post(bidder_thr_sem); 

        //printf("Bidder %d is waiting for computeStage in round %d\n",id,j);

        //sem_wait(bidder_sync_sem); // Wait till Evaluator has completed tasks in round j

        //while(bb->evalUpdatedRound != k);
        
        
        if(winBit[j] == 1 && computeBit == 0)
            auctionLost = true;
        //cout << "Round " << j << " is completed" << endl;
        
    }

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
        

    BN_bn2bin(rcommit, bb->bidderWinProof[id]); // Write commit randomness to BB
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

        uint n = BN_num_bytes(rcommit);
        BN_bn2bin(rcommit, bb->bidderWinProof[id]); // Write proof to BB

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
        sem_wait(eval_sync_sem[i]);
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