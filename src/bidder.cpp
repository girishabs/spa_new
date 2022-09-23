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
    //bidCommit  = GroupElement(grp);

    rcommit = grp->getRandomNumber() ;
    bid = BN_new();
    BN_set_word(bid, bidval);
    //printf("The bid value is:\n");
    //BN_print_fp(stdout, bid);
    //cout << endl;
#ifdef DEBUG    
    printBidBits();
#endif

    evalBB = static_cast<struct BBMemoryEval *>(&bb->evalBB);
    

    BN_set_word(bid, bidval);
    

    GroupElement e = GroupElement(grp);

    // Generate Public/Private keys for each round
    for(int j = 0; j < MAX_BIT_LENGTH; j++)
    {

        
        x[j] = grp->getRandomNumber() ;
        r[j] = grp->getRandomNumber() ;
        grp->power(&e, grp->g, x[j]); //pubKey = g^x

        bidderBB->common.pubKey[j] = e.gpt; // Write public keys to BB
        
        // printf("Bidder public key [%d][%d]:\n",id,j);
        // e.printGroupPoint(&bidderBB->common.pubKey[j]);
        // printf("Bidder private key [%d]:\n",j);
        // BN_print_fp(stdout, x[j]);
        // cout << endl;    
    }

    uint msglen = 0;


    for(int j = 0; j < MAX_BIT_LENGTH; j++)
    {
        msglen = msglen + BN_num_bytes(x[j]);
        msglen = msglen + BN_num_bytes(r[j]);
        msglen = msglen + BN_num_bytes(s[j]);
        msglen = msglen + BN_num_bytes(t[j]);

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

    bidderBB->common.commitment = bidCommit->gpt; // Write to BB    
        
    
    bb->setupStageDone[id] = true;

    // usleep(100000);
    sem_wait(bidder_sync_sem);
    
#ifdef Trying
    for(int i = 1; i < MAX_BIDDERS; i++)
    {
        if(i == id)
            continue;
        printf("Bidder %d is waiting for bidder %d in setup\n",id, i);
        //while(!bb->setupStageDone[i])
            usleep(10);
    }
#endif

    // while(!bb->setupStageDone[0]) 
        usleep(1);

    

    //printf("Completed setup stage for bidder %d\n",id);

	return computeStage;
 
}


struct thread_data
{
    uint i; // Bidder id
    uint j; // auction round
    bool bit; // Bit being encoded
    Eval *eval; // Pointer to Eval class.
};

void * buildEvalData(void *input)
{
    struct thread_data *td = (struct thread_data *) input;
    uint i = td->i;
    //uint j = td->j;

    Eval *eval = (Eval *)td->eval;

    BIGNUM *num;
    GroupElement e  = GroupElement(eval->grp);  
    GroupElement f  = GroupElement(eval->grp);  

    // cout << "Inside buildEvalData thread " << i << endl;
    
    // Pre-allocate the OT first messages for both 0 and 1. Use bit specific messages during computation

    for(uint j = 0; j < MAX_BIT_LENGTH; j ++)
    {
        eval->beta[i][j] = eval->grp->getRandomNumber();
        eval->invbeta[i][j] = BN_new();
        BN_sub(eval->invbeta[i][j],eval->grp->q,eval->beta[i][j]);
        num = eval->grp->getRandomNumber() ;
        eval->grp->power(&f, eval->grp->g, num);
        eval->evalBB->T2[i][j] = f.gpt; // Write T2 values to BB
                
        eval->grp->power(&e,eval->grp->g, eval->beta[i][j]); // G0 = g^beta
        eval->G0[i][j] = e.gpt;

        eval->grp->elementMultiply(&e, &e, eval->T1); // G1 = g^beta.T1
        eval->G1[i][j] = e.gpt;
                
        eval->grp->power(&e,eval->grp->h, eval->beta[i][j]); // H0 = h^beta
        eval->H0[i][j] = e.gpt;

        eval->grp->elementMultiply(&e, &e, &f); // H1 = h^beta.T2
        eval->H1[i][j] = e.gpt;
    }

    sem_post(&eval->eval_init_sem[i]); // Increment the counting semaphore

    pthread_exit(NULL);    
}


// The following function initializes the Eval object
void Eval::initEval()
{

    auto ststart = std::chrono::high_resolution_clock::now();
    
    // Allocate OT parameters and write them on to BB
    BIGNUM *num;
    GroupElement e  = GroupElement(grp);  
    GroupElement f  = GroupElement(grp);  

    T1 = new GroupElement(grp);
    num = grp->getRandomNumber() ;
    grp->power(T1, grp->g, num);
    evalBB->T1 = T1->gpt;
    int rc = 0;

    pthread_t threads[MAX_BIDDERS+1];
    struct thread_data td[MAX_BIDDERS+1];

    for(uint i = 0; i < MAX_BIDDERS; i++)
    {

#ifdef INIT_THREAD
        sem_init(&eval_init_sem[i], 0, 1);
        sem_wait(&eval_init_sem[i]); // Wait for semaphore
        td[i].i = i;
            
        td[i].eval = this;
        rc = pthread_create(&threads[i], NULL, &buildEvalData, (void *)&td[i]);
        if(rc)
        {
            cout << "Error in creating threads for buildEvalData" << rc << endl;
        }
#endif // INIT_THREAD

        for(uint j = 0; j < MAX_BIT_LENGTH; j ++)
        {
            beta[i][j] = grp->getRandomNumber();
            invbeta[i][j] = BN_new();
            BN_sub(invbeta[i][j],grp->q,beta[i][j]);

            num = grp->getRandomNumber() ;
            auto pstart = std::chrono::high_resolution_clock::now();

            grp->power(&f, grp->g, num);

            auto stend = std::chrono::high_resolution_clock::now();

            std::chrono::duration<double, std::milli> stfloat_ms = stend - pstart;

            printf("Exponentiation time for %d,%d is ", i, j ); 
            cout << stfloat_ms.count() << " milliseconds" << std::endl;

            evalBB->T2[i][j] = f.gpt; // Write T2 values to BB
                
            grp->power(&e,grp->g, beta[i][j]); // G0 = g^beta
            G0[i][j] = e.gpt;


            auto mstart = std::chrono::high_resolution_clock::now();


            grp->elementMultiply(&e, &e, T1); // G1 = g^beta.T1

            stend = std::chrono::high_resolution_clock::now();

            stfloat_ms = stend - mstart;

            printf("Element multiplication time for %d,%d is ", i, j ); 
            cout << stfloat_ms.count() << " milliseconds" << std::endl;


            G1[i][j] = e.gpt;
                
            grp->power(&e,grp->h, beta[i][j]); // H0 = h^beta
            H0[i][j] = e.gpt;

            grp->elementMultiply(&e, &e, &f); // H1 = h^beta.T2
            H1[i][j] = e.gpt;

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
    for(uint j = 0; j < MAX_BIT_LENGTH; j++)
    {
        delta[j] = BN_new();
        // Following is dummy OT second message values - required only for commitment
        s[j] = grp->getRandomNumber();
        t[j] = grp->getRandomNumber();
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


PStage Eval::protocolSetupStage()
{
    //cout << "Inside eval SetupStage" << endl;
    //printf("Bid value for eval %d is %X\n", id, bidval);
    rcommit = grp->getRandomNumber() ;
    bid = BN_new();
    BN_set_word(bid, bidval);
    GroupElement e  = GroupElement(grp);

    // Initialize the claimant on BB to be invalid
    bb->winnerClaim = -1; 

#ifdef DEBUG
    printBidBits();
#endif    

    // Generate Public/Private keys for each round
    for(int j = 0; j < MAX_BIT_LENGTH; j++)
    {
        // BIGNUM *n = BN_new();
        // BN_set_word(n, 1);
        // x[j] = n;

        x[j] = grp->getRandomNumber() ;
        r[j] = grp->getRandomNumber() ;

        
        grp->power(&e, grp->g, x[j]);

       // printf("Eval public gpt [%d][%d]:\n",id,j);
       // e.printGroupPoint(&e.gpt);

        evalBB->common.pubKey[j] = e.gpt; // Write public keys to BB
        // printf("Eval public key [%d][%d]:\n",id,j);
        // e.printGroupPoint(&evalBB->common.pubKey[j]);
    

        // printf("Eval private key [%d][%d]:\n",id,j);
        // BN_print_fp(stdout, x[j]);
        // cout << endl;
            
    }
    uint msglen = 0;


    for(int j = 0; j < MAX_BIT_LENGTH; j++)
    {
        msglen = msglen + BN_num_bytes(x[j]);
        msglen = msglen + BN_num_bytes(r[j]);
        msglen = msglen + BN_num_bytes(s[j]);
        msglen = msglen + BN_num_bytes(t[j]);
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
#ifdef DEBUG    
    printf("Original buffer for bidder %d is:\n", id);
    printBuffer(buffer, size);
#endif    
    
    unsigned char hashString[SHA256_DIGEST_LENGTH];

    SHA256(buffer, size, hashString);

    BIGNUM *hash = BN_new();

    BN_bin2bn(hashString,MAX_BIG_NUM_SIZE,hash);

    
    commitObj->Commit(bidCommit, bid,hash, rcommit); // Generate Commitment
    evalBB->common.commitment = bidCommit->gpt;

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

    
    char name[16];

    usleep(10);
    for(uint i = 1; i < MAX_BIDDERS; i++)
    {

        sprintf(name, "bidderSyn-%d",i); // Each semaphore has a name of the form "bidder-<id>". E.g.: Bidder 12 has name "bidder-12"

        eval_sync_sem[i] = sem_open(name, O_CREAT, 0777, 0);
        if(eval_sync_sem[i] == SEM_FAILED)
        {
            perror("bidder_sync_sem: Semaphore creation failed");
        }
        int sval = 0;
        sem_getvalue(eval_sync_sem[i], &sval);
        //printf("Value of sync semaphore %d is %d\n", i, sval);
        sem_post(eval_sync_sem[i]);
        
        // Wait for everyone to complete their setup stage.
        //printf("Bidder %d is waiting for bidder %d in setup\n",id, i);

        //while(!bb->setupStageDone[i]);       
    }


    bb->setupStageDone[id] = true;
    return computeStage; 
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
    bool computeBit, winBit ;
    GroupElement e  = GroupElement(grp);
    GroupElement f  = GroupElement(grp);

    for(uint k = 1; k <= MAX_BIT_LENGTH; k++)
    {    
        uint j = k-1;
        computeBit = getABPbit(j);
        if (computeBit)
        {
            enc->oneBitEncode(bitcode[j], r[j]);

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
            while(!bb->OTParamsUpdated[id][j]) 
                usleep(10); 
                // Wait till Eval updates OT params
            auto end = std::chrono::high_resolution_clock::now();

            std::chrono::duration<double, std::milli> float_ms = end - start;

            //std::cout << "OT wait time is " << 
            //    float_ms.count() << " ms for bidder " << id << std::endl;
        }        
    
            
            
        //printf("%d Received OT Params for round %d\n", id, j);

// Run OT to send  the bit code to evalutor
        GroupElement G = GroupElement(grp, &evalBB->G[id][j]);
        GroupElement H = GroupElement(grp, &evalBB->H[id][j]);
        // printf("Used G and H are:\n");
        // grp->printGroupElement(&G);
        // grp->printGroupElement(&H);
        
        grp->power(&e, &G, s[j]);
        grp->power(&f, &H, t[j]);

        grp->elementMultiply(&e, &e, &f);
        grp->elementMultiply(&e, &e, bitcode[j]);

        bidderBB->msgEnc_0[j] = e.gpt; // Write OT message to BB
     //   printf("C0[%d][%d] point written is:\n", id, j);
     //   e.printGroupPoint(&bidderBB->msgEnc_0[j]);

     //   printf("Bidder's z[%d][%d] is : \n",id, j);
     //   e.printGroupPoint(&bidderBB->z[j]); 
        
        bb->bidderUpdatedRound[id] = k;       

        //sem_post(bidder_sync_sem); // Signal the waiting thread that bidder is done updating
     

        //cout << id << ", waiting for eval update in round " << j << endl;      

        //usleep(100);

        sem_post(bidder_thr_sem); 

        // printf("Bidder %d is waiting for computeStage in round %d\n",id,j);

        sem_wait(bidder_sync_sem); // Wait till Evaluator has completed tasks in round j

        //while(bb->evalUpdatedRound != k);
        
        
        if(bb->winBit[j] == 1 && computeBit == 0)
            auctionLost = true;
        //cout << "Round " << j << " is completed" << endl;
        
    }

	return verifyStage;
}

/* This procedure implements the computation stage of the protocol - for the evalutor.
 * The bidder computes the ABP bit.
 * Uses BES to enode the bit to generate the bit code.
 * Uses the ABP bit as the choice bit for OT protocol.
 * Generates round specific randomness beta for the OT.
 * Writes the OT keys, G = g^beta.T1^computeBit, H = h^beta.T1^computeBit and T2 to the BB.
 * Generates the OT encryption for the bit.
 * Writes the encrypted messages for msg-0 and msg-1 of OT to the BB.
 * Obtains the OT encryptions for each bidder, C_0.
 * Computes the winBit for the round and writes it to BB.
 *  
*/


void * OTUpdate(void *input)
{
    struct thread_data *td = (struct thread_data *) input;
    uint i = td->i;
    uint j = td->j;

    Eval *eval = (Eval *)td->eval;

    //cout << "Inside thread " << i<< " j = " << j << endl;
    //eval->grp->printGroupElement(eval->grp->g);
    //eval->grp->power(&e,eval->grp->g, eval->beta[i][j]);
    //BN_print_fp(stdout, eval->beta[i][j]);
    //cout << endl;

    if(td->bit == 0) // OT params for choice bit = 0
    {
        eval->evalBB->G[i][j] = eval->G0[i][j] ; 

        eval->evalBB->H[i][j] = eval->H0[i][j] ; 

    }
    else if(td->bit == 1) // OT params for choice bit = 1
    {
        eval->evalBB->G[i][j] = eval->G1[i][j] ;    
        eval->evalBB->H[i][j] = eval->H1[i][j] ; 
    }
    GroupElement *e  = new GroupElement(eval->grp, &eval->evalBB->G[i][j]);   
    GroupElement *f  = new GroupElement(eval->grp, &eval->evalBB->H[i][j]);   

#ifdef DEBUG
    printf("Values of G and H %d,%d are:\n", i,j);
    eval->grp->printGroupElement(e);
    eval->grp->printGroupElement(f);
#endif    

    eval->bb->OTParamsUpdated[i][j] = true;   

    BBMemoryBidder *bidderBB = static_cast<struct BBMemoryBidder *>(&eval->bb->bidderBB[i]);

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
    
    while(eval->bb->bidderUpdatedRound[i] != j+1)
        usleep(10);


    //printf("C0[%d][%d] point received is:\n",i,j);

    GroupElement C0 = GroupElement(eval->grp, &bidderBB->msgEnc_0[j]);
    //C0.printGroupPoint(&bidderBB->msgEnc_0[j]);

    GroupElement z  = GroupElement(eval->grp, &bidderBB->z[j]);
    //printf("Eval:Retrieved z[%d][%d] is \n:",i,j);
    //eval->grp->printGroupElement(&z);
    //printf("Rx: beta, invbeta[%d][%d] are:\n", i,j);
    //BN_print_fp(stdout, eval->beta[i][j]);
    //cout << endl;
    //BN_print_fp(stdout, eval->invbeta[i][j]);
    //cout << endl;

    GroupElement a  = GroupElement(eval->grp);
    eval->grp->power(&a,&z,eval->invbeta[i][j]);

    eval->grp->elementMultiply(eval->bidderBitcode[i],&C0,&a);
    // printf("\nEval:The retrieved bitcode[%d][%d] is : \n", i,j);

    // eval->grp->printGroupElement(eval->bidderBitcode[i]);

    sem_post(&eval->eval_thr_sem[i]); // Increment the counting semaphore
    pthread_exit(NULL);    
}


PStage Eval::protocolComputeStageEval()
{
    bool computeBit, winBit ;
	//cout << "Inside ComputeStageEval" << endl;
    double OTClock = 0;
    int rc = 0;

    
    for(uint k = 1; k <= MAX_BIT_LENGTH; k++)
    {
        auto start = std::chrono::high_resolution_clock::now(); // measuring time taken for rounds

        uint j = k-1;
        pthread_t threads[MAX_BIDDERS-1];
        struct thread_data td[MAX_BIDDERS-1];
        evalComputeBit[j] = getABPbit(j);
        
        GroupElement e  = GroupElement(grp);   
        auto start2 = std::chrono::high_resolution_clock::now();
        for(uint i = 1; i < MAX_BIDDERS; i++)
        {
            
            // printf("Tx: beta, invbeta[%d][%d] are:\n", i,j);
            // BN_print_fp(stdout, beta[i][j]);
            // cout << endl;
            // BN_print_fp(stdout, invbeta[i][j]);
            // cout << endl;
            // OT first message computation

            sem_init(&eval_thr_sem[i], 0, 1);

            sem_wait(&eval_thr_sem[i]); // Wait for semaphore


            td[i-1].i = i;
            td[i-1].j = j;
            td[i-1].bit = evalComputeBit[j] ;
            td[i-1].eval = this;
            rc = pthread_create(&threads[i-1], NULL, &OTUpdate, (void *)&td[i-1]);
            if(rc)
            {
                cout << "Error in creating threads for OTUpdate" << rc << endl;
            }

        }               
    
            // printf("Value of G and H[%d][%d] are:\n",i,j);
            // e.printGroupPoint(&evalBB->G[i][j]);
            // e.printGroupPoint(&evalBB->H[i][j]);
 
            //printf("\nEval: beta[%d][%d]:\n",i,j);
            //BN_print_fp(stdout,invbeta[i][j]);    
            
        
        //if(!evalComputeBit[j])
        //{
            //printf("Eval has a 0 bit. Hence getting all bit codes\n");
            
            enc->zeroBitEncode(bidderBitcode[id],x[j],id,j,bb); // id = 0 for eval
            
            //grp->printGroupElement(bidderBitcode[id]);


            for(uint i = 1; i < MAX_BIDDERS; i++)
            {
                // printf("Waiting for thread %d\n",i);
                sem_wait(&eval_thr_sem[i]); // Wait for thread i to complete OT operation with bidder i
            }
            // printf("Done waiting for threads during round %d\n",j); 
            

            
            winBit = enc->decodeBitcode(j, this);

            auto end2 = std::chrono::high_resolution_clock::now();
            std::chrono::duration<double, std::milli> float_ms2 = end2 - start2;
            OTClock += float_ms2.count();

            //std::cout << "OT Computation time is " << 
            //float_ms2.count() << " ms during round " << j << std::endl;

        //} 
        
        /* else
        {
            winBit = 1;   
            auto end2 = std::chrono::high_resolution_clock::now();
            std::chrono::duration<double, std::milli> float_ms2 = end2 - start2;
            OTClock += float_ms2.count();

            std::cout << "OT Computation time for 1 eval bit is " << 
            float_ms2.count() << " ms for all bidders " << std::endl;
        }*/

        if (winBit == 0) // Computed bit is 0. Need to provide proofs
        {
            for(int i =0; i < MAX_BIDDERS; i++)
            {
                bb->proofOfComputation[i][j] = bidderBitcode[i]->gpt; // Write proof to BB
                //printf("Proof of computation [%d][%d]\n",i,j);
                //grp->printGroupElement(bidderBitcode[i]);
                //bidderBitcode[i]->printGroupPoint(&bb->proofOfComputation[i][j]);
            }
        }
     
        bb->winBit[j] = winBit;
        //printf("%d'th winBit is %i\n", j, winBit);

        if(bb->winBit[j] == 1 && evalComputeBit[j]  == 0)
        {
            auctionLost = true;
        }
        //cout << "Round " << j << " is completed" << endl;
        auto end = std::chrono::high_resolution_clock::now();

        std::chrono::duration<double, std::milli> float_ms = end - start;

        //std::cout << "Computation stage " << j << " elapsed time is " << 
        //float_ms.count() << " milliseconds" << std::endl;
        //bb->evalUpdatedRound = k; // Win Bit update completed by Eval for round j=k-1
        
        char name[16];
        for(uint i = 1; i < MAX_BIDDERS; i++)
        {
            sprintf(name, "bidderSyn-%d",i); // Each semaphore has a name of the form "bidder-<id>". E.g.: Bidder 12 has name "bidder-12"

            eval_sync_sem[i] = sem_open(name, O_CREAT, 0777, 0);
            if(eval_sync_sem[i] == SEM_FAILED)
            {
                perror("bidder_sync_sem: Semaphore creation failed");
            }
            sem_post(eval_sync_sem[i]);
        }

    }
    // cout << "Total OT Time taken is " << OTClock << "ms" << endl;
    announceWinner();

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
void Eval::announceWinner()
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
bool Eval::verifyWinnerClaim()
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

        GroupElement a = GroupElement(grp, &bb->bidderBB[winId].msgEnc_0[j]);

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

void Bidder::printBuffer(unsigned char *buffer, uint n)
{
    cout << endl;
    for(uint k = 0; k < n; k++)
    {
        printf("%0X", buffer[k]);
    }
    cout << endl;
}