/* This file contains the main function. The auction program can be started as either a bidder, evaluator or verifier by 
* passing parameters 0, 1 or 99. This number is used as the id by the process.
* The program also takes second argument which is for specifying the bid value.
*
*/

#include <string>
#include "bidder.h"
#include <cmath>

#include "verify.h"



int main(int argc, char const *argv[])
{

	const char *type = argv[1];


	PType processType;

	if(argc != 3)
	{
		cout << "Usage: auction id bidvalue" << endl;
		exit(-1);
	}

	if(strcmp(argv[1],"0") == 0)
	{
		//cout << "Process is an Evaluator" << endl;
		processType = pEvaluator;
		
	}
	else if(strcmp(argv[1],"99") == 0)
	{
		//cout << "Process is a Verifier" << endl;
		processType = pVerifier;
	}
	else
	{
		//cout << "Process is a Bidder" << endl;
		processType = pBidder;

	}

	auto start = std::chrono::high_resolution_clock::now();
    
    
	//Create a shared memory object. We use the Boost Interprocess library
    shared_memory_object shm (open_or_create, "Bulletin Board", read_write);

    //Set size
    shm.truncate(sizeof(struct BulletinBoard));

    //Map the whole shared memory in this process
    mapped_region region(shm, read_write);

    BulletinBoard *bb = static_cast<BulletinBoard*>(region.get_address());
	uint id = atoi(argv[1]);
	uint size = region.get_size();
	uint bidvalue = atoi(argv[2]);
   	

    switch(processType)
	{
		case pEvaluator:
		{
			
			auto st_start = std::chrono::high_resolution_clock::now();

			Eval eval = Eval(1, bidvalue, D, ADDR_Verify, 0, bb);
			{
				eval.initEval();
				eval.protocolSetupStage();

				auto st_end = std::chrono::high_resolution_clock::now();

		    	std::chrono::duration<double, std::milli> st_float_ms = st_end - st_start;

    			std::cout << "Total Setup stage elapsed time is " << 
    			st_float_ms.count() << " milliseconds" << std::endl;
			}	

			{
				auto start = std::chrono::high_resolution_clock::now();


				eval.protocolComputeStageEval();
				auto end = std::chrono::high_resolution_clock::now();

		    	std::chrono::duration<double, std::milli> float_ms = end - start;

    			std::cout << "Total Computation stage elapsed time is " << 
    			float_ms.count() << " milliseconds" << std::endl;
    		}

    		eval.protocolVerificationStage();
    		if(eval.verifyWinnerClaim() == true)
    		{
    			printf("Winner verification is successful\n");
    		}
    		else
    			printf("Winner verification is failure\n");	
			break;
		}
		case pBidder:
		{
			
			Bidder bidder = Bidder((D+100*id), bidvalue, D, ADDR_Verify, id, bb);
			bidder.protocolSetupStage();
			bidder.protocolComputeStageBidder();
			bidder.protocolVerificationStage();
			
			break;	
		}
		case pVerifier:
		{
			Verify ver = Verify(bb);
			ver.runVerify();
			
			break;
		}
		default:
			cout << "Unrecognized types" << endl;
	}

	return 0;
}

