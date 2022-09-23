#ifndef GROUP_H
#define GROUP_H

#include <openssl/obj_mac.h>

#include <openssl/ec.h>

#define MAX_BIG_NUM_SIZE 32

using namespace::std;

class Group;
class GroupElement;
class Encoder;
typedef struct t_grpPoint
{
	unsigned char gx[MAX_BIG_NUM_SIZE];
	uint xn;
	unsigned char gy[MAX_BIG_NUM_SIZE];
	uint yn;
} GrpPoint;

typedef unsigned char zqPoint[MAX_BIG_NUM_SIZE];

class GroupElement
{
public:
	GroupElement(){}
	

	GroupElement(EC_POINT *element, Group *_grp);
	GroupElement(Group *_grp, GrpPoint *_gpt);
	GroupElement(Group* grp);
	~GroupElement()	
	{
		EC_POINT_clear_free(ep);

	}
	void setPoint();

	void gPrint(unsigned char *c, uint num);
	void printGroupPoint(GrpPoint *gpt);

	
	EC_POINT *ep;
	Group *grp;
	GrpPoint gpt;

private:
	
	friend class Group;
	friend class Encoder;

};

class Group
{
public:

		friend class GroupElement;
		friend class Encoder;

		~Group()
		{
			delete g;
			delete h;
			delete ident;
			delete g1;
			BN_free(q);
		}


		/*
		 * nid: NID of the curve
		 */
		
		Group(int nid )
		{
			ecg = EC_GROUP_new_by_curve_name(nid);
			initGroup();
		}
	

		
		void initGroup()
		{
			BN_CTX *ctx = BN_CTX_new();
    		BIGNUM *k; 
			
			EC_POINT *i = EC_POINT_new(ecg);
			BIGNUM *x = BN_new();
			BIGNUM *y = BN_new();
			BN_set_word(x, 0);
			BN_set_word(y, 0);
			
			EC_POINT_set_affine_coordinates(ecg, i, x, y,ctx);
			ident = new GroupElement(i, this);

    		k = BN_new(); // Place holder for the order of group
			EC_GROUP_get_order(ecg, k, ctx);
			q = BN_new();
			q = k;
			//printf("q = \n");
			//BN_print_fp(stdout, q);

			
			numBitsInOrder = BN_num_bits(k);
			EC_POINT *ecpg = (EC_POINT *) EC_GROUP_get0_generator(ecg);
			g = new GroupElement(ecpg, this);

			//printf("g = \n");
			//printGroupElement(g);


			EC_POINT *ecph = (EC_POINT *) EC_POINT_dup(ecpg, ecg);
			EC_POINT_dbl(ecg, ecph, g->ep,NULL);

			h = new GroupElement(ecph, this);	

			EC_POINT_dbl(ecg, ecph, h->ep,NULL);

			g1 = new GroupElement(ecph, this);		
			
			if(EC_POINT_is_at_infinity(ecg, h->ep) ==1)
			{
				printf("h is a point at infinity\n");
			}
			if(EC_POINT_set_to_infinity(ecg, ident->ep) == 0)
			{
				printf("Setting point to infinity failed\n");
			}
#ifdef DEBUG			
			
			printf("****Group initialized****\n");
			printGroupParams();
#endif			
		}
		
		uint power(GroupElement *ret, GroupElement *g, BIGNUM *r);

		GroupElement* getRandomGroupElement();
		int getGroupDegree();
		GroupElement* GroupMultiply(GroupElement base, const BIGNUM *exp);
		uint elementMultiply(GroupElement *ret, GroupElement *a, GroupElement *b);

		GroupElement *multiElementMultiply(GroupElement* gelem[], uint id);
		uint compareElements(GroupElement *a, GroupElement *b);

		void printGroupElement(GroupElement *p);
		
		BIGNUM * getRandomNumber();

		uint getInverse(GroupElement *element);
		void printECPoint(EC_POINT* ep);
		void printGroupParams();
		void dupGroupElement(GroupElement *d, GroupElement *s);


		GroupElement *g; //generator
		GroupElement *g1; //second generator
		GroupElement *h; //Group Element used for Commitments

		GroupElement *ident;

		BIGNUM *q;
		int numBitsInOrder;
		EC_GROUP *ecg;


private:
	Group()	{} // Default constructor not accessible
	


};
#endif
