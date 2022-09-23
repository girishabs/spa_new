#include <iostream>
#include "common.h"

#include "group.h"


GroupElement::GroupElement(Group *_grp)
{
	grp = _grp;
	ep = EC_POINT_new(grp->ecg);
}

GroupElement::GroupElement(EC_POINT *element, Group *_grp)
{
	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();
	grp = _grp;

	ep = element;
	EC_POINT_get_affine_coordinates(grp->ecg, ep, x, y, NULL);
	
	gpt.xn = BN_bn2bin(x, gpt.gx);
	gpt.yn = BN_bn2bin(y, gpt.gy);
	BN_free(x);
	BN_free(y);
}
GroupElement::GroupElement(Group *_grp, GrpPoint *_gpt)
{
	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();

	grp = _grp;

	gpt = *_gpt;
	BN_bin2bn(gpt.gx,gpt.xn,x);
	BN_bin2bn(gpt.gy,gpt.yn,y);
	
	ep = EC_POINT_new(grp->ecg);
	if(EC_POINT_set_affine_coordinates(grp->ecg, ep, x, y, NULL) == 0)
	{	
		printf("ERROR occurred while setting affine coordinates\n");
		printGroupPoint(_gpt);
	}
}

void GroupElement::setPoint()
{
	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();
	BN_CTX *ctx = BN_CTX_new();

	
	EC_POINT_get_affine_coordinates(grp->ecg, ep, x, y, ctx);
	
	gpt.xn = BN_bn2bin(x, gpt.gx);
	gpt.yn = BN_bn2bin(y, gpt.gy);	
	BN_free(x);
	BN_free(y);
	BN_CTX_free(ctx);
}

void GroupElement::gPrint(unsigned char *c, uint num)
{
	for (uint i = 0; i < num; i++)
	{
		printf("%02X",c[i]);
	}
	cout << endl;
	//cout << num << " bytes" << endl;
}

void GroupElement::printGroupPoint(GrpPoint *gpt)
{
	if(gpt->xn > MAX_BIG_NUM_SIZE || gpt->yn > MAX_BIG_NUM_SIZE)
	{	
		printf("Group point seems corrupted. Not printg\n");
		return;
	}	

	printf("x = ");

	gPrint(gpt->gx, gpt->xn);
   	cout << "\tand" << endl << "y = ";

   	gPrint(gpt->gy, gpt->yn);
   	cout << endl;
}
void Group::dupGroupElement(GroupElement *d, GroupElement *s)
{
	d->ep = EC_POINT_dup(s->ep, ecg);
	d->setPoint();
}

GroupElement* Group::getRandomGroupElement() 
{
    BIGNUM *k = getRandomNumber(); 
    GroupElement *r = new GroupElement(this);

    if (!EC_POINT_mul(ecg,r->ep,k,r->ep,k,NULL)) 
    {
		printf("Something went wrong with get point mul\n");
   		BN_free(k);
  		return NULL; 
    } 
	return r;
}	




int Group::getGroupDegree()
{
	return EC_GROUP_get_degree(ecg);
}

void Group::printGroupElement(GroupElement* p)
{
	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();
	
	EC_POINT_get_affine_coordinates(ecg, p->ep, x, y, NULL);
	printf("x = ");
	BN_print_fp(stdout, x);
   	cout << "\tand" << endl << "y = ";
   	BN_print_fp(stdout, y);
   	cout << endl;
    BN_free(x);
    BN_free(y);
}


/** Computes the product of two group elements
 *  \param  group  underlying group object
 *  \param  c    GroupElement object for the result (r = a * b)
 *  \param  a      GroupElement object with the first multiplicand
 *  \param  b      GroupElement object with the second multiplicand
 *  \param  ctx    BN_CTX object (optional)
 *  \return c on success and NULL if an error occurred
 */		



uint Group::elementMultiply(GroupElement *ret, GroupElement *a, GroupElement *b)
{

	if(EC_POINT_add(ecg, ret->ep,  a->ep, b->ep, NULL) == 0)
	{
		printf("Group: Error in elementMultiply\n");
		return 0;
	}
	//printf("Inside elementMultiply\n");
	//printECPoint(ret->ep);
	ret->setPoint();
	return 1;
}

/** Computes r = generator * n + q * m
 *  \param  group  underlying EC_GROUP object
 *  \param  r      EC_POINT object for the result
 *  \param  n      BIGNUM with the multiplier for the group generator (optional)
 *  \param  q      EC_POINT object with the first factor of the second summand
 *  \param  m      BIGNUM with the second factor of the second summand
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */

uint Group::power(GroupElement *ret, GroupElement *base, BIGNUM *exp)
{
	if(EC_POINT_mul(ecg, ret->ep, NULL, base->ep, exp, NULL) == 0) 
	{
		printf("Group: Error in power\n");
		return 0;
	}
	ret->setPoint();
	return 1;
}

/** Gets a random element from Z_q **/

BIGNUM * Group::getRandomNumber()
{
	BN_CTX *ctx = NULL;
    BIGNUM *k; 
      
    k = BN_new(); // Place holder for the order of group

	if (!BN_pseudo_rand(k, numBitsInOrder, 0, 0))
	{
		printf("Something went wrong with get pseudorand\n");
		return NULL;
    } 
    return k;
}

/** Computes ret = \prod_{i=0}^{num-1} p[i] ^ m[i]
 *  \param  group  underlying group object
 *  \param  ret      GroupElement object for the result
 *  \param  num    number further multiplicands
 *  \param  p      array of size num of GroupElement objects
 *  \param  m      array of size num of BIGNUM objects
 *  \param  ctx    BN_CTX object (optional)
 *  \return GroupElement pointer on success and NULL if an error occurred
 */

 
GroupElement *Group::multiElementMultiply(GroupElement* gelem[], uint id)
{
	GroupElement *ret = new GroupElement(this);
	EC_POINT *p[MAX_BIDDERS];
	BIGNUM *m[MAX_BIDDERS];
	BIGNUM *n;
	BN_set_word(n, 0);

	for(uint i = 0; i < id; i++)
	{

		p[i] = gelem[i]->ep;
		BN_set_word(m[i], 1);
	}

	if(EC_POINTs_mul(ecg, ret->ep, n, id, (const EC_POINT **)p, (const BIGNUM **)m, NULL) == 0)
	{
		printf("Group: Error in multiElementMultiply\n");
		return NULL;
	}
	return ret;
}

/** Computes the inverse of a EC_POINT
 *  \param  group  underlying EC_GROUP object
 *  \param  a      EC_POINT object to be inverted (it's used for the result as well)
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
uint Group::getInverse(GroupElement *e)
{
	if(EC_POINT_invert(ecg, e->ep, NULL) == 0)
	{
		printf("Group: Error in getInverse\n");
		return 0;
	}
	e->setPoint();
	return 1;
}
/** Compares two GroupElements
 *  \param  a      first GroupElement object
 *  \param  b      second GroupElement object
 *  \return 1 if the points are not equal, 0 if they are, or -1 on error
 */
uint Group::compareElements(GroupElement *a, GroupElement *b)
{
	return(EC_POINT_cmp(ecg, a->ep, b->ep, NULL));
}

// Utility function for printing the different group parameters.

void Group::printGroupParams()
{
	printf("Identity is:\n");
	printGroupElement(ident);
	printf("Generator g is:\n");
	printGroupElement(g);
	printf("Element h is:\n");
	printGroupElement(h);
	printf("Element g1 is:\n");
	printGroupElement(g1);
	printf("Order of Group q is:\n");
	BN_print_fp(stdout, q);
	cout << endl;

}

void Group::printECPoint(EC_POINT* ep)
{
	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();
	
	EC_POINT_get_affine_coordinates(ecg, ep, x, y, NULL);
	printf("x = ");
	BN_print_fp(stdout, x);
   	cout << "\tand" << endl << "y = ";
   	BN_print_fp(stdout, y);
   	cout << endl;
    BN_free(x);
    BN_free(y);
}
