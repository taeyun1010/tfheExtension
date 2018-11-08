#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <iostream>
#include <cstdlib>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <cassert>
#include <time.h>
#include <thread>

#include <pthread.h>

#define null 0

using namespace std;

int bitsize = 0;

// these are number of bits used for representing Double struct
int integerbitsize = 0;
int fractionbitsize = 0;
double times[10];

struct tensor{
	double var;
	struct tensor *p;
}Head,*Tail;

struct CipherSet{
	LweSample *a;
	LweSample *b;
	int minbit;
	const TFheGateBootstrappingCloudKeySet* EK;
};
struct MulInitSet{
	LweSample *C;
	LweSample *a;
	LweSample *b;
	int ind;
	const TFheGateBootstrappingCloudKeySet* EK;
};
struct CalcSet{
	LweSample *r;
	LweSample *a;
	LweSample *b;
	LweSample *c;
	const TFheGateBootstrappingCloudKeySet* EK;
};
struct Double{
	LweSample *integerpart;
	LweSample *fractionpart;
};
TFheGateBootstrappingSecretKeySet* testkey;
int V = 0;
void *thread_and(void *arg)
{
	struct CalcSet* input = (struct CalcSet*)arg;
	bootsAND(input->r,input->a,input->b,input->EK);       

        pthread_exit((void *)input->r);	
}
void *thread_xor(void *arg)
{
	struct CalcSet* input = (struct CalcSet*)arg;
        bootsXOR(input->r,input->a,input->b,input->EK);

        pthread_exit((void *)input->r);
}
void *thread_mux(void *arg)
{
	struct CalcSet* input = (struct CalcSet*)arg;
	bootsMUX(input->r,input->a,input->b,input->c,input->EK);
	
        pthread_exit((void *)input->r);
}

void *thread_not(void *arg)
{
        struct CalcSet* input = (struct CalcSet*)arg;
        bootsNOT(input->r,input->a,input->EK);

        pthread_exit((void *)input->r);
}

// decrypts given LweSample
int decryptLweSample(LweSample* input, TFheGateBootstrappingSecretKeySet* key){
	int Result = 0;
	for(int i=0;i<bitsize;i++)
	{
		Result<<=1;
		Result+=bootsSymDecrypt(&input[i],key);
	}	
	return Result;
}


// decrypts given integer part of Double struct
int decryptIntegerpart(LweSample* input, TFheGateBootstrappingSecretKeySet* key){
	int Result = 0;
	for(int i=0;i<integerbitsize;i++)
	{
		// //
		// int intermediateBit = bootsSymDecrypt(&input[i],key);
		// cout << "intermediateBit = " << intermediateBit << endl;
		// //
		
		Result<<=1;
		Result+=bootsSymDecrypt(&input[i],key);
	}	
	return Result;
}

// decrypts given fractional part of Double struct
double decryptFractionpart(LweSample* input, TFheGateBootstrappingSecretKeySet* key){
	double result = 0;
	for(int i=0;i<fractionbitsize;i++)
	{
		int temp = bootsSymDecrypt(&input[i],key);
		cout << "temp[" << i << "] = " << temp << endl;
		result += temp * (pow(2, -(i+1)));
	}	
	return result;
}

// decrypts given Double struct
double decryptDouble(Double d, TFheGateBootstrappingSecretKeySet* key){
	double result;
	LweSample* integerpart = d.integerpart;
	LweSample* fractionpart = d.fractionpart;
	int decryptedintpart = decryptIntegerpart(integerpart, key);
	cout << "decryptedintpart = " << decryptedintpart << endl;
	double decryptedfracpart = decryptFractionpart(fractionpart, key);
	cout << "decryptedfracpart = " << decryptedfracpart << endl;
	result = decryptedintpart + decryptedfracpart;
	return result;
}


LweSample* CipherCmp(LweSample *a,LweSample *b,const TFheGateBootstrappingCloudKeySet* EK)
{
	LweSample *Tmp = new_gate_bootstrapping_ciphertext(EK->params);
	LweSample *Result = new_gate_bootstrapping_ciphertext(EK->params);

	bootsCONSTANT(Result,0,EK);

	for(int i = 0 ; i < bitsize ; i++)
	{
		bootsXOR(Tmp,&a[i],&b[i],EK);
		bootsOR(Result,Result,Tmp,EK);
	}
	bootsNOT(Result,Result,EK);	
	return Result;
}
LweSample* CipherAdd(LweSample* a,LweSample* b,const TFheGateBootstrappingCloudKeySet* EK)
{
	LweSample *carry = new_gate_bootstrapping_ciphertext(EK->params);
	LweSample *Result = new_gate_bootstrapping_ciphertext_array(bitsize,EK->params);
	
	pthread_t thread[2];
	struct CalcSet *in[2];

	for(int i= bitsize-1 ; i >= 0 ; i--)
	{
		if(i == bitsize-1)
		{

			LweSample *b1,*b2;
			b1 = new_gate_bootstrapping_ciphertext(EK->params);
			b2 = new_gate_bootstrapping_ciphertext(EK->params);		

			for(int num =0 ; num<2; num++)	in[num]= (struct CalcSet*)malloc(sizeof(struct CalcSet));

			in[0]->r = carry;
			in[0]->a = &a[i];
			in[0]->b = &b[i];
			in[0]->EK= EK;

			in[1]->r = &Result[i];
			in[1]->a = &a[i];
			in[1]->b = &b[i];
			in[1]->EK= EK;

			pthread_create(&thread[0],NULL,&thread_and,(void*)in[0]); // Function for getting carry... 
			pthread_create(&thread[1],NULL,&thread_xor,(void*)in[1]); // Function for getting bit...
			
			pthread_join(thread[0],(void **)&b1);
			pthread_join(thread[1],(void **)&b2);

			//bootsAND(carry,&a[i],&b[i],EK);
			//bootsXOR(&Result[i],&a[i],&b[i],EK);
		}
		else
		{
                        for(int num =0 ; num<2; num++)  in[num]= (struct CalcSet*)malloc(sizeof(struct CalcSet));

			LweSample *b1;
			b1 = new_gate_bootstrapping_ciphertext(EK->params);
			bootsXOR(b1,&a[i],&b[i],EK);
			
			LweSample *b2 = new_gate_bootstrapping_ciphertext(EK->params);
			bootsCOPY(b2,carry,EK);			

			in[0]->r = &Result[i];
			in[0]->a = b1;
			in[0]->b = b2;
			in[0]->EK= EK;

			in[1]->r = carry;
			in[1]->a = b1;
			in[1]->b = b2;
			in[1]->c = &a[i];
			in[1]->EK= EK;

			pthread_create(&thread[0],NULL,&thread_xor,(void*)in[0]);
			pthread_create(&thread[1],NULL,&thread_mux,(void*)in[1]);

			pthread_join(thread[0],(void **)&b1);
			pthread_join(thread[1],(void **)&b2);

			//bootsXOR(&Result[i],b1,carry,EK);
			//bootsMUX(carry,b1,carry,&a[i],EK);

		}
	}

	return Result;
}

//add function used for addition of Double
LweSample* CipherAddDoubleHelper(LweSample* a,LweSample* b,const TFheGateBootstrappingCloudKeySet* EK)
{
	LweSample *carry = new_gate_bootstrapping_ciphertext(EK->params);
	LweSample *Result = new_gate_bootstrapping_ciphertext_array(integerbitsize + fractionbitsize,EK->params);
	
	pthread_t thread[2];
	struct CalcSet *in[2];

	for(int i= integerbitsize + fractionbitsize-1 ; i >= 0 ; i--)
	{
		if(i == integerbitsize + fractionbitsize-1)
		{

			LweSample *b1,*b2;
			b1 = new_gate_bootstrapping_ciphertext(EK->params);
			b2 = new_gate_bootstrapping_ciphertext(EK->params);		

			for(int num =0 ; num<2; num++)	in[num]= (struct CalcSet*)malloc(sizeof(struct CalcSet));

			in[0]->r = carry;
			in[0]->a = &a[i];
			in[0]->b = &b[i];
			in[0]->EK= EK;

			in[1]->r = &Result[i];
			in[1]->a = &a[i];
			in[1]->b = &b[i];
			in[1]->EK= EK;

			pthread_create(&thread[0],NULL,&thread_and,(void*)in[0]); // Function for getting carry... 
			pthread_create(&thread[1],NULL,&thread_xor,(void*)in[1]); // Function for getting bit...
			
			pthread_join(thread[0],(void **)&b1);
			pthread_join(thread[1],(void **)&b2);

			//bootsAND(carry,&a[i],&b[i],EK);
			//bootsXOR(&Result[i],&a[i],&b[i],EK);
		}
		else
		{
                        for(int num =0 ; num<2; num++)  in[num]= (struct CalcSet*)malloc(sizeof(struct CalcSet));

			LweSample *b1;
			b1 = new_gate_bootstrapping_ciphertext(EK->params);
			bootsXOR(b1,&a[i],&b[i],EK);
			
			LweSample *b2 = new_gate_bootstrapping_ciphertext(EK->params);
			bootsCOPY(b2,carry,EK);			

			in[0]->r = &Result[i];
			in[0]->a = b1;
			in[0]->b = b2;
			in[0]->EK= EK;

			in[1]->r = carry;
			in[1]->a = b1;
			in[1]->b = b2;
			in[1]->c = &a[i];
			in[1]->EK= EK;

			pthread_create(&thread[0],NULL,&thread_xor,(void*)in[0]);
			pthread_create(&thread[1],NULL,&thread_mux,(void*)in[1]);

			pthread_join(thread[0],(void **)&b1);
			pthread_join(thread[1],(void **)&b2);

			//bootsXOR(&Result[i],b1,carry,EK);
			//bootsMUX(carry,b1,carry,&a[i],EK);

		}
	}

	return Result;
}

// //adds two double, given two Double structs
// // TODO: get rid of key argument
// Double CipherAddDouble(Double input1, Double input2, const TFheGateBootstrappingCloudKeySet* EK, TFheGateBootstrappingSecretKeySet* key)
// {
// 	Double result;
// 	LweSample* a = new_gate_bootstrapping_ciphertext_array(integerbitsize + fractionbitsize,EK->params);
// 	LweSample* b = new_gate_bootstrapping_ciphertext_array(integerbitsize + fractionbitsize,EK->params);

// 	//
// 	LweSample* c = new_gate_bootstrapping_ciphertext_array(integerbitsize + fractionbitsize,EK->params);
// 	LweSample* d = new_gate_bootstrapping_ciphertext_array(integerbitsize + fractionbitsize,EK->params);
// 	//


// 	for (int i=0; i < integerbitsize; i++){
// 		bootsCOPY(&a[i],&input1.integerpart[i],EK);
// 		bootsCOPY(&b[i],&input2.integerpart[i],EK);
// 	}
// 	for (int i=integerbitsize; i < (integerbitsize + fractionbitsize); i++){
// 		bootsCOPY(&a[i],&input1.fractionpart[i-integerbitsize],EK);
// 		bootsCOPY(&b[i],&input2.fractionpart[i-integerbitsize],EK);

// 		bootsCOPY(&c[i],&input1.fractionpart[i-integerbitsize],EK);
// 		bootsCOPY(&d[i],&input2.fractionpart[i-integerbitsize],EK);

// 	}

// 	// //
// 	// for (int i=0; i < fractionbitsize; i++){
// 	// 	bootsCOPY(&c[i],&input1.fractionpart[i],EK);
// 	// 	bootsCOPY(&d[i],&input2.fractionpart[i],EK);

// 	// }
// 	// //


// 	// LweSample *sum = new_gate_bootstrapping_ciphertext_array(integerbitsize + fractionbitsize,EK->params);
// 	LweSample *sum2 = new_gate_bootstrapping_ciphertext_array(fractionbitsize,EK->params);
	
	
// 	// sum = CipherAdd(a,b, EK);

// 	sum2 = CipherAdd(c+integerbitsize,d+integerbitsize, EK);

	
// 	// result.integerpart = sum;
// 	// result.fractionpart = sum + integerbitsize; 

// 	// double temp = decryptFractionpart(result.fractionpart, key);
// 	// cout << "temp = " << temp << endl;

// 	double temp = decryptFractionpart(c+integerbitsize, key);
// 	cout << "temp = " << temp << endl;
// 	temp = decryptFractionpart(d+integerbitsize, key);
// 	cout << "temp = " << temp << endl;

// 	temp = decryptFractionpart(sum2, key);
// 	cout << "temp = " << temp << endl;

// 	return result;
// }

//adds two double, given two Double structs
Double CipherAddDouble(Double input1, Double input2, const TFheGateBootstrappingCloudKeySet* EK)
{
	Double result;
	LweSample* a = new_gate_bootstrapping_ciphertext_array(integerbitsize + fractionbitsize,EK->params);
	LweSample* b = new_gate_bootstrapping_ciphertext_array(integerbitsize + fractionbitsize,EK->params);

	// //
	// LweSample* c = new_gate_bootstrapping_ciphertext_array(integerbitsize + fractionbitsize,EK->params);
	// LweSample* d = new_gate_bootstrapping_ciphertext_array(integerbitsize + fractionbitsize,EK->params);
	// //


	for (int i=0; i < integerbitsize; i++){
		bootsCOPY(&a[i],&input1.integerpart[i],EK);
		bootsCOPY(&b[i],&input2.integerpart[i],EK);
	}
	for (int i=integerbitsize; i < (integerbitsize + fractionbitsize); i++){
		bootsCOPY(&a[i],&input1.fractionpart[i-integerbitsize],EK);
		bootsCOPY(&b[i],&input2.fractionpart[i-integerbitsize],EK);

		// //
		// int decryptedbit = bootsSymDecrypt(&a[i],key);
		// cout << "decryptedbit[" << i << "] = " << decryptedbit << endl;
		// //

		// bootsCOPY(&c[i],&input1.fractionpart[i-integerbitsize],EK);
		// bootsCOPY(&d[i],&input2.fractionpart[i-integerbitsize],EK);

	}
	// double decryptedfraction = decryptFractionpart(&a[integerbitsize], key);
	// cout << "decryptedfraction = " << decryptedfraction << endl;
	// double decryptedfraction2 = decryptFractionpart(&b[integerbitsize], key);
	// cout << "decryptedfraction2 = " << decryptedfraction2 << endl;
	// //
	// for (int i=0; i < fractionbitsize; i++){
	// 	bootsCOPY(&c[i],&input1.fractionpart[i],EK);
	// 	bootsCOPY(&d[i],&input2.fractionpart[i],EK);

	// }
	// //


	LweSample *sum = new_gate_bootstrapping_ciphertext_array(integerbitsize + fractionbitsize,EK->params);
	// LweSample *sum2 = new_gate_bootstrapping_ciphertext_array(fractionbitsize,EK->params);
	
	
	sum = CipherAddDoubleHelper(a,b, EK);

	// sum2 = CipherAdd(a+integerbitsize,b+integerbitsize, EK);

	
	result.integerpart = sum;
	result.fractionpart = sum + integerbitsize; 

	// int intsum = decryptIntegerpart(&sum[0], key);
	// cout << "intsum = " << intsum << endl;

	// double temp = decryptFractionpart(&sum[integerbitsize], key);
	// cout << "temp = " << temp << endl;

	// double temp = decryptFractionpart(result.fractionpart, key);
	// cout << "temp = " << temp << endl;

	// double temp = decryptFractionpart(c+integerbitsize, key);
	// cout << "temp = " << temp << endl;
	// temp = decryptFractionpart(d+integerbitsize, key);
	// cout << "temp = " << temp << endl;

	// double temp = decryptFractionpart(sum2, key);
	// cout << "temp = " << temp << endl;

	return result;
}

LweSample* CipherAdd(LweSample* a,LweSample* b,const TFheGateBootstrappingCloudKeySet* EK,int minbit) // special Add functions used for Multiplications
{

        LweSample *carry = new_gate_bootstrapping_ciphertext(EK->params);
        LweSample *Result = new_gate_bootstrapping_ciphertext_array(bitsize,EK->params);

	pthread_t thread[2];
        struct CalcSet *in[2];


	for(int i= bitsize-1; i>minbit ; i--)
	{
		bootsCOPY(&Result[i],&a[i],EK);
	}

        for(int i= minbit ; i >= 0 ; i--)
        {
                if(i == minbit)
                {
                        bootsAND(carry,&a[i],&b[i],EK);
                        bootsXOR(&Result[i],&a[i],&b[i],EK);
                }
                else
                {

			for(int num =0 ; num<2; num++)  in[num]= (struct CalcSet*)malloc(sizeof(struct CalcSet));

                        LweSample *b1;
                        b1 = new_gate_bootstrapping_ciphertext(EK->params);
                        bootsXOR(b1,&a[i],&b[i],EK);

			LweSample *b2 = new_gate_bootstrapping_ciphertext(EK->params);
                        bootsCOPY(b2,carry,EK);

                        in[0]->r = &Result[i];
                        in[0]->a = b1;
                        in[0]->b = b2;
                        in[0]->EK= EK;

                        in[1]->r = carry;
                        in[1]->a = b1;
                        in[1]->b = b2;
                        in[1]->c = &a[i];
                        in[1]->EK= EK;

                        pthread_create(&thread[0],NULL,&thread_xor,(void*)in[0]);
                        pthread_create(&thread[1],NULL,&thread_mux,(void*)in[1]);

                        pthread_join(thread[0],(void **)&b1);
                        pthread_join(thread[1],(void **)&b2);


                        //bootsXOR(&Result[i],b1,carry,EK);
                        //bootsMUX(carry,b1,carry,&a[i],EK);
                }
        }
        
	return Result;
}

LweSample* CipherAddDoubleHelper(LweSample* a,LweSample* b,const TFheGateBootstrappingCloudKeySet* EK,int minbit) // special Add functions used for Multiplications
{

        LweSample *carry = new_gate_bootstrapping_ciphertext(EK->params);
        LweSample *Result = new_gate_bootstrapping_ciphertext_array((integerbitsize + fractionbitsize),EK->params);

	pthread_t thread[2];
        struct CalcSet *in[2];


	for(int i= (integerbitsize + fractionbitsize)-1; i>minbit ; i--)
	{
		bootsCOPY(&Result[i],&a[i],EK);
	}

        for(int i= minbit ; i >= 0 ; i--)
        {
                if(i == minbit)
                {
                        bootsAND(carry,&a[i],&b[i],EK);
                        bootsXOR(&Result[i],&a[i],&b[i],EK);
                }
                else
                {

			for(int num =0 ; num<2; num++)  in[num]= (struct CalcSet*)malloc(sizeof(struct CalcSet));

                        LweSample *b1;
                        b1 = new_gate_bootstrapping_ciphertext(EK->params);
                        bootsXOR(b1,&a[i],&b[i],EK);

			LweSample *b2 = new_gate_bootstrapping_ciphertext(EK->params);
                        bootsCOPY(b2,carry,EK);

                        in[0]->r = &Result[i];
                        in[0]->a = b1;
                        in[0]->b = b2;
                        in[0]->EK= EK;

                        in[1]->r = carry;
                        in[1]->a = b1;
                        in[1]->b = b2;
                        in[1]->c = &a[i];
                        in[1]->EK= EK;

                        pthread_create(&thread[0],NULL,&thread_xor,(void*)in[0]);
                        pthread_create(&thread[1],NULL,&thread_mux,(void*)in[1]);

                        pthread_join(thread[0],(void **)&b1);
                        pthread_join(thread[1],(void **)&b2);


                        //bootsXOR(&Result[i],b1,carry,EK);
                        //bootsMUX(carry,b1,carry,&a[i],EK);
                }
        }
        
	return Result;
}

// LweSample* CipherSub(LweSample* a,LweSample* b,const TFheGateBootstrappingCloudKeySet* EK)
// {
// 	LweSample *carry = new_gate_bootstrapping_ciphertext(EK->params);
// 	LweSample *O = new_gate_bootstrapping_ciphertext(EK->params);
// 	LweSample *Rev = new_gate_bootstrapping_ciphertext_array(bitsize,EK->params);
// 	LweSample *Arv = new_gate_bootstrapping_ciphertext_array(bitsize,EK->params);

// 	bootsCONSTANT(O,1,EK);

// 	/** Reversing bits of b **/

// 	for(int i = 0; i < bitsize ; i++)
// 	{
// 		bootsNOT(&Rev[i],&b[i],EK);
// 	}

// 	/** Add one to Reversed bit form of b **/

// 	for(int i = bitsize-1 ; i >= 0 ; i--)
// 	{
// 		if(i == bitsize-1)
// 		{
// 			bootsAND(carry,&Rev[i],O,EK);
// 			bootsXOR(&Arv[i],&Rev[i],O,EK);
// 		}
// 		else
// 		{
// 			bootsXOR(&Arv[i],&Rev[i],carry,EK);
// 			bootsAND(carry,carry,&Rev[i],EK);
// 		}
// 	}
	
// 	return CipherAdd(a,Arv,EK);
// }

LweSample* CipherSub(LweSample* a,LweSample* b,const TFheGateBootstrappingCloudKeySet* EK)
{
	LweSample *carry = new_gate_bootstrapping_ciphertext(EK->params);
	LweSample *Rev = new_gate_bootstrapping_ciphertext_array(bitsize,EK->params);
	LweSample *Result = new_gate_bootstrapping_ciphertext_array(bitsize,EK->params);

	int *x;
	/** Reversing bits of b **/
	pthread_t thread[bitsize];
	for(int i = 0; i < bitsize ; i++)
	{
		struct CalcSet *in;
		in = (struct CalcSet*)malloc(sizeof(struct CalcSet));
		in->r = &Rev[i];
		in->a = &b[i];
		in->EK= EK;		
		pthread_create(&thread[i],NULL,&thread_not,(void*)in);
		//bootsNOT(&Rev[i],&b[i],EK);
	}
	for(int i = 0; i < bitsize ; i++)	pthread_join(thread[i],(void **)&x);
	
	for(int i= bitsize-1 ; i >= 0 ; i--)
        {
                if(i == bitsize-1)
                {
			bootsCONSTANT(carry,1,EK);
                }
		struct CalcSet *in[2];
                for(int num =0 ; num<2; num++)  in[num]= (struct CalcSet*)malloc(sizeof(struct CalcSet));

                LweSample *b1;
                b1 = new_gate_bootstrapping_ciphertext(EK->params);
                bootsXOR(b1,&a[i],&Rev[i],EK);

                LweSample *b2 = new_gate_bootstrapping_ciphertext(EK->params);
                bootsCOPY(b2,carry,EK);

                in[0]->r = &Result[i];
                in[0]->a = b1;
                in[0]->b = b2;
                in[0]->EK= EK;

                in[1]->r = carry;
                in[1]->a = b1;
                in[1]->b = b2;
                in[1]->c = &a[i];
                in[1]->EK= EK;

                pthread_create(&thread[0],NULL,&thread_xor,(void*)in[0]);
                pthread_create(&thread[1],NULL,&thread_mux,(void*)in[1]);

                pthread_join(thread[0],(void **)&b1);
                pthread_join(thread[1],(void **)&b2);

 
                //bootsXOR(&Result[i],b1,carry,EK);
                //bootsMUX(carry,b1,carry,&a[i],EK);
        }
	return Result;
}

//sub function used for subtraction of Doubles
//TODO: replace this with optimized version
LweSample* CipherSubDoubleHelper(LweSample* a,LweSample* b,const TFheGateBootstrappingCloudKeySet* EK)
{
	LweSample *carry = new_gate_bootstrapping_ciphertext(EK->params);
	LweSample *O = new_gate_bootstrapping_ciphertext(EK->params);
	LweSample *Rev = new_gate_bootstrapping_ciphertext_array(integerbitsize + fractionbitsize,EK->params);
	LweSample *Arv = new_gate_bootstrapping_ciphertext_array(integerbitsize + fractionbitsize,EK->params);

	bootsCONSTANT(O,1,EK);

	/** Reversing bits of b **/

	for(int i = 0; i < (integerbitsize + fractionbitsize) ; i++)
	{
		bootsNOT(&Rev[i],&b[i],EK);
	}

	/** Add one to Reversed bit form of b **/

	for(int i = integerbitsize + fractionbitsize-1 ; i >= 0 ; i--)
	{
		if(i == integerbitsize + fractionbitsize-1)
		{
			bootsAND(carry,&Rev[i],O,EK);
			bootsXOR(&Arv[i],&Rev[i],O,EK);
		}
		else
		{
			bootsXOR(&Arv[i],&Rev[i],carry,EK);
			bootsAND(carry,carry,&Rev[i],EK);
		}
	}
	
	return CipherAddDoubleHelper(a,Arv,EK);
}

//subtracts two double, given two Double structs
//TODO: use newly created optimized version of CipherSubDoubleHelper
Double CipherSubDouble(Double input1, Double input2, const TFheGateBootstrappingCloudKeySet* EK)
{
	Double result;
	LweSample* a = new_gate_bootstrapping_ciphertext_array(integerbitsize + fractionbitsize,EK->params);
	LweSample* b = new_gate_bootstrapping_ciphertext_array(integerbitsize + fractionbitsize,EK->params);

	// //
	// LweSample* c = new_gate_bootstrapping_ciphertext_array(integerbitsize + fractionbitsize,EK->params);
	// LweSample* d = new_gate_bootstrapping_ciphertext_array(integerbitsize + fractionbitsize,EK->params);
	// //


	for (int i=0; i < integerbitsize; i++){
		bootsCOPY(&a[i],&input1.integerpart[i],EK);
		bootsCOPY(&b[i],&input2.integerpart[i],EK);
	}
	for (int i=integerbitsize; i < (integerbitsize + fractionbitsize); i++){
		bootsCOPY(&a[i],&input1.fractionpart[i-integerbitsize],EK);
		bootsCOPY(&b[i],&input2.fractionpart[i-integerbitsize],EK);

		// //
		// int decryptedbit = bootsSymDecrypt(&a[i],key);
		// cout << "decryptedbit[" << i << "] = " << decryptedbit << endl;
		// //

		// bootsCOPY(&c[i],&input1.fractionpart[i-integerbitsize],EK);
		// bootsCOPY(&d[i],&input2.fractionpart[i-integerbitsize],EK);

	}
	// double decryptedfraction = decryptFractionpart(&a[integerbitsize], key);
	// cout << "decryptedfraction = " << decryptedfraction << endl;
	// double decryptedfraction2 = decryptFractionpart(&b[integerbitsize], key);
	// cout << "decryptedfraction2 = " << decryptedfraction2 << endl;
	// //
	// for (int i=0; i < fractionbitsize; i++){
	// 	bootsCOPY(&c[i],&input1.fractionpart[i],EK);
	// 	bootsCOPY(&d[i],&input2.fractionpart[i],EK);

	// }
	// //


	LweSample *difference = new_gate_bootstrapping_ciphertext_array(integerbitsize + fractionbitsize,EK->params);
	// LweSample *sum2 = new_gate_bootstrapping_ciphertext_array(fractionbitsize,EK->params);
	
	
	difference = CipherSubDoubleHelper(a,b, EK);

	// sum2 = CipherAdd(a+integerbitsize,b+integerbitsize, EK);

	
	result.integerpart = difference;
	result.fractionpart = difference + integerbitsize; 

	// int intsum = decryptIntegerpart(&sum[0], key);
	// cout << "intsum = " << intsum << endl;

	// double temp = decryptFractionpart(&sum[integerbitsize], key);
	// cout << "temp = " << temp << endl;

	// double temp = decryptFractionpart(result.fractionpart, key);
	// cout << "temp = " << temp << endl;

	// double temp = decryptFractionpart(c+integerbitsize, key);
	// cout << "temp = " << temp << endl;
	// temp = decryptFractionpart(d+integerbitsize, key);
	// cout << "temp = " << temp << endl;

	// double temp = decryptFractionpart(sum2, key);
	// cout << "temp = " << temp << endl;

	return result;
}

void *thread_adder(void *arg)
{
        struct CipherSet* input = (struct CipherSet*)arg;


        LweSample* Ret = CipherAdd(input->a,input->b,input->EK,input->minbit);

	pthread_exit((void *)Ret);
}

//adder used for multiplication between Doubles
void *thread_adder_Double(void *arg)
{
        struct CipherSet* input = (struct CipherSet*)arg;


        LweSample* Ret = CipherAddDoubleHelper(input->a,input->b,input->EK,input->minbit);

	pthread_exit((void *)Ret);
}

void *thread_initializer(void *arg)
{
	struct MulInitSet* input = (struct MulInitSet*)arg;
	
	input->C = new_gate_bootstrapping_ciphertext_array(bitsize,input->EK->params);
	for(int i=input->ind;i<bitsize;i++)	bootsAND(&input->C[i-input->ind],&input->a[bitsize-1-input->ind],&input->b[i],input->EK);	
	for(int i=bitsize-input->ind;i<bitsize;i++)	bootsCONSTANT(&input->C[i],0,input->EK);
	pthread_exit((void *)input->C);
}

void *thread_initializer_Double(void *arg)
{
	struct MulInitSet* input = (struct MulInitSet*)arg;
	
	input->C = new_gate_bootstrapping_ciphertext_array((integerbitsize + fractionbitsize),input->EK->params);
	for(int i=input->ind;i<(integerbitsize + fractionbitsize);i++)	bootsAND(&input->C[i-input->ind],&input->a[(integerbitsize + fractionbitsize)-1-input->ind],&input->b[i],input->EK);	
	for(int i=(integerbitsize + fractionbitsize)-input->ind;i<(integerbitsize + fractionbitsize);i++)	bootsCONSTANT(&input->C[i],0,input->EK);
	pthread_exit((void *)input->C);
}

void *zero_initializer(void *arg)
{
        struct MulInitSet* input = (struct MulInitSet*)arg;

        input->C = new_gate_bootstrapping_ciphertext_array(bitsize,input->EK->params);
        for(int i=0;i<bitsize;i++)     bootsCONSTANT(&input->C[i],0,input->EK);
        pthread_exit((void *)input->C);
}

void *zero_initializer_Double(void *arg)
{
        struct MulInitSet* input = (struct MulInitSet*)arg;

        input->C = new_gate_bootstrapping_ciphertext_array((integerbitsize + fractionbitsize),input->EK->params);
        for(int i=0;i<(integerbitsize + fractionbitsize);i++)     bootsCONSTANT(&input->C[i],0,input->EK);
        pthread_exit((void *)input->C);
}

LweSample* CipherMul(LweSample* a,LweSample* b,const TFheGateBootstrappingCloudKeySet* EK)	// O(2*n) algorithm = about 
{
	// clock_t begin = clock();
	int bin = 1;
	while(bin<bitsize)	bin*=2;
	LweSample *Container[bin*2];
        pthread_t init[bin];

        /** Boost speed by initializing variables concurrently using threads **/

        for(int i = 0 ; i < bitsize ; i++)
        {
                struct MulInitSet *in;
                in = (struct MulInitSet*)malloc(sizeof(struct MulInitSet));
                in->C = Container[i];
                in->a = a;
                in->b = b;
                in->EK = EK;
                in->ind = i;
                pthread_create(&init[i],NULL,&thread_initializer,(void*)in);
        }
	for(int i = bitsize ; i < bin ; i++)
	{
		struct MulInitSet *in;
                in = (struct MulInitSet*)malloc(sizeof(struct MulInitSet));
                in->C = Container[i];
                in->EK = EK;
                pthread_create(&init[i],NULL,&zero_initializer,(void*)in);
	}

        /** Boost speed by using complete binary-tree based thread calculation **/


        for(int i=0;i<bin;i++)      pthread_join(init[i],(void **)&Container[i]);

        pthread_t thread[bin];

        int len = bin/2;
        int pivot = 0;
        while(len>0)
        {
                for(int i=0;i<len;i++)
                {
                        struct CipherSet *in;
                        in = (struct CipherSet*)malloc(sizeof(struct CipherSet));
                        in->a = Container[pivot+i];
                        in->b = Container[pivot+2*len-1-i];
			if(bitsize>(i+1+pivot/2))	in->minbit = i+1+pivot/2;
			else	in->minbit = bitsize-1;
                        in->EK = EK;
                        pthread_create(&thread[pivot/2+i],NULL,&thread_adder,(void *)in);
                }
                for(int i=0;i<len;i++)  pthread_join(thread[pivot/2+i],(void **)&Container[pivot+len*2+i]);
                pivot+=len*2;
                len/=2;
        }
		// clock_t end = clock();
		// double elapsed_secs = double(end - begin) / CLOCKS_PER_SEC;
		// cout << "elapsed secs to calculate a product = " << elapsed_secs << endl;
        return Container[2*bin-2];
}

LweSample* CipherMulDoubleHelper(LweSample* a,LweSample* b,const TFheGateBootstrappingCloudKeySet* EK)	// O(2*n) algorithm = about 
{
	int bin = 1;
	while(bin<(integerbitsize + fractionbitsize))	bin*=2;
	LweSample *Container[bin*2];
        pthread_t init[bin];

        /** Boost speed by initializing variables concurrently using threads **/

        for(int i = 0 ; i < (integerbitsize + fractionbitsize) ; i++)
        {
                struct MulInitSet *in;
                in = (struct MulInitSet*)malloc(sizeof(struct MulInitSet));
                in->C = Container[i];
                in->a = a;
                in->b = b;
                in->EK = EK;
                in->ind = i;
                pthread_create(&init[i],NULL,&thread_initializer_Double,(void*)in);
        }
	for(int i = integerbitsize + fractionbitsize ; i < bin ; i++)
	{
		struct MulInitSet *in;
                in = (struct MulInitSet*)malloc(sizeof(struct MulInitSet));
                in->C = Container[i];
                in->EK = EK;
                pthread_create(&init[i],NULL,&zero_initializer_Double,(void*)in);
	}

        /** Boost speed by using complete binary-tree based thread calculation **/


        for(int i=0;i<bin;i++)      pthread_join(init[i],(void **)&Container[i]);

        pthread_t thread[bin];

        int len = bin/2;
        int pivot = 0;
        while(len>0)
        {
                for(int i=0;i<len;i++)
                {
                        struct CipherSet *in;
                        in = (struct CipherSet*)malloc(sizeof(struct CipherSet));
                        in->a = Container[pivot+i];
                        in->b = Container[pivot+2*len-1-i];
			if((integerbitsize + fractionbitsize)>(i+1+pivot/2))	in->minbit = i+1+pivot/2;
			else	in->minbit = integerbitsize + fractionbitsize-1;
                        in->EK = EK;
                        pthread_create(&thread[pivot/2+i],NULL,&thread_adder_Double,(void *)in);
                }
                for(int i=0;i<len;i++)  pthread_join(thread[pivot/2+i],(void **)&Container[pivot+len*2+i]);
                pivot+=len*2;
                len/=2;
        }
        return Container[2*bin-2];
}

//TODO: delete key argument
Double CipherMulDouble(Double input1, Double input2, const TFheGateBootstrappingCloudKeySet* EK, TFheGateBootstrappingSecretKeySet* key)
{
	Double result;
	LweSample* a = new_gate_bootstrapping_ciphertext_array(integerbitsize + fractionbitsize,EK->params);
	LweSample* b = new_gate_bootstrapping_ciphertext_array(integerbitsize + fractionbitsize,EK->params);

	// //
	// LweSample* c = new_gate_bootstrapping_ciphertext_array(integerbitsize + fractionbitsize,EK->params);
	// LweSample* d = new_gate_bootstrapping_ciphertext_array(integerbitsize + fractionbitsize,EK->params);
	// //


	for (int i=0; i < integerbitsize; i++){
		bootsCOPY(&a[i],&input1.integerpart[i],EK);
		bootsCOPY(&b[i],&input2.integerpart[i],EK);
	}
	for (int i=integerbitsize; i < (integerbitsize + fractionbitsize); i++){
		bootsCOPY(&a[i],&input1.fractionpart[i-integerbitsize],EK);
		bootsCOPY(&b[i],&input2.fractionpart[i-integerbitsize],EK);

		// //
		// int decryptedbit = bootsSymDecrypt(&a[i],key);
		// cout << "decryptedbit[" << i << "] = " << decryptedbit << endl;
		// //

		// bootsCOPY(&c[i],&input1.fractionpart[i-integerbitsize],EK);
		// bootsCOPY(&d[i],&input2.fractionpart[i-integerbitsize],EK);

	}
	// double decryptedfraction = decryptFractionpart(&a[integerbitsize], key);
	// cout << "decryptedfraction = " << decryptedfraction << endl;
	// double decryptedfraction2 = decryptFractionpart(&b[integerbitsize], key);
	// cout << "decryptedfraction2 = " << decryptedfraction2 << endl;
	// //
	// for (int i=0; i < fractionbitsize; i++){
	// 	bootsCOPY(&c[i],&input1.fractionpart[i],EK);
	// 	bootsCOPY(&d[i],&input2.fractionpart[i],EK);

	// }
	// //


	// LweSample *product = new_gate_bootstrapping_ciphertext_array(integerbitsize + fractionbitsize,EK->params);
	LweSample *product;
	
	
	product = CipherMulDoubleHelper(a,b, EK);

	int decrypted = decryptLweSample(product, key);
	cout << "decrypted = " << decrypted << endl;

	// sum2 = CipherAdd(a+integerbitsize,b+integerbitsize, EK);

	
	// result.integerpart = product;
	// result.fractionpart = product + integerbitsize; 

	// int intsum = decryptIntegerpart(&sum[0], key);
	// cout << "intsum = " << intsum << endl;

	// double temp = decryptFractionpart(&sum[integerbitsize], key);
	// cout << "temp = " << temp << endl;

	// double temp = decryptFractionpart(result.fractionpart, key);
	// cout << "temp = " << temp << endl;

	// double temp = decryptFractionpart(c+integerbitsize, key);
	// cout << "temp = " << temp << endl;
	// temp = decryptFractionpart(d+integerbitsize, key);
	// cout << "temp = " << temp << endl;

	// double temp = decryptFractionpart(sum2, key);
	// cout << "temp = " << temp << endl;

	return result;
}

//helper for CipherEuclid to execute that concurrently
//TODO: delete key argument
void CipherEuclidHelper(vector<LweSample*> squares, LweSample* ciphertext1, LweSample* ciphertext2, const TFheGateBootstrappingCloudKeySet* EK, TFheGateBootstrappingSecretKeySet* key){
	LweSample* difference;
	LweSample* square;	
	difference = CipherSub(ciphertext1,ciphertext2,EK);
	square = CipherMul(difference,difference,EK);
	int result = decryptLweSample(square, key);
	cout << "square result = " << result << endl;
	squares.push_back(square);
}

void f1(int n)
{
    for (int i = 0; i < 5; ++i) {
        std::cout << "Thread 1 executing\n";
        ++n;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

// //version that uses threads
// //Given two arrays containing ciphertexts, calculate the square of Euclidean distance between them (in encrypted form)
// // REQUIRES: the two input arrays must have the same number of ciphertexts
// //TODO: delete key argument
// LweSample* CipherEuclid(vector<LweSample*> a,vector<LweSample*> b,const TFheGateBootstrappingCloudKeySet* EK,TFheGateBootstrappingSecretKeySet* key){
// 	int result;
// 	LweSample* sum = new_LweSample_array(bitsize, EK->params->in_out_params);
// 	vector<thread> threads;

// 	//initialize sum to 0, using cloud key
// 	for(int i=0;i<bitsize;i++)
// 	{
// 		bootsCONSTANT(sum+i, 0 ,EK);
	
// 		// bootsSymEncrypt(&sum[bitsize-1-i],(0>>i)&0x01,key);
// 	}
// 	// bootsCONSTANT(sum, 0 ,EK);
// 	// result = decryptLweSample(sum, key);
// 	// cout << "initial sum result = " << result << endl;
	
// 	vector<LweSample*> squares;

// 	for (int i=0; i<a.size(); i++){
// 		LweSample* ciphertext1 = a[i];
// 		LweSample* ciphertext2 = b[i];
// 		// LweSample* difference;
// 		// LweSample* square;	

// 		// std::thread thisthread(CipherEuclidHelper, squares, ciphertext1, ciphertext2, EK);
// 		// std::thread thisthread(f1, n+1);
// 		// thread thisthread = thread(CipherEuclidHelper, squares, ciphertext1, ciphertext2, EK);
		
// 		threads.push_back(thread(CipherEuclidHelper, squares, ciphertext1, ciphertext2, EK, key));
// 		// difference = CipherSub(ciphertext1,ciphertext2,EK);
// 		// // result = decryptLweSample(difference, key);
// 		// // cout << "difference result = " << result << endl;
// 		// square = CipherMul(difference,difference,EK);
// 		// // result = decryptLweSample(square, key);
// 		// // cout << "square result = " << result << endl;
// 		// // LweSample* newsum;
// 		// sum = CipherAdd(sum, square, EK);
// 		// result = decryptLweSample(sum, key);
// 		// int Result = 0;
// 		// for(int i=0;i<bitsize;i++)
// 		// {
// 		// 	Result<<=1;
// 		// 	Result+=bootsSymDecrypt(&newsum[i],key);
// 		// }	
// 		// cout << "sum result = " << result << endl;
// 	}

// 	for(int i=0; i<threads.size(); i++){
// 		threads[i].join();
// 	}

// 	for(int i=0; i<squares.size(); i++){
// 		sum = CipherAdd(sum, squares[i], EK);
// 		result = decryptLweSample(sum, key);
// 		cout << "sum result = " << result << endl;
// 	}


// 	return sum;
// }

//original version that does not use threads
//Given two arrays containing ciphertexts, calculate the square of Euclidean distance between them (in encrypted form)
// REQUIRES: the two input arrays must have the same number of ciphertexts
LweSample* CipherEuclid(vector<LweSample*> a,vector<LweSample*> b,const TFheGateBootstrappingCloudKeySet* EK){
	// clock_t begin = clock();
	int result;
	LweSample* sum = new_LweSample_array(bitsize, EK->params->in_out_params);

	//initialize sum to 0, using cloud key
	for(int i=0;i<bitsize;i++)
	{
		bootsCONSTANT(sum+i, 0 ,EK);
	
		// bootsSymEncrypt(&sum[bitsize-1-i],(0>>i)&0x01,key);
	}
	// bootsCONSTANT(sum, 0 ,EK);
	// result = decryptLweSample(sum, key);
	// cout << "initial sum result = " << result << endl;
	for (int i=0; i<a.size(); i++){
		LweSample* ciphertext1 = a[i];
		LweSample* ciphertext2 = b[i];
		LweSample* difference;
		LweSample* square;	
		difference = CipherSub(ciphertext1,ciphertext2,EK);
		// result = decryptLweSample(difference, key);
		// cout << "difference result = " << result << endl;
		square = CipherMul(difference,difference,EK);
		// result = decryptLweSample(square, key);
		// cout << "square result = " << result << endl;
		// LweSample* newsum;
		sum = CipherAdd(sum, square, EK);
		// result = decryptLweSample(sum, key);
		// int Result = 0;
		// for(int i=0;i<bitsize;i++)
		// {
		// 	Result<<=1;
		// 	Result+=bootsSymDecrypt(&newsum[i],key);
		// }	
		// cout << "sum result = " << result << endl;
	}
	// clock_t end = clock();
	// double elapsed_secs = double(end - begin) / CLOCKS_PER_SEC;
	// cout << "elapsed secs to calculate 2-norm = " << elapsed_secs << endl;
	
	return sum;
}

//encrypts given integer
LweSample* encryptInteger(int plaintext, TFheGateBootstrappingSecretKeySet* key){
	LweSample *ciphertext = new_gate_bootstrapping_ciphertext_array(bitsize,key->params);
	
	for(int i=0;i<bitsize;i++)
	{
		bootsSymEncrypt(&ciphertext[bitsize-1-i],(plaintext>>i)&0x01,key);
	}
	return ciphertext;
}


template <class T>
int numDigits(T number)
{
    int digits = 0;
    if (number < 0) digits = 1; // remove this line if '-' counts as a digit
    while (number) {
        number /= 10;
        digits++;
    }
    return digits;
}

//encrypts given integer part of Double
// ciphertext[0] holds least significant bit
// ciphertext[integerbitsize-1] holds the most significant bit 
LweSample* encryptIntegerpart(int plaintext, TFheGateBootstrappingSecretKeySet* key){
	LweSample *ciphertext = new_gate_bootstrapping_ciphertext_array(integerbitsize,key->params);
	
	for(int i=0;i<integerbitsize;i++)
	{
		bootsSymEncrypt(&ciphertext[integerbitsize-1-i],(plaintext>>i)&0x01,key);
		
		// //
		// int temp = bootsSymDecrypt(&ciphertext[integerbitsize-1-i], key);
		// cout << "integerpart[" << i << "] = " << temp << endl;
		// //
	}
	return ciphertext;
}

// //when plaintext is given as integer type e.g) 124 , is not working
// //encrypts given fractional part, where argument plaintext is given as 41 if integer was 124.41
// LweSample* encryptFractionpart(int plaintext, TFheGateBootstrappingSecretKeySet* key){
// 	LweSample *ciphertext = new_gate_bootstrapping_ciphertext_array(fractionbitsize,key->params);
// 	int numdigitsbefore, numdigitsafter;
// 	for(int i=0;i<fractionbitsize;i++)
// 	{
// 		cout << "plaintext = " << plaintext << endl;
// 		numdigitsbefore = numDigits(plaintext);
// 		plaintext = plaintext * 2;
// 		numdigitsafter = numDigits(plaintext);
// 		if (numdigitsafter > numdigitsbefore){
// 			// bootsSymEncrypt(&ciphertext[fractionbitsize-1-i],1,key);
// 			bootsSymEncrypt(&ciphertext[i],1,key);
			
// 			//
// 			int temp = bootsSymDecrypt(&ciphertext[i], key);
// 			cout << "fractionpart[" << i << "] = " << temp << endl;
// 			//
			
// 			//get rid of the leading digit
// 			plaintext = plaintext - pow(10,(numdigitsafter-1));
// 		}
// 		else {
// 			// bootsSymEncrypt(&ciphertext[fractionbitsize-1-i],0,key);
// 			bootsSymEncrypt(&ciphertext[i],0,key);
		
// 			//
// 			int temp = bootsSymDecrypt(&ciphertext[i], key);
// 			cout << "fractionpart[" << i << "] = " << temp << endl;
// 			//
		
// 		}
// 		// bootsSymEncrypt(&ciphertext[fractionbitsize-1-i],(plaintext>>i)&0x01,key);
// 	}
// 	return ciphertext;
// }


//when plaintext is given in double type   i.e. 0.xxx
//encrypts given fractional part, where argument plaintext is given as 41 if integer was 124.41
LweSample* encryptFractionpart(double plaintext, TFheGateBootstrappingSecretKeySet* key){
	LweSample *ciphertext = new_gate_bootstrapping_ciphertext_array(fractionbitsize,key->params);
	// int numdigitsbefore, numdigitsafter;
	for(int i=0;i<fractionbitsize;i++)
	{
		// cout << "plaintext = " << plaintext << endl;
		// numdigitsbefore = numDigits(plaintext);
		plaintext = plaintext * 2;
		// numdigitsafter = numDigits(plaintext);
		if (plaintext >= 1){
			// bootsSymEncrypt(&ciphertext[fractionbitsize-1-i],1,key);
			bootsSymEncrypt(&ciphertext[i],1,key);
			
			// //
			// int temp = bootsSymDecrypt(&ciphertext[i], key);
			// cout << "fractionpart[" << i << "] = " << temp << endl;
			// //
			
			//get rid of the leading 1
			plaintext = plaintext - 1;
		}
		else {
			// bootsSymEncrypt(&ciphertext[fractionbitsize-1-i],0,key);
			bootsSymEncrypt(&ciphertext[i],0,key);
		
			// //
			// int temp = bootsSymDecrypt(&ciphertext[i], key);
			// cout << "fractionpart[" << i << "] = " << temp << endl;
			// //
		
		}
		// bootsSymEncrypt(&ciphertext[fractionbitsize-1-i],(plaintext>>i)&0x01,key);
	}
	return ciphertext;
}

//given a ciphertext, determine its absolute value
LweSample* CipherAbs(LweSample* ciphertext, const TFheGateBootstrappingCloudKeySet* EK){
	LweSample* mask = new_gate_bootstrapping_ciphertext_array(bitsize, EK->params);
	LweSample* result = new_gate_bootstrapping_ciphertext_array(bitsize, EK->params);

	for(int i=0;i<bitsize;i++)
	{
		// mask[i] = ciphertext[0];
		bootsCOPY(mask+i, ciphertext, EK);
	}

	LweSample* sum = CipherAdd(ciphertext,mask,EK);

	for (int i=0; i<bitsize; i++){
		bootsXOR(result+i, sum+i, mask+i, EK);
	}

	return result;

}

//original version that does not use threads
//Given two arrays containing ciphertexts, calculate the one norm distance between them (in encrypted form)
// REQUIRES: the two input arrays must have the same number of ciphertexts
LweSample* CipherOneNorm(vector<LweSample*> a,vector<LweSample*> b,const TFheGateBootstrappingCloudKeySet* EK){

	// clock_t begin = clock();

	int result;
	LweSample* sum = new_LweSample_array(bitsize, EK->params->in_out_params);

	//initialize sum to 0, using cloud key
	for(int i=0;i<bitsize;i++)
	{
		bootsCONSTANT(sum+i, 0 ,EK);
	}
	for (int i=0; i<a.size(); i++){
		LweSample* ciphertext1 = a[i];
		LweSample* ciphertext2 = b[i];
		LweSample* difference;
		LweSample* abs;	
		difference = CipherSub(ciphertext1,ciphertext2,EK);
		abs = CipherAbs(difference,EK);
		sum = CipherAdd(sum, abs, EK);
	}

	// clock_t end = clock();

	// double elapsed_secs = double(end - begin) / CLOCKS_PER_SEC;
	// cout << "elapsed secs to calculate one-norm = " << elapsed_secs << endl;

	return sum;
}

int main(int argc, char *argv[])
{

	if(argc!=7)
	{
		printf("Usage : ./tensor2 <num1> <num2> <mode> <bitsize> <integerbitsize> <fractionbitsize>\n");
		printf("Calculation mode :\n1) Addition\n2) Multiplication\n3) Subtraction\n4) Comparison\n5) Euclidean distance \n6) Absolute value \n7) One norm distance\n 8) double addition\n9) double subtraction\n10) double multiplication\n>");
		exit(0);
	}
/*
	if(atoi(argv[4])!=16&&atoi(argv[4])!=32&&atoi(argv[4])!=64)
	{
		printf("Bitsize should be 16 bits or 32 bits or 64 bits.\n");
		exit(0);		
	}
*/
	bitsize = atoi(argv[4]);
	integerbitsize = atoi(argv[5]);
	fractionbitsize = atoi(argv[6]);

	// // Key_Creation & Encryption Scheme

	// const int minimum_lambda = 110;
	// TFheGateBootstrappingParameterSet* params = new_default_gate_bootstrapping_parameters(minimum_lambda);

	// //generate a random key
	// uint32_t seed[] = { 314, 1592, 657 };
	// tfhe_random_generator_setSeed(seed,3);
	// TFheGateBootstrappingSecretKeySet* key = new_random_gate_bootstrapping_secret_keyset(params);
	// testkey = key;
	// //export the secret key to file for later use
	// FILE* secret_key = fopen("secret.key","wb");
	// export_tfheGateBootstrappingSecretKeySet_toFile(secret_key, key);
	// fclose(secret_key);

	// //export the cloud key to a file (for the cloud)
	// FILE* cloud_key = fopen("cloud.key","wb");
	// export_tfheGateBootstrappingCloudKeySet_toFile(cloud_key, &key->cloud);
	// fclose(cloud_key);


	//reads the secret key from file
    FILE* secret_key = fopen("secret.key","rb");
    TFheGateBootstrappingSecretKeySet* key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
    fclose(secret_key);

	//reads the cloud key from file
    FILE* cloud_key = fopen("cloud.key","rb");
    const TFheGateBootstrappingCloudKeySet* bk = new_tfheGateBootstrappingCloudKeySet_fromFile(cloud_key);
    fclose(cloud_key);

	//if necessary, the params are inside the key
    const TFheGateBootstrappingParameterSet* params = key->params;
    const LweParams *in_out_params = params->in_out_params;



	/** Calculation test **/
	int a,b;
	a = atoi(argv[1]);
	b = atoi(argv[2]);
	
	
	LweSample* t0 = encryptInteger(a, key);
	LweSample* t1 = encryptInteger(b, key);

	// // CipherText Container 	
	// LweSample *t0 = new_gate_bootstrapping_ciphertext_array(bitsize,params);
	// LweSample *t1 = new_gate_bootstrapping_ciphertext_array(bitsize,params);
	
	// for(int i=0;i<bitsize;i++)
	// {
	// 	bootsSymEncrypt(&t0[bitsize-1-i],(a>>i)&0x01,key);
	// 	bootsSymEncrypt(&t1[bitsize-1-i],(b>>i)&0x01,key);
	// }


	int mode = atoi(argv[3]);
	printf("\nStarting Calculation...\n");
	LweSample* Test;
	if(mode == 1)	Test = CipherAdd(t0,t1,&key->cloud);
	else if(mode == 2) {
		int fpvector1[16] = {53,58,53,36,49,53,49,74,61,61,70,62,47,47,44,68};
		int fpvector2[16] = {59,55,53,46,48,59,60,70,52,54,57,71,50,49,46,61};

		LweSample* ciphertext1 = encryptInteger(fpvector1[0], key);
		LweSample* ciphertext2 = encryptInteger(fpvector2[0], key);

		for (int i=8; i< 65; i++){
			bitsize = i;
			cout << "bitsize = " << bitsize << endl;
			Test = CipherMul(ciphertext1,ciphertext2,&key->cloud);
			int result = decryptLweSample(Test, key);
			cout << "result = " << result << endl;
		}
		// Test = CipherMul(t0,t1,&key->cloud);
	}
	else if(mode == 3) Test = CipherSub(t0,t1,&key->cloud);
	else if(mode == 4) Test = CipherCmp(t0,t1,&key->cloud);
	else if(mode == 5){
		// vector<LweSample*> vector1, vector2;	

		// int plaintext1 = 14;
		// int plaintext2 = 56;
		// LweSample* ciphertext1 = encryptInteger(plaintext1, key);
		// LweSample* ciphertext2 = encryptInteger(plaintext2, key);
		// vector1.push_back(ciphertext1);
		// vector2.push_back(ciphertext2);

		// Test = CipherEuclid(vector1,vector2,&key->cloud, key);
		// int result = decryptLweSample(Test, key);
		// cout << "result = " << result << endl;

		vector<LweSample*> vector1, vector2;	
		// square of Euclidean distance should return 765
		int fpvector1[16] = {53,58,53,36,49,53,49,74,61,61,70,62,47,47,44,68};
		int fpvector2[16] = {59,55,53,46,48,59,60,70,52,54,57,71,50,49,46,61};
		for (int i=0; i< 16; i++){
			LweSample* ciphertext1 = encryptInteger(fpvector1[i], key);
			vector1.push_back(ciphertext1);
			LweSample* ciphertext2 = encryptInteger(fpvector2[i], key);
			vector2.push_back(ciphertext2);

		}
		for (int i=32; i < 33; i++){
			bitsize = i;
			cout << "bitsize = " << bitsize << endl;
			Test = CipherEuclid(vector1, vector2, &key->cloud);
			int result = decryptLweSample(Test, key);
			cout << "result = " << result << endl;
			
		}
		

	}
	else if(mode == 6){
		// for(int i=0;i<bitsize;i++)
		// {
		// 	int bit =bootsSymDecrypt(&t0[i],key);
		// 	cout << "bit = " << bit << endl;
		// }
		CipherAbs(t0, &key->cloud);
	}
	else if(mode == 7){
		vector<LweSample*> vector1, vector2;	
		int fpvector1[16] = {53,58,53,36,49,53,49,74,61,61,70,62,47,47,44,68};
		int fpvector2[16] = {59,55,53,46,48,59,60,70,52,54,57,71,50,49,46,61};
		for (int i=0; i< 16; i++){
			LweSample* ciphertext1 = encryptInteger(fpvector1[i], key);
			vector1.push_back(ciphertext1);
			LweSample* ciphertext2 = encryptInteger(fpvector2[i], key);
			vector2.push_back(ciphertext2);

		}
		for (int i=10; i<11; i++){
			bitsize = i;
			cout << "bitsize = " << bitsize << endl;
			Test = CipherOneNorm(vector1, vector2, &key->cloud);
			int result = decryptLweSample(Test, key);
			cout << "result = " << result << endl;
		}
	}
	else if(mode == 8){
		// double testdouble = 256.128;
		LweSample *integerpart1 = new_gate_bootstrapping_ciphertext_array(integerbitsize,params);
		LweSample *fractionpart1 = new_gate_bootstrapping_ciphertext_array(fractionbitsize,params);
		LweSample *integerpart2 = new_gate_bootstrapping_ciphertext_array(integerbitsize,params);
		LweSample *fractionpart2 = new_gate_bootstrapping_ciphertext_array(fractionbitsize,params);
		Double temp1, temp2;
		integerpart1 = encryptIntegerpart(3, key);
		// fractionpart = encryptFractionpart(128, key);
		fractionpart1 = encryptFractionpart(0.389, key);
		// int result = decryptIntegerpart(integerpart, key);
		// cout << "integerpart decrypted result = " << result << endl;
		integerpart2 = encryptIntegerpart(1, key);
		// fractionpart = encryptFractionpart(128, key);
		fractionpart2 = encryptFractionpart(0.735, key);
		// int result = decryptIntegerpart(integerpart, key);
		// cout << "integerpart decrypted result = " << result << endl;
		// double fractionresult = decryptFractionpart(fractionpart1, key);
		// cout << "fractionpart1 decrypted result = " << fractionresult << endl;
		temp1.integerpart = integerpart1;
		temp1.fractionpart = fractionpart1;
		temp2.integerpart = integerpart2;
		temp2.fractionpart = fractionpart2;
		// double decrypted = decryptDouble(temp1, key);
		// cout << "decrypted  = " << decrypted << endl;


		Double sum = CipherAddDouble(temp1, temp2 , &key->cloud);
		double decryptedsum = decryptDouble(sum, key);
		cout << "decryptedsum  = " << decryptedsum << endl;

		// // double testdouble = 256.128;
		// LweSample *encryptedDouble = new_gate_bootstrapping_ciphertext_array(integerbitsize + fractionbitsize,params);
		// Double temp;
		// encryptedDouble = encryptIntegerpart(256, key);
		// // fractionpart = encryptFractionpart(128, key);
		// (encryptedDouble + integerbitsize) = encryptFractionpart(0.389467239, key);
		// int result = decryptIntegerpart(encryptedDouble, key);
		// cout << "integerpart decrypted result = " << result << endl;
		// double fractionresult = decryptFractionpart(&encryptedDouble[integerbitsize], key);
		// cout << "fractionpart decrypted result = " << fractionresult << endl;
	
	}
	else if(mode == 9){
		LweSample *integerpart1 = new_gate_bootstrapping_ciphertext_array(integerbitsize,params);
		LweSample *fractionpart1 = new_gate_bootstrapping_ciphertext_array(fractionbitsize,params);
		LweSample *integerpart2 = new_gate_bootstrapping_ciphertext_array(integerbitsize,params);
		LweSample *fractionpart2 = new_gate_bootstrapping_ciphertext_array(fractionbitsize,params);
		Double temp1, temp2;
		integerpart1 = encryptIntegerpart(3, key);
		fractionpart1 = encryptFractionpart(0.389, key);
		integerpart2 = encryptIntegerpart(4, key);
		fractionpart2 = encryptFractionpart(0.735, key);
		temp1.integerpart = integerpart1;
		temp1.fractionpart = fractionpart1;
		temp2.integerpart = integerpart2;
		temp2.fractionpart = fractionpart2;


		Double difference = CipherSubDouble(temp1, temp2 , &key->cloud);
		double decrypteddifference = decryptDouble(difference, key);
		cout << "decrypteddifference  = " << decrypteddifference << endl;
	}
	else if(mode == 10){
		LweSample *integerpart1 = new_gate_bootstrapping_ciphertext_array(integerbitsize,params);
		LweSample *fractionpart1 = new_gate_bootstrapping_ciphertext_array(fractionbitsize,params);
		LweSample *integerpart2 = new_gate_bootstrapping_ciphertext_array(integerbitsize,params);
		LweSample *fractionpart2 = new_gate_bootstrapping_ciphertext_array(fractionbitsize,params);
		Double temp1, temp2;
		integerpart1 = encryptIntegerpart(1, key);
		fractionpart1 = encryptFractionpart(0.3, key);
		integerpart2 = encryptIntegerpart(1, key);
		fractionpart2 = encryptFractionpart(0.7, key);
		temp1.integerpart = integerpart1;
		temp1.fractionpart = fractionpart1;
		temp2.integerpart = integerpart2;
		temp2.fractionpart = fractionpart2;


		Double product = CipherMulDouble(temp1, temp2 , &key->cloud, key);
		double decryptedproduct = decryptDouble(product, key);
		cout << "decryptedproduct  = " << decryptedproduct << endl;
	}
	else	exit(0);
	if(mode < 4)
	{
		int result = decryptLweSample(Test, key);
		cout << "result = " << result << endl;
		// int Result = 0;
		// for(int i=0;i<bitsize;i++)
		// {
		// 	Result<<=1;
		// 	Result+=bootsSymDecrypt(&Test[i],key);
		// }	
		// printf("Calculation Result : %d\n",Result);
	}
	// else
	// {
	// 	if(bootsSymDecrypt(Test,key))	printf("It is same value\n");
	// 	else printf("It is not same value\n");
	// }
	/** End of Calculation test **/
	
}

