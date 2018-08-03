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
#include <ctime>
#include <mex.h>

#include <pthread.h>

#define null 0

using namespace std;

int bitsize = 32;


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

LweSample* CipherSub(LweSample* a,LweSample* b,const TFheGateBootstrappingCloudKeySet* EK)
{
	LweSample *carry = new_gate_bootstrapping_ciphertext(EK->params);
	LweSample *O = new_gate_bootstrapping_ciphertext(EK->params);
	LweSample *Rev = new_gate_bootstrapping_ciphertext_array(bitsize,EK->params);
	LweSample *Arv = new_gate_bootstrapping_ciphertext_array(bitsize,EK->params);

	bootsCONSTANT(O,1,EK);

	/** Reversing bits of b **/

	for(int i = 0; i < bitsize ; i++)
	{
		bootsNOT(&Rev[i],&b[i],EK);
	}

	/** Add one to Reversed bit form of b **/

	for(int i = bitsize-1 ; i >= 0 ; i--)
	{
		if(i == bitsize-1)
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
	
	return CipherAdd(a,Arv,EK);
}

void *thread_adder(void *arg)
{
        struct CipherSet* input = (struct CipherSet*)arg;


        LweSample* Ret = CipherAdd(input->a,input->b,input->EK,input->minbit);

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
void *zero_initializer(void *arg)
{
        struct MulInitSet* input = (struct MulInitSet*)arg;

        input->C = new_gate_bootstrapping_ciphertext_array(bitsize,input->EK->params);
        for(int i=0;i<bitsize;i++)     bootsCONSTANT(&input->C[i],0,input->EK);
        pthread_exit((void *)input->C);
}

LweSample* CipherMul(LweSample* a,LweSample* b,const TFheGateBootstrappingCloudKeySet* EK)	// O(2*n) algorithm = about 
{
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
        return Container[2*bin-2];
}

//Given two arrays containing ciphertexts, calculate the square of Euclidean distance between them (in encrypted form)
// REQUIRES: the two input arrays must have the same number of ciphertexts
LweSample* CipherEuclid(vector<LweSample*> a,vector<LweSample*> b,const TFheGateBootstrappingCloudKeySet* EK){
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
		LweSample* abs;	
		difference = CipherSub(ciphertext1,ciphertext2,EK);
		// result = decryptLweSample(difference, key);
		// cout << "difference result = " << result << endl;
		abs = CipherAbs(difference,EK);
		// result = decryptLweSample(square, key);
		// cout << "square result = " << result << endl;
		// LweSample* newsum;
		sum = CipherAdd(sum, abs, EK);
		// result = decryptLweSample(sum, key);
		// int Result = 0;
		// for(int i=0;i<bitsize;i++)
		// {
		// 	Result<<=1;
		// 	Result+=bootsSymDecrypt(&newsum[i],key);
		// }	
		// cout << "sum result = " << result << endl;
	}
	return sum;
}


//calculate Euclidean distance given two vectors, in encrypted form
//REQUIRES: requires integer to be passed after it is converted to int32 format
void mexFunction(int nlhs, mxArray *plhs[], int nrhs, const mxArray *prhs[]){
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

	int *inputvector1 = (int*) mxGetPr(prhs[0]);
    int *inputvector2 = (int*) mxGetPr(prhs[1]);
	int *vectorlength = (int*) mxGetPr(prhs[2]);
	
	// cout << "vectorlength = " << *vectorlength << endl;
	vector<LweSample*> vector1, vector2;

	for (int i =0; i< *vectorlength; i++){
    	// cout << "*inputvector1[i] = " << inputvector1[i] << "\n";
        // cout << "inputvector2[i] = " << inputvector2[i] << "\n";
		int plaintext1 = inputvector1[i];
		int plaintext2 = inputvector2[i];
		LweSample* ciphertext1 = encryptInteger(plaintext1, key);
		LweSample* ciphertext2 = encryptInteger(plaintext2, key);
		vector1.push_back(ciphertext1);
		vector2.push_back(ciphertext2);
    }

	clock_t begin = clock();
	LweSample* distance = CipherOneNorm(vector1,vector2,&key->cloud);
	clock_t end = clock();
	double elapsed_secs = double(end - begin) / CLOCKS_PER_SEC;
	cout << "elapsed_secs = " << elapsed_secs << endl;
	int result = decryptLweSample(distance, key);
	cout << "result = " << result << endl;
}

// int main(int argc, char *argv[])
// {

// 	if(argc!=5)
// 	{
// 		printf("Usage : ./tensor2 <num1> <num2> <mode> <bitsize>\n");
// 		printf("Calculation mode :\n1) Addition\n2) Multiplication\n3) Subtraction\n4) Comparison\n5) Euclidean distance\n>");
// 		exit(0);
// 	}

// 	bitsize = atoi(argv[4]);

// 	//reads the secret key from file
//     FILE* secret_key = fopen("secret.key","rb");
//     TFheGateBootstrappingSecretKeySet* key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
//     fclose(secret_key);

// 	//reads the cloud key from file
//     FILE* cloud_key = fopen("cloud.key","rb");
//     const TFheGateBootstrappingCloudKeySet* bk = new_tfheGateBootstrappingCloudKeySet_fromFile(cloud_key);
//     fclose(cloud_key);

// 	//if necessary, the params are inside the key
//     const TFheGateBootstrappingParameterSet* params = key->params;
//     const LweParams *in_out_params = params->in_out_params;



// 	/** Calculation test **/
// 	int a,b;
// 	a = atoi(argv[1]);
// 	b = atoi(argv[2]);
	
	
// 	LweSample* t0 = encryptInteger(a, key);
// 	LweSample* t1 = encryptInteger(b, key);


// 	int mode = atoi(argv[3]);
// 	printf("\nStarting Calculation...\n");
// 	LweSample* Test;
// 	if(mode == 1)	Test = CipherAdd(t0,t1,&key->cloud);
// 	else if(mode == 2) Test = CipherMul(t0,t1,&key->cloud);
// 	else if(mode == 3) Test = CipherSub(t0,t1,&key->cloud);
// 	else if(mode == 4) Test = CipherCmp(t0,t1,&key->cloud);
// 	else if(mode == 5){
// 		LweSample* t2 = encryptInteger(14, key);
// 		LweSample* t3 = encryptInteger(56, key);	
// 		LweSample* array1[] = {t0, t2};
// 		LweSample* array2[] = {t1, t3};
// 		Test = CipherEuclid(array1,array2,&key->cloud, 2, key);
// 		int result = decryptLweSample(Test, key);
// 		cout << "result = " << result << endl;
// 	}
// 	else	exit(0);
// 	if(mode < 4)
// 	{
// 		int result = decryptLweSample(Test, key);
// 		cout << "result = " << result << endl;
// 	}
	
// }

