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

#include <pthread.h>

#define null 0




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

//
//
// static int myCfunc ( lua_State *L) {
//   printf ("Roses are Red\n");
//   return 0; }
// int luaopen_fromlua ( lua_State *L) {
//   static const luaL_Reg Map [] = {
//     {"dothis", myCfunc},
//     {NULL,NULL} } ;
//   luaL_register(L, "cstuff", Map);
//   return 1; }
//
//


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
LweSample* CipherAdd(LweSample* a,LweSample* b,const TFheGateBootstrappingCloudKeySet* EK)
{
	LweSample *carry = new_gate_bootstrapping_ciphertext(EK->params);
	LweSample *Result = new_gate_bootstrapping_ciphertext_array(32,EK->params);
	
	for(int i= 31 ; i >= 0 ; i--)
	{
		if(i == 31)
		{
			pthread_t thread[2];
			struct CalcSet *in[2];
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
			
			pthread_join(thread[0],(void **)&carry);
			pthread_join(thread[1],(void **)&Result[i]);
			//bootsAND(carry,&a[i],&b[i],EK);
			//bootsXOR(&Result[i],&a[i],&b[i],EK);
		}
		else
		{
			pthread_t thread[2];
                        struct CalcSet *in[2];
                        for(int num =0 ; num<2; num++)  in[num]= (struct CalcSet*)malloc(sizeof(struct CalcSet));

			LweSample *copy = new_gate_bootstrapping_ciphertext(EK->params);
			
			LweSample *b1;
			b1 = new_gate_bootstrapping_ciphertext(EK->params);
			bootsXOR(b1,&a[i],&b[i],EK);
			bootsXOR(&Result[i],b1,carry,EK);
			bootsMUX(carry,b1,carry,&a[i],EK);
		}
	}
	return Result;
}
LweSample* CipherAdd(LweSample* a,LweSample* b,const TFheGateBootstrappingCloudKeySet* EK,int minbit) // special Add functions used for Multiplications
{

        LweSample *carry = new_gate_bootstrapping_ciphertext(EK->params);
        LweSample *Result = new_gate_bootstrapping_ciphertext_array(32,EK->params);

	for(int i= 31; i>minbit ; i--)
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
                        LweSample *b1;
                        b1 = new_gate_bootstrapping_ciphertext(EK->params);

                        bootsXOR(b1,&a[i],&b[i],EK);
                        bootsXOR(&Result[i],b1,carry,EK);
                        bootsMUX(carry,b1,carry,&a[i],EK);
                }
        }
        return Result;
}

LweSample* CipherSub(LweSample* a,LweSample* b,const TFheGateBootstrappingCloudKeySet* EK)
{
	LweSample *carry = new_gate_bootstrapping_ciphertext(EK->params);
	LweSample *O = new_gate_bootstrapping_ciphertext(EK->params);
	LweSample *Rev = new_gate_bootstrapping_ciphertext_array(32,EK->params);
	LweSample *Arv = new_gate_bootstrapping_ciphertext_array(32,EK->params);

	bootsCONSTANT(O,1,EK);

	/** Reversing bits of b **/

	for(int i = 0; i < 32 ; i++)
	{
		bootsNOT(&Rev[i],&b[i],EK);
	}

	/** Add one to Reversed bit form of b **/

	for(int i = 31 ; i >= 0 ; i--)
	{
		if(i == 31)
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
	
	input->C = new_gate_bootstrapping_ciphertext_array(32,input->EK->params);
	for(int i=input->ind;i<32;i++)	bootsAND(&input->C[i-input->ind],&input->a[31-input->ind],&input->b[i],input->EK);	
	for(int i=32-input->ind;i<32;i++)	bootsCONSTANT(&input->C[i],0,input->EK);
	pthread_exit((void *)input->C);
}
LweSample* CipherMul(LweSample* a,LweSample* b,const TFheGateBootstrappingCloudKeySet* EK)	// O(2*n) algorithm = about 
{
	LweSample *Container[32];
	pthread_t init[32];

	/** Boost speed by initializing variables concurrently using threads **/

	for(int i = 0 ; i < 32 ; i++)
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


	/** Boost speed by using complete binary-tree based thread calculation **/ 

	for(int i=0;i<32;i++)	pthread_join(init[i],(void **)&Container[i]);
	
	pthread_t thread[32];
	LweSample* Ret[16];
	for(int i = 0 ; i < 16 ; i++)
	{
		struct CipherSet *in;
		in = (struct CipherSet*)malloc(sizeof(struct CipherSet));
		in->a = Container[i];
		in->b = Container[31-i];
		in->minbit = i+1;
		in->EK = EK; 
		pthread_create(&thread[i],NULL,&thread_adder,(void *)in);
	}
	for(int i = 0 ; i< 16 ; i ++)	pthread_join(thread[i],(void **)&Ret[i]);
	LweSample* Ret2[8];
	for(int i = 0 ; i < 8 ; i++)
	{
		struct CipherSet *in;
		in = (struct CipherSet*)malloc(sizeof(struct CipherSet));
		in->a = Ret[i];
		in->b = Ret[15-i];
		in->minbit = 17+i;
		in->EK = EK;
		pthread_create(&thread[16+i],NULL,&thread_adder,(void *)in);	
	}

	for(int i = 0 ; i < 8 ; i++)	pthread_join(thread[16+i],(void **)&Ret2[i]);

	LweSample* Ret3[4];
	for(int i = 0 ; i < 4 ; i++)
	{
		struct CipherSet *in;
                in = (struct CipherSet*)malloc(sizeof(struct CipherSet));
		in->a = Ret2[i];
		in->b = Ret2[7-i];
		in->minbit = 25+i;
		in->EK = EK;
		pthread_create(&thread[24+i],NULL,&thread_adder,(void *)in);
	} 

	for(int i = 0 ; i < 4 ; i++)	pthread_join(thread[24+i],(void **)&Ret3[i]);

	LweSample* Ret4[2];
        for(int i = 0 ; i < 2 ; i++)
        {
                struct CipherSet *in;
                in = (struct CipherSet*)malloc(sizeof(struct CipherSet));
                in->a = Ret3[i];
                in->b = Ret3[3-i];
		in->minbit = 29+i;
                in->EK = EK;
                pthread_create(&thread[28+i],NULL,&thread_adder,(void *)in);
        }

        for(int i = 0 ; i < 2 ; i++)    pthread_join(thread[28+i],(void **)&Ret4[i]);

	LweSample* Retx;
        for(int i = 0 ; i < 1 ; i++)
        {
                struct CipherSet *in;
                in = (struct CipherSet*)malloc(sizeof(struct CipherSet));
                in->a = Ret4[i];
                in->b = Ret4[1-i];
		in->minbit = 31+i;
                in->EK = EK;
                pthread_create(&thread[30+i],NULL,&thread_adder,(void *)in);
        }

        for(int i = 0 ; i < 1 ; i++)    pthread_join(thread[30+i],(void **)&Retx);	

	return Retx;
}


int main(int argc, char *argv[])
{




/*	
	if(argc !=2) // Error Case
	{
		printf("Usage : ./tensor1 <FileName>\n");
		exit(0);
	
}
	else
	{
		FILE *fp;
		if((fp = fopen(argv[1],"rb"))<=0) //File open.
		{
			printf("Invalid File(%s)... exit\n",argv[1]);
			exit(0);
		}
		double var = 0;
		while(fscanf(fp,"%lf",&var)>0)
		{
			if(V ==0)	// First input case
			{
				Tail = &Head;
				Head.var = var;
			}
			else
			{
				Tail->p = (struct tensor*)malloc(sizeof(struct tensor));
				Tail=Tail->p;
				Tail->var = var;		
			}
			Tail->p = null;
			V++;
		}
		if(V==0)
		{
			printf("Error Reading FIle(%s)... exit\n",argv[1]);
                        exit(0); 
		}
		if(V%2) // If case is not fit for linear regression, abort.
		{
			printf("Error On variable...(due to variables) exit\n");
			exit(0);
		}
		fclose(fp);
	}
*/

	if(argc!=3)
	{
		printf("Usage : ./tensor2 <num1> <num2>\n");
		exit(0);
	}
	
	// Key_Creation & Encryption Scheme

	const int minimum_lambda = 110;
	TFheGateBootstrappingParameterSet* params = new_default_gate_bootstrapping_parameters(minimum_lambda);

	//generate a random key
	uint32_t seed[] = { 314, 1592, 657 };
	tfhe_random_generator_setSeed(seed,3);
	TFheGateBootstrappingSecretKeySet* key = new_random_gate_bootstrapping_secret_keyset(params);
	testkey = key;
	//export the secret key to file for later use
	FILE* secret_key = fopen("secret.key","wb");
	export_tfheGateBootstrappingSecretKeySet_toFile(secret_key, key);
	fclose(secret_key);

	//export the cloud key to a file (for the cloud)
	FILE* cloud_key = fopen("cloud.key","wb");
	export_tfheGateBootstrappingCloudKeySet_toFile(cloud_key, &key->cloud);
	fclose(cloud_key);

	LweSample *x[V/2];
	LweSample *y[V/2];
	for(int i = 0; i < V/2; i++)
	{
		x[i] = new_gate_bootstrapping_ciphertext_array(32,params);
	} 
	for(int i = 0; i < V/2; i++)
	{
		y[i] = new_gate_bootstrapping_ciphertext_array(32,params);	
	}
	Tail = &Head;
	
	for(int i = 0; i < V; i++)
	{
		// Seperate each bit.

		long long Value = Tail->var*1000; 

		// Encrypting each bit.		

		for(int j=0;j<32;j++) // Looping for number of bits of double
		{
			if(i<V/2)	bootsSymEncrypt(&x[i][j],(Value>>(32-j))&1,key);
			else	bootsSymEncrypt(&y[i-V/2][j],(Value>>(32-j))&1,key);	
		}
		Tail= Tail->p;
	}
	LweSample *alpha;
	alpha = new_gate_bootstrapping_ciphertext_array(32,params);
	int LearningRate = 0.01*1000;
	for(int i=0;i<32;i++)	bootsSymEncrypt(&alpha[i],(LearningRate>>(32-i))&1,key);
	LweSample *b0,*b1;
	b0 = new_gate_bootstrapping_ciphertext_array(32,params);
	b1 = new_gate_bootstrapping_ciphertext_array(32,params);

	for(int i=0;i<32;i++)
	{
		bootsSymEncrypt(&b0[i],0,key);
		bootsSymEncrypt(&b1[i],0,key);
	}

	/** Calculation test **/
	int a,b;
	printf("Input : two variables for calculations :  ");
	a = atoi(argv[1]);
	b = atoi(argv[2]);
	// CipherText Container 	
	LweSample *t0 = new_gate_bootstrapping_ciphertext_array(32,params);
	LweSample *t1 = new_gate_bootstrapping_ciphertext_array(32,params);
	
	for(int i=0;i<32;i++)
	{
		bootsSymEncrypt(&t0[31-i],(a>>i)&0x01,key);
		bootsSymEncrypt(&t1[31-i],(b>>i)&0x01,key);
	}
	printf("Mode of calculation : 1) Addition 2) Multiplication 3) Subtraction ");
	int mode = -1;
	scanf("%d",&mode);
	printf("\nStart Calculation...\n");
	LweSample* Test;
	if(mode == 1)	Test = CipherAdd(t0,t1,&key->cloud);
	else if(mode == 2) Test = CipherMul(t0,t1,&key->cloud);
	else if(mode == 3) Test = CipherSub(t0,t1,&key->cloud);
	else	exit(0);
	int Result = 0;
	for(int i=0;i<32;i++)
	{
		Result<<=1;
		Result+=bootsSymDecrypt(&Test[i],key);
	}	
	printf("Calculation Result : %d\n",Result);
	/** End of Calculation test **/
	

	/* -----		This must be on server side			----- */
	// Calculation Scheme
	/*clock_t tstart,tfinish;
	tstart = clock();	
	for (int i=0; i< 20; i++){
		printf("%dth loop\n",i);
		int idx = i % (V/2);
		
		LweSample *p = CipherAdd(b0,CipherMul(b1,x[idx],&key->cloud),&key->cloud);
		LweSample *err = CipherSub(p,y[idx],&key->cloud);
		b0 = CipherSub(b0,CipherMul(alpha,err,&key->cloud),&key->cloud);
		b1 = CipherSub(b1,CipherMul(CipherMul(alpha,err,&key->cloud),x[idx],&key->cloud),&key->cloud);

		int Result = 0;
	        for(int i=0;i<32;i++)
	        {
	                Result<<=1;
	                Result+=bootsSymDecrypt(&b0[i],key);
	        }       
	        printf("Calculation Result : %d, ",Result);

		Result = 0;
                for(int i=0;i<32;i++)
                {
                        Result<<=1;
                        Result+=bootsSymDecrypt(&b1[i],key);
                }
                printf("Calculation Result : %d\n",Result);

	}
	tfinish = clock();
	double len = (tfinish-tstart)/CLOCKS_PER_SEC;
	printf("Elapsed time for linear regression : %lf\n",len);*/
	/* ------		This must be on server side			----- */
}
