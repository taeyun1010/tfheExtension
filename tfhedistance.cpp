#include <stdio.h>
#include <iostream>
#include <iomanip>
#include <cstdlib>
#include <cmath>
#include <sys/time.h>
#include <tfhe/tfhe.h>
#include <tfhe/polynomials.h>
#include <tfhe/lwesamples.h>
#include <tfhe/lwekey.h>
#include <tfhe/lweparams.h>
#include <tfhe/tlwe.h>
#include <tfhe/tgsw.h>
#include "tfhedistance.h"

using namespace std;

// int32_t numberofbits = 32;

int32_t numberofbits = 32;

// struct CipherSet{
// 	LweSample *a;
// 	LweSample *b;
// 	int minbit;
// 	const TFheGateBootstrappingCloudKeySet* EK;
// };
// struct MulInitSet{
// 	LweSample *C;
// 	LweSample *a;
// 	LweSample *b;
// 	int ind;
// 	const TFheGateBootstrappingCloudKeySet* EK;
// };
// struct CalcSet{
// 	LweSample *r;
// 	LweSample *a;
// 	LweSample *b;
// 	LweSample *c;
// 	const TFheGateBootstrappingCloudKeySet* EK;
// };

// **********************************************************************************
// ********************************* MAIN *******************************************
// **********************************************************************************


void dieDramatically(string message) {
    cerr << message << endl;
    abort();
}

// decrypts given LweSample
int32_t decryptLweSample(const LweSample* input, const int32_t nb_bits, TFheGateBootstrappingSecretKeySet* key){
	int32_t int_answer = 0;
    for (int i=0; i<nb_bits; i++) {
        int ai = bootsSymDecrypt(&input[i], key);
        cout << "decrypted ai = " << ai << endl;
        int_answer |= (ai<<i);
    }
    return int_answer;
}

void full_adder_MUX(LweSample *sum, const LweSample *x, const LweSample *y, const int32_t nb_bits,
                    const TFheGateBootstrappingSecretKeySet *keyset) {
    const LweParams *in_out_params = keyset->params->in_out_params;
    // carries
    LweSample *carry = new_LweSample_array(2, in_out_params);
    bootsSymEncrypt(carry, 0, keyset); // first carry initialized to 0
    // temps
    LweSample *temp = new_LweSample_array(2, in_out_params);

    for (int32_t i = 0; i < nb_bits; ++i) {
        //sumi = xi XOR yi XOR carry(i-1) 
        bootsXOR(temp, x + i, y + i, &keyset->cloud); // temp = xi XOR yi
        bootsXOR(sum + i, temp, carry, &keyset->cloud);

        // carry = MUX(xi XOR yi, carry(i-1), xi AND yi)
        bootsAND(temp + 1, x + i, y + i, &keyset->cloud); // temp1 = xi AND yi
        bootsMUX(carry + 1, temp, carry, temp + 1, &keyset->cloud);

        bool mess1 = bootsSymDecrypt(temp, keyset);
        bool mess2 = bootsSymDecrypt(carry, keyset);
        bool mess3 = bootsSymDecrypt(temp + 1, keyset);
        bool messmux = bootsSymDecrypt(carry + 1, keyset);

        if (messmux != (mess1 ? mess2 : mess3)) {
            cout << "ERROR!!! " << i << " - ";
            cout << t32tod(lwePhase(temp, keyset->lwe_key)) << " - ";
            cout << t32tod(lwePhase(carry, keyset->lwe_key)) << " - ";
            cout << t32tod(lwePhase(temp + 1, keyset->lwe_key)) << " - ";
            cout << t32tod(lwePhase(carry + 1, keyset->lwe_key)) << endl;
        }

        bootsCOPY(carry, carry + 1, &keyset->cloud);
    }
    bootsCOPY(sum + nb_bits, carry, &keyset->cloud);

    delete_LweSample_array(2, temp);
    delete_LweSample_array(2, carry);
}

//TODO: delete key argument
void full_adder(LweSample *sum, const LweSample *x, const LweSample *y, const int32_t nb_bits,
                const TFheGateBootstrappingCloudKeySet *bk, const LweParams *in_out_params, TFheGateBootstrappingSecretKeySet* key) {
    // int decryptedx = decryptLweSample(x, nb_bits, key);
    // int decryptedy = decryptLweSample(y, nb_bits, key);
    
    // cout << "decryptedx = " << decryptedx << endl;
    // cout << "decryptedy = " << decryptedy << endl;

    // carries
    LweSample *carry = new_LweSample_array(2, in_out_params);
    // first carry initialized to 0
    bootsCONSTANT(carry, 0, bk);
    // temps
    LweSample *temp = new_LweSample_array(3, in_out_params);

    for (int32_t i = 0; i < nb_bits; ++i) {

        int ai = bootsSymDecrypt(&x[i], key);
        cout << "decrypted x[" << i << "] = " << ai << endl;
        ai = bootsSymDecrypt(&y[i], key);
        cout << "decrypted y[" << i << "] = " << ai << endl;

        //sumi = xi XOR yi XOR carry(i-1) 
        bootsXOR(temp, x + i, y + i, bk); // temp = xi XOR yi
        bootsXOR(sum + i, temp, carry, bk);

        //
        int decryptedbit = bootsSymDecrypt(sum + i, key);
        cout << "decryptedbit[" << i << "]" << decryptedbit << endl;
        //


        // carry = (xi AND yi) XOR (carry(i-1) AND (xi XOR yi))
        bootsAND(temp + 1, x + i, y + i, bk); // temp1 = xi AND yi
        bootsAND(temp + 2, carry, temp, bk); // temp2 = carry AND temp
        bootsXOR(carry + 1, temp + 1, temp + 2, bk);
        bootsCOPY(carry, carry + 1, bk);
    }
    bootsCOPY(sum + nb_bits, carry, bk);

    delete_LweSample_array(3, temp);
    delete_LweSample_array(2, carry);
}

// //calculate x-y
// void full_subtractor(LweSample *difference, const LweSample *x, const LweSample *y, const int32_t nb_bits,
//                 const TFheGateBootstrappingSecretKeySet *keyset) {
//     const LweParams *in_out_params = keyset->params->in_out_params;
//     // carries
//     LweSample *borrow = new_LweSample_array(2, in_out_params);
    
    
//     bootsSymEncrypt(borrow, 0, keyset); // first carry initialized to 0
//     // bootsCONSTANT(borrow, 0, &keyset->cloud);

    
//     // temps
//     LweSample *temp = new_LweSample_array(6, in_out_params);

//     for (int32_t i = 0; i < nb_bits; ++i) {
//         //sumi = xi XOR yi XOR carry(i-1) 
//         bootsXOR(temp, x + i, y + i, &keyset->cloud); // temp = xi XOR yi
//         bootsXOR(difference + i, temp, borrow, &keyset->cloud);

//         // carry = (xi AND yi) XOR (carry(i-1) AND (xi XOR yi))
//         bootsNOT(temp + 1, x + i, &keyset->cloud); // temp1 = xi'
//         bootsAND(temp + 2, temp + 1, borrow, &keyset->cloud); // temp2 = xi' AND Bin
//         bootsAND(temp + 3, temp + 1, y + i, &keyset->cloud);  // temp3 = xi' AND yi
//         bootsAND(temp + 4, y + i, borrow, &keyset->cloud);    //temp4 = yi AND Bin
//         bootsOR(temp + 5, temp + 2, temp + 3, &keyset->cloud); //temp5 = (xi' AND Bin) OR (xi' AND yi)
//         bootsOR(borrow + 1, temp + 5, temp + 4, &keyset->cloud);
//         bootsCOPY(borrow, borrow + 1, &keyset->cloud);
//     }
//     // bootsCOPY(difference + nb_bits, carry, &keyset->cloud);

//     delete_LweSample_array(6, temp);
//     delete_LweSample_array(2, borrow);
// }

//calculate x-y
void full_subtractor(LweSample *difference, const LweSample *x, const LweSample *y, const int32_t nb_bits,
                const TFheGateBootstrappingCloudKeySet *bk, const LweParams *in_out_params) {
    // carries
    LweSample *borrow = new_LweSample_array(2, in_out_params);
    
    // first carry initialized to 0
    bootsCONSTANT(borrow, 0, bk);
    
    // temps
    LweSample *temp = new_LweSample_array(6, in_out_params);

    for (int32_t i = 0; i < nb_bits; ++i) {
        //sumi = xi XOR yi XOR carry(i-1) 
        bootsXOR(temp, x + i, y + i, bk); // temp = xi XOR yi
        bootsXOR(difference + i, temp, borrow, bk);

        // carry = (xi AND yi) XOR (carry(i-1) AND (xi XOR yi))
        bootsNOT(temp + 1, x + i, bk); // temp1 = xi'
        bootsAND(temp + 2, temp + 1, borrow, bk); // temp2 = xi' AND Bin
        bootsAND(temp + 3, temp + 1, y + i, bk);  // temp3 = xi' AND yi
        bootsAND(temp + 4, y + i, borrow, bk);    //temp4 = yi AND Bin
        bootsOR(temp + 5, temp + 2, temp + 3, bk); //temp5 = (xi' AND Bin) OR (xi' AND yi)
        bootsOR(borrow + 1, temp + 5, temp + 4, bk);
        bootsCOPY(borrow, borrow + 1, bk);
    }
    // bootsCOPY(difference + nb_bits, carry, bk);

    delete_LweSample_array(6, temp);
    delete_LweSample_array(2, borrow);
}

// ? returns 1 if y >= x, 0 if y < x ???
void comparison_MUX(LweSample *comp, const LweSample *x, const LweSample *y, const int32_t nb_bits,
                    const TFheGateBootstrappingCloudKeySet *bk, const LweParams *in_out_params) {
    // carries
    LweSample *carry = new_LweSample_array(2, in_out_params);
    bootsCONSTANT(carry, 1, bk); // first carry initialized to 1
    // temps
    LweSample *temp = new_LweSample(in_out_params);

    for (int32_t i = 0; i < nb_bits; ++i) {
        bootsXOR(temp, x + i, y + i, bk); // temp = xi XOR yi
        bootsMUX(carry + 1, temp, y + i, carry, bk);
        bootsCOPY(carry, carry + 1, bk);
    }
    bootsCOPY(comp, carry, bk);

    delete_LweSample(temp);
    delete_LweSample_array(2, carry);
}

//calculate x*y,  uses same number of bits to represent multiplication result, might cause overflow
void full_multiplicator(LweSample *product, const LweSample *x, const LweSample *y, const int32_t nb_bits,
                const TFheGateBootstrappingCloudKeySet *bk, const LweParams *in_out_params, TFheGateBootstrappingSecretKeySet* key) {
    int ai;

    for (int j=0; j<nb_bits; j++){
            ai = bootsSymDecrypt(&x[j], key);
            cout << "x[" << j << "]" << " = " << ai << endl;
    }
    for (int j=0; j<nb_bits; j++){
            ai = bootsSymDecrypt(&y[j], key);
            cout << "y[" << j << "]" << " = " << ai << endl;
    }
    // temps
    // LweSample *temp = new_LweSample_array(nb_bits, in_out_params);
    const TFheGateBootstrappingParameterSet* params = key->params;
    LweSample *temp = new_gate_bootstrapping_ciphertext_array(nb_bits,params);



    LweSample *partialsum = new_LweSample_array(nb_bits + 1, in_out_params);
    for (int j=0; j<nb_bits; j++){
            ai = bootsSymDecrypt(&partialsum[j], key);
            cout << "initial partialsum[" << j << "]" << " = " << ai << endl;
    }
    // for (int i=0; i<numberofbits; i++) {
    //             int ai = bootsSymDecrypt(&product[i], key);
    //             int_answer |= (ai<<i);
    //         }


    for (int i=0; i< nb_bits; i++){
        cout << "doing " << i << "th loop" << endl;
        for (int j=0; j<nb_bits; j++){
            bootsAND(temp+j, &x[j], &y[i], bk);
            ai = bootsSymDecrypt(&temp[j], key);
            cout << "ai = " << ai << endl;
        }
        // LweSample *temp2 = new_LweSample_array(nb_bits, in_out_params);
        LweSample *temp2 = new_gate_bootstrapping_ciphertext_array(nb_bits,params);
        for (int j=0; j<nb_bits; j++){
            bootsCOPY(&temp2[j], &partialsum[j], bk);
        }
        // bootsCOPY(temp2, partialsum, bk);
        for (int j=0; j<nb_bits; j++){
            ai = bootsSymDecrypt(&temp2[j], key);
            cout << "copied temp2[" << j << "]" << " = " << ai << endl;
        }
        for (int j=0; j<nb_bits; j++){
            ai = bootsSymDecrypt(&temp[j], key);
            cout << "temp before addition temp[" << j << "]" << " = " << ai << endl;
        }
        for (int j=0; j<nb_bits; j++){
            ai = bootsSymDecrypt(&partialsum[j], key);
            cout << "partialsum before addition partialsum[" << j << "]" << " = " << ai << endl;
        }
        full_adder(partialsum, temp, temp2, nb_bits, bk, in_out_params, key);
        // for (int j=0; j<nb_bits; j++){
        //     ai = bootsSymDecrypt(&partialsum[j], key);
        //     cout << "partialsum[" << j << "]" << " = " << ai << endl;
        // }
        int32_t int_answer = 0;
        for (int j=0; j<nb_bits; j++) {
            int ai = bootsSymDecrypt(&partialsum[j], key);
            int_answer |= (ai<<j);
        }
        
        cout << "partialsum int_answer = " << int_answer << endl;
        delete_LweSample_array(nb_bits, temp2);
    }

    bootsCOPY(product, partialsum, bk);

    delete_LweSample_array(nb_bits, temp);
    delete_LweSample_array(nb_bits, partialsum);
    
}
// void *thread_xor(void *arg)
// {
// 	struct CalcSet* input = (struct CalcSet*)arg;
//         bootsXOR(input->r,input->a,input->b,input->EK);

//         pthread_exit((void *)input->r);
// }
// void *thread_mux(void *arg)
// {
// 	struct CalcSet* input = (struct CalcSet*)arg;
// 	bootsMUX(input->r,input->a,input->b,input->c,input->EK);
	
//         pthread_exit((void *)input->r);
// }
// LweSample* CipherAdd(LweSample* a,LweSample* b,const TFheGateBootstrappingCloudKeySet* EK,int minbit) // special Add functions used for Multiplications
// {

//         LweSample *carry = new_gate_bootstrapping_ciphertext(EK->params);
//         LweSample *Result = new_gate_bootstrapping_ciphertext_array(numberofbits,EK->params);

// 	pthread_t thread[2];
//         struct CalcSet *in[2];


// 	for(int i= numberofbits-1; i>minbit ; i--)
// 	{
// 		bootsCOPY(&Result[i],&a[i],EK);
// 	}

//         for(int i= minbit ; i >= 0 ; i--)
//         {
//                 if(i == minbit)
//                 {
//                         bootsAND(carry,&a[i],&b[i],EK);
//                         bootsXOR(&Result[i],&a[i],&b[i],EK);
//                 }
//                 else
//                 {

// 			for(int num =0 ; num<2; num++)  in[num]= (struct CalcSet*)malloc(sizeof(struct CalcSet));

//                         LweSample *b1;
//                         b1 = new_gate_bootstrapping_ciphertext(EK->params);
//                         bootsXOR(b1,&a[i],&b[i],EK);

// 			LweSample *b2 = new_gate_bootstrapping_ciphertext(EK->params);
//                         bootsCOPY(b2,carry,EK);

//                         in[0]->r = &Result[i];
//                         in[0]->a = b1;
//                         in[0]->b = b2;
//                         in[0]->EK= EK;

//                         in[1]->r = carry;
//                         in[1]->a = b1;
//                         in[1]->b = b2;
//                         in[1]->c = &a[i];
//                         in[1]->EK= EK;

//                         pthread_create(&thread[0],NULL,&thread_xor,(void*)in[0]);
//                         pthread_create(&thread[1],NULL,&thread_mux,(void*)in[1]);

//                         pthread_join(thread[0],(void **)&b1);
//                         pthread_join(thread[1],(void **)&b2);


//                         //bootsXOR(&Result[i],b1,carry,EK);
//                         //bootsMUX(carry,b1,carry,&a[i],EK);
//                 }
//         }
//         return Result;
// }

// void *thread_adder(void *arg)
// {
//         struct CipherSet* input = (struct CipherSet*)arg;


//         LweSample* Ret = CipherAdd(input->a,input->b,input->EK,input->minbit);

// 	pthread_exit((void *)Ret);
// }

// void *thread_initializer(void *arg)
// {
// 	struct MulInitSet* input = (struct MulInitSet*)arg;
	
// 	input->C = new_gate_bootstrapping_ciphertext_array(numberofbits,input->EK->params);
// 	for(int i=input->ind;i<numberofbits;i++)	bootsAND(&input->C[i-input->ind],&input->a[numberofbits-1-input->ind],&input->b[i],input->EK);	
// 	for(int i=numberofbits-input->ind;i<numberofbits;i++)	bootsCONSTANT(&input->C[i],0,input->EK);
// 	pthread_exit((void *)input->C);
// }
// void *zero_initializer(void *arg)
// {
//         struct MulInitSet* input = (struct MulInitSet*)arg;

//         input->C = new_gate_bootstrapping_ciphertext_array(numberofbits,input->EK->params);
//         for(int i=0;i<numberofbits;i++)     bootsCONSTANT(&input->C[i],0,input->EK);
//         pthread_exit((void *)input->C);
// }

// LweSample* CipherMul(LweSample* a,LweSample* b,const TFheGateBootstrappingCloudKeySet* EK)	// O(2*n) algorithm = about 
// {
// 	int bin = 1;
// 	while(bin<numberofbits)	bin*=2;
// 	LweSample *Container[bin*2];
//         pthread_t init[bin];

//         /** Boost speed by initializing variables concurrently using threads **/

//         for(int i = 0 ; i < numberofbits ; i++)
//         {
//                 struct MulInitSet *in;
//                 in = (struct MulInitSet*)malloc(sizeof(struct MulInitSet));
//                 in->C = Container[i];
//                 in->a = a;
//                 in->b = b;
//                 in->EK = EK;
//                 in->ind = i;
//                 pthread_create(&init[i],NULL,&thread_initializer,(void*)in);
//         }
// 	for(int i = numberofbits ; i < bin ; i++)
// 	{
// 		struct MulInitSet *in;
//                 in = (struct MulInitSet*)malloc(sizeof(struct MulInitSet));
//                 in->C = Container[i];
//                 in->EK = EK;
//                 pthread_create(&init[i],NULL,&zero_initializer,(void*)in);
// 	}

//         /** Boost speed by using complete binary-tree based thread calculation **/


//         for(int i=0;i<bin;i++)      pthread_join(init[i],(void **)&Container[i]);

//         pthread_t thread[bin];

//         int len = bin/2;
//         int pivot = 0;
//         while(len>0)
//         {
//                 for(int i=0;i<len;i++)
//                 {
//                         struct CipherSet *in;
//                         in = (struct CipherSet*)malloc(sizeof(struct CipherSet));
//                         in->a = Container[pivot+i];
//                         in->b = Container[pivot+2*len-1-i];
// 			if(numberofbits>(i+1+pivot/2))	in->minbit = i+1+pivot/2;
// 			else	in->minbit = numberofbits-1;
//                         in->EK = EK;
//                         pthread_create(&thread[pivot/2+i],NULL,&thread_adder,(void *)in);
//                 }
//                 for(int i=0;i<len;i++)  pthread_join(thread[pivot/2+i],(void **)&Container[pivot+len*2+i]);
//                 pivot+=len*2;
//                 len/=2;
//         }
//         return Container[2*bin-2];
// }





//EXPORT void tLweExtractKey(LweKey* result, const TLweKey* key); //TODO: change the name and put in a .h
//EXPORT void tfhe_createLweBootstrappingKeyFFT(LweBootstrappingKeyFFT* bk, const LweKey* key_in, const TGswKey* rgsw_key);
//EXPORT void tfhe_bootstrapFFT(LweSample* result, const LweBootstrappingKeyFFT* bk, Torus32 mu1, Torus32 mu0, const LweSample* x);


int main(int argc, char *argv[]){
    if(argc!=4){
		printf("Usage : ./filename <num1> <num2> <mode>\n");
        printf("Calculation mode :\n1) Addition\n2) Multiplication\n3) Subtraction\n4) Comparision\n>");
		exit(0);
	}

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
    int32_t arg1,arg2,arg3;
	arg1 = atoi(argv[1]);
	arg2 = atoi(argv[2]);
    arg3 = atoi(argv[3]);
    LweSample *ciphertext1 = new_gate_bootstrapping_ciphertext_array(numberofbits,params);
	LweSample *ciphertext2 = new_gate_bootstrapping_ciphertext_array(numberofbits,params);
    for (int i=0; i<numberofbits; i++) {
        bootsSymEncrypt(&ciphertext1[i], (arg1>>i)&1, key);
        bootsSymEncrypt(&ciphertext2[i], (arg2>>i)&1, key);
    }
    switch(arg3){
        case 1:{
            // LweSample* sum = new_LweSample_array(numberofbits + 1, in_out_params);
            // full_adder(sum, ciphertext1, ciphertext2, numberofbits, bk, in_out_params);
            // //decrypt and rebuild the 32-bit plaintext answer
            // int32_t int_answer = 0;
            // for (int i=0; i<numberofbits; i++) {
            //     int ai = bootsSymDecrypt(&sum[i], key);
            //     int_answer |= (ai<<i);
            // }
            
            // cout << "addition int_answer = " << int_answer << endl;
            break;
        }
        case 2:{
            LweSample* product = new_LweSample_array(numberofbits, in_out_params);
            full_multiplicator(product, ciphertext1, ciphertext2, numberofbits,bk, in_out_params, key);
            //decrypt and rebuild the 32-bit plaintext answer
            int32_t int_answer = 0;
            for (int i=0; i<numberofbits; i++) {
                int ai = bootsSymDecrypt(&product[i], key);
                int_answer |= (ai<<i);
            }
            
            cout << "multiplication int_answer = " << int_answer << endl;


            // //
            // LweSample* product = CipherMul(ciphertext1,ciphertext2,&key->cloud);
            // int32_t int_answer = 0;
            // for (int i=0; i<numberofbits; i++) {
            //     int ai = bootsSymDecrypt(&product[i], key);
            //     int_answer |= (ai<<i);
            // }
            
            // cout << "multiplication int_answer = " << int_answer << endl;

            break;
        }
        case 3:{
            LweSample* difference = new_LweSample_array(numberofbits, in_out_params);

            full_subtractor(difference, ciphertext1, ciphertext2, numberofbits, bk, in_out_params);
            // full_subtractor(difference, ciphertext1, ciphertext2, numberofbits, key, bk, in_out_params);
            int32_t int_answer = 0;
            for (int i=0; i<numberofbits; i++) {
                int ai = bootsSymDecrypt(&difference[i], key);
                int_answer |= (ai<<i);
            }
            
            cout << "subtraction int_answer = " << int_answer << endl;
            break;
        }
        case 4:{
            LweSample *comp = new_LweSample(in_out_params);
            comparison_MUX(comp, ciphertext1, ciphertext2, numberofbits, bk, in_out_params);

            // verification
            {
                // bool messCarry = 1;
                // for (int32_t i = 0; i < numberofbits; ++i) {
                //     bool messX = bootsSymDecrypt(x + i, key);
                //     bool messY = bootsSymDecrypt(y + i, key);

                //     messCarry = (messX ^ messY) ? messY : messCarry;
                // }
                bool messComp = bootsSymDecrypt(comp, key);
                cout << "messComp = " << messComp << endl;
                // if (messComp != messCarry) {
                //     cout << "ERROR!!! " << trial << "," << nb_bits << endl;
                // }
            }
            break;
        }
    }



}



// #ifndef NDEBUG
// extern const TLweKey *debug_accum_key;
// extern const LweKey *debug_extract_key;
// extern const LweKey *debug_in_key;
// #endif

// int32_t main(int32_t argc, char **argv) {
// #ifndef NDEBUG
//     cout << "DEBUG MODE!" << endl;
// #endif
//     const int32_t nb_bits = 16;
//     const int32_t nb_trials = 10;

//     // generate params 
//     int32_t minimum_lambda = 100;
//     TFheGateBootstrappingParameterSet *params = new_default_gate_bootstrapping_parameters(minimum_lambda);
//     const LweParams *in_out_params = params->in_out_params;
//     // generate the secret keyset
//     TFheGateBootstrappingSecretKeySet *keyset = new_random_gate_bootstrapping_secret_keyset(params);


//     for (int32_t trial = 0; trial < nb_trials; ++trial) {

//         // generate samples
//         LweSample *x = new_LweSample_array(nb_bits, in_out_params);
//         LweSample *y = new_LweSample_array(nb_bits, in_out_params);
//         for (int32_t i = 0; i < nb_bits; ++i) {
//             bootsSymEncrypt(x + i, rand() % 2, keyset);
//             bootsSymEncrypt(y + i, rand() % 2, keyset);
//         }
//         // output sum
//         LweSample *sum = new_LweSample_array(nb_bits + 1, in_out_params);



//         // evaluate the addition circuit 
//         cout << "starting bootstrapping " << nb_bits << "-bits addition circuit (FA in MUX version)...trial " << trial
//              << endl;
//         clock_t begin1 = clock();
//         full_adder_MUX(sum, x, y, nb_bits, keyset);
//         clock_t end1 = clock();
//         cout << "finished bootstrappings " << nb_bits << "-bits addition circuit (FA in MUX version)" << endl;
//         cout << "total time (microsecs)... " << (end1 - begin1) << endl;


//         // verification
//         bool messCarry = 0;
//         for (int32_t i = 0; i < nb_bits; ++i) {
//             bool messX = bootsSymDecrypt(x + i, keyset);
//             bool messY = bootsSymDecrypt(y + i, keyset);
//             bool messSum = bootsSymDecrypt(sum + i, keyset);

//             if (messSum != (messX ^ messY ^ messCarry)) {
//                 cout << "ERROR!!! " << trial << "," << i << " - ";
//                 cout << t32tod(lwePhase(x + i, keyset->lwe_key)) << " - ";
//                 cout << t32tod(lwePhase(y + i, keyset->lwe_key)) << " - ";
//                 cout << t32tod(lwePhase(sum + i, keyset->lwe_key)) << endl;
//             }

//             messCarry = messCarry ? (messX || messY) : (messX && messY);
//         }
//         bool messSum = bootsSymDecrypt(sum + nb_bits, keyset);
//         if (messSum != messCarry) {
//             cout << "ERROR!!! " << trial << "," << nb_bits << endl;
//         }





//         // evaluate the addition circuit 
//         cout << "starting bootstrapping " << nb_bits << "-bits addition circuit (FA)...trial " << trial << endl;
//         clock_t begin2 = clock();
//         full_adder(sum, x, y, nb_bits, keyset);
//         clock_t end2 = clock();
//         cout << "finished bootstrappings " << nb_bits << "-bits addition circuit (FA)" << endl;
//         cout << "total time (microsecs)... " << (end2 - begin2) << endl;


//         // verification
//         {
//             bool messCarry = 0;
//             for (int32_t i = 0; i < nb_bits; ++i) {
//                 bool messX = bootsSymDecrypt(x + i, keyset);
//                 bool messY = bootsSymDecrypt(y + i, keyset);
//                 bool messSum = bootsSymDecrypt(sum + i, keyset);

//                 if (messSum != (messX ^ messY ^ messCarry)) {
//                     cout << "ERROR!!! " << trial << "," << i << endl;
//                 }

//                 messCarry = messCarry ? (messX || messY) : (messX && messY);
//             }
//             bool messSum = bootsSymDecrypt(sum + nb_bits, keyset);
//             if (messSum != messCarry) {
//                 cout << "ERROR!!! " << trial << "," << nb_bits << endl;
//             }
//         }


//         LweSample *comp = new_LweSample(in_out_params);
//         // evaluate the addition circuit 
//         cout << "starting bootstrapping " << nb_bits << "-bits comparison...trial " << trial << endl;
//         clock_t begin3 = clock();
//         comparison_MUX(comp, x, y, nb_bits, keyset);
//         clock_t end3 = clock();
//         cout << "finished bootstrappings " << nb_bits << "-bits comparison" << endl;
//         cout << "total time (microsecs)... " << (end3 - begin3) << endl;

//         // verification
//         {
//             bool messCarry = 1;
//             for (int32_t i = 0; i < nb_bits; ++i) {
//                 bool messX = bootsSymDecrypt(x + i, keyset);
//                 bool messY = bootsSymDecrypt(y + i, keyset);

//                 messCarry = (messX ^ messY) ? messY : messCarry;
//             }
//             bool messComp = bootsSymDecrypt(comp, keyset);
//             if (messComp != messCarry) {
//                 cout << "ERROR!!! " << trial << "," << nb_bits << endl;
//             }
//         }


//         delete_LweSample_array(nb_bits + 1, sum);
//         delete_LweSample_array(nb_bits, y);
//         delete_LweSample_array(nb_bits, x);
//     }

//     delete_gate_bootstrapping_secret_keyset(keyset);
//     delete_gate_bootstrapping_parameters(params);

//     return 0;
// }