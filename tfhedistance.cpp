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

using namespace std;

// int32_t numberofbits = 32;

int32_t numberofbits = 32;

// **********************************************************************************
// ********************************* MAIN *******************************************
// **********************************************************************************


void dieDramatically(string message) {
    cerr << message << endl;
    abort();
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


void full_adder(LweSample *sum, const LweSample *x, const LweSample *y, const int32_t nb_bits,
                const TFheGateBootstrappingSecretKeySet *keyset) {
    const LweParams *in_out_params = keyset->params->in_out_params;
    // carries
    LweSample *carry = new_LweSample_array(2, in_out_params);
    bootsSymEncrypt(carry, 0, keyset); // first carry initialized to 0
    // temps
    LweSample *temp = new_LweSample_array(3, in_out_params);

    for (int32_t i = 0; i < nb_bits; ++i) {
        //sumi = xi XOR yi XOR carry(i-1) 
        bootsXOR(temp, x + i, y + i, &keyset->cloud); // temp = xi XOR yi
        bootsXOR(sum + i, temp, carry, &keyset->cloud);

        // carry = (xi AND yi) XOR (carry(i-1) AND (xi XOR yi))
        bootsAND(temp + 1, x + i, y + i, &keyset->cloud); // temp1 = xi AND yi
        bootsAND(temp + 2, carry, temp, &keyset->cloud); // temp2 = carry AND temp
        bootsXOR(carry + 1, temp + 1, temp + 2, &keyset->cloud);
        bootsCOPY(carry, carry + 1, &keyset->cloud);
    }
    bootsCOPY(sum + nb_bits, carry, &keyset->cloud);

    delete_LweSample_array(3, temp);
    delete_LweSample_array(2, carry);
}

//calculate x-y
void full_subtractor(LweSample *difference, const LweSample *x, const LweSample *y, const int32_t nb_bits,
                const TFheGateBootstrappingSecretKeySet *keyset) {
    const LweParams *in_out_params = keyset->params->in_out_params;
    // carries
    LweSample *borrow = new_LweSample_array(2, in_out_params);
    bootsSymEncrypt(borrow, 0, keyset); // first carry initialized to 0
    // temps
    LweSample *temp = new_LweSample_array(6, in_out_params);

    for (int32_t i = 0; i < nb_bits; ++i) {
        //sumi = xi XOR yi XOR carry(i-1) 
        bootsXOR(temp, x + i, y + i, &keyset->cloud); // temp = xi XOR yi
        bootsXOR(difference + i, temp, borrow, &keyset->cloud);

        // carry = (xi AND yi) XOR (carry(i-1) AND (xi XOR yi))
        bootsNOT(temp + 1, x + i, &keyset->cloud); // temp1 = xi'
        bootsAND(temp + 2, temp + 1, borrow, &keyset->cloud); // temp2 = xi' AND Bin
        bootsAND(temp + 3, temp + 1, y + i, &keyset->cloud);  // temp3 = xi' AND yi
        bootsAND(temp + 4, y + i, borrow, &keyset->cloud);    //temp4 = yi AND Bin
        bootsOR(temp + 5, temp + 2, temp + 3, &keyset->cloud); //temp5 = (xi' AND Bin) OR (xi' AND yi)
        bootsOR(borrow + 1, temp + 5, temp + 4, &keyset->cloud);
        bootsCOPY(borrow, borrow + 1, &keyset->cloud);
    }
    // bootsCOPY(difference + nb_bits, carry, &keyset->cloud);

    delete_LweSample_array(6, temp);
    delete_LweSample_array(2, borrow);
}


void comparison_MUX(LweSample *comp, const LweSample *x, const LweSample *y, const int32_t nb_bits,
                    const TFheGateBootstrappingSecretKeySet *keyset) {
    const LweParams *in_out_params = keyset->params->in_out_params;
    // carries
    LweSample *carry = new_LweSample_array(2, in_out_params);
    bootsSymEncrypt(carry, 1, keyset); // first carry initialized to 1
    // temps
    LweSample *temp = new_LweSample(in_out_params);

    for (int32_t i = 0; i < nb_bits; ++i) {
        bootsXOR(temp, x + i, y + i, &keyset->cloud); // temp = xi XOR yi
        bootsMUX(carry + 1, temp, y + i, carry, &keyset->cloud);
        bootsCOPY(carry, carry + 1, &keyset->cloud);
    }
    bootsCOPY(comp, carry, &keyset->cloud);

    delete_LweSample(temp);
    delete_LweSample_array(2, carry);
}



// LweSample* CipherMul(LweSample* a,LweSample* b,const TFheGateBootstrappingCloudKeySet* EK)	// O(2*n) algorithm = about 
// {
// 	int bin = 1;
// 	while(bin<bitsize)	bin*=2;
// 	LweSample *Container[bin*2];
//         pthread_t init[bin];

//         /** Boost speed by initializing variables concurrently using threads **/

//         for(int i = 0 ; i < bitsize ; i++)
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
// 	for(int i = bitsize ; i < bin ; i++)
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
// 			if(bitsize>(i+1+pivot/2))	in->minbit = i+1+pivot/2;
// 			else	in->minbit = bitsize-1;
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
    if(argc!=3){
		printf("Usage : ./filename <num1> <num2>\n");
		exit(0);
	}

    //reads the secret key from file
    FILE* secret_key = fopen("secret.key","rb");
    TFheGateBootstrappingSecretKeySet* key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
    fclose(secret_key);

	//reads the cloud key from file
    FILE* cloud_key = fopen("cloud.key","rb");
    TFheGateBootstrappingCloudKeySet* bk = new_tfheGateBootstrappingCloudKeySet_fromFile(cloud_key);
    fclose(cloud_key);

	//if necessary, the params are inside the key
    const TFheGateBootstrappingParameterSet* params = key->params;
    const LweParams *in_out_params = params->in_out_params;
    int32_t arg1,arg2;
	arg1 = atoi(argv[1]);
	arg2 = atoi(argv[2]);
    LweSample *ciphertext1 = new_gate_bootstrapping_ciphertext_array(numberofbits,params);
	LweSample *ciphertext2 = new_gate_bootstrapping_ciphertext_array(numberofbits,params);
    for (int i=0; i<numberofbits; i++) {
        bootsSymEncrypt(&ciphertext1[i], (arg1>>i)&1, key);
        bootsSymEncrypt(&ciphertext2[i], (arg2>>i)&1, key);
    }
    

    // LweSample* sum = new_LweSample_array(numberofbits + 1, in_out_params);;
    // full_adder(sum, ciphertext1, ciphertext2, numberofbits, key);
    // //decrypt and rebuild the 32-bit plaintext answer
    // int32_t int_answer = 0;
    // for (int i=0; i<numberofbits; i++) {
    //     int ai = bootsSymDecrypt(&sum[i], key);
    //     int_answer |= (ai<<i);
    // }
    
    // cout << "addition int_answer = " << int_answer << endl;

    // LweSample* difference = new_LweSample_array(numberofbits, in_out_params);;
    // full_subtractor(difference, ciphertext1, ciphertext2, numberofbits, key);
    // int_answer = 0;
    // for (int i=0; i<numberofbits; i++) {
    //     int ai = bootsSymDecrypt(&difference[i], key);
    //     int_answer |= (ai<<i);
    // }
    
    // cout << "subtraction int_answer = " << int_answer << endl;

    LweSample *comp = new_LweSample(in_out_params);
    comparison_MUX(comp, ciphertext1, ciphertext2, numberofbits, key);

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