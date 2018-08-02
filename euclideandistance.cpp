#include "tfhedistance.h"
#include "operations.h"

using namespace std;

int main (int argc, char* argv[]){
    if(argc!=5){
		printf("Usage : ./filename <num1> <num2> <mode> <numberofbits>\n");
        printf("Calculation mode :\n1) Addition\n2) Multiplication\n3) Subtraction\n4) Comparison\n>");
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
    int32_t arg1,arg2,arg3,arg4;
	arg1 = atoi(argv[1]);
	arg2 = atoi(argv[2]);
    arg3 = atoi(argv[3]);
    arg4 = atoi(argv[4]);
    int numberofbits = arg4;
    LweSample *ciphertext1 = new_gate_bootstrapping_ciphertext_array(numberofbits,params);
	LweSample *ciphertext2 = new_gate_bootstrapping_ciphertext_array(numberofbits,params);
    for (int i=0; i<numberofbits; i++) {
        bootsSymEncrypt(&ciphertext1[i], (arg1>>i)&1, key);
        bootsSymEncrypt(&ciphertext2[i], (arg2>>i)&1, key);
    }
    switch(arg3){
        case 1:{
            LweSample* sum = new_LweSample_array(numberofbits + 1, in_out_params);
            full_adder(sum, ciphertext1, ciphertext2, numberofbits, bk, in_out_params);
            //decrypt and rebuild the 32-bit plaintext answer
            int32_t int_answer = 0;
            for (int i=0; i<numberofbits; i++) {
                int ai = bootsSymDecrypt(&sum[i], key);
                int_answer |= (ai<<i);
            }
            
            cout << "addition int_answer = " << int_answer << endl;
            break;
        }
        case 2:{
            LweSample* product = new_LweSample_array(numberofbits, in_out_params);
            full_multiplicator(product, ciphertext1, ciphertext2, numberofbits, bk, in_out_params,key);
            //decrypt and rebuild the 32-bit plaintext answer
            int32_t int_answer = 0;
            for (int i=0; i<numberofbits; i++) {
                int ai = bootsSymDecrypt(&product[i], key);
                int_answer |= (ai<<i);
            }
            
            cout << "multiplication int_answer = " << int_answer << endl;
            break;
        }
    }
}