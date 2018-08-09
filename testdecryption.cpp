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






int main(int argc, char *argv[])
{
    int16_t arg1 = 124;

    //reads the cloud key from file
    FILE* secret_key = fopen("/home/taeyun/Desktop/tensor1_new/secret.key","rb");
    TFheGateBootstrappingSecretKeySet* key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
    fclose(secret_key);

    //if necessary, the params are inside the key
    const TFheGateBootstrappingParameterSet* params = key->params;
    
    LweSample* ciphertext1 = new_gate_bootstrapping_ciphertext_array(16, params);
    for (int i=0; i<16; i++) {
        bootsSymEncrypt(&ciphertext1[i], (arg1>>i)&1, key);
    }

    //read the 16 ciphertexts of the result
    LweSample* answer = new_gate_bootstrapping_ciphertext_array(16, params);
    const int32_t n = params->in_out_params->n;
    // std::cout << "n = " << n << std::endl;


    for (int i=0; i<16; i++) {
        // std::cout << "printing " << i << "th ciphertext" << std::endl;
        for (int j=0; j<n; j++){
            // std::cout << "j = " << j << std::endl;
            // std::cout << "*ciphertext1[" << i << "]->a = " << *(ciphertext1[i].a + sizeof(Torus32) * j) <<std::endl;
            // *(answer[i].a + sizeof(answer[i].a) * j) = *(ciphertext1[i].a + sizeof(ciphertext1[i].a) * j);
            answer[i].a[j] = ciphertext1[i].a[j];
        
        }
        // std::cout << "ciphertext1[" << i << "]->b = " << ciphertext1[i].b << std::endl;
        // std::cout << "ciphertext1[" << i << "]->current_variance = " << ciphertext1[i].current_variance << std::endl;
        // *answer[i].a = *ciphertext1[i].a;
        answer[i].b = ciphertext1[i].b;
        answer[i].current_variance = ciphertext1[i].current_variance;
    }


    // for (int i=0; i<16; i++) {
    //     std::cout << "printing " << i << "th ciphertext" << std::endl;
    //     std::cout << "*ciphertext1[" << i << "]->a = " << *answer[i].a <<std::endl;
    //     std::cout << "ciphertext1[" << i << "]->b = " << answer[i].b << std::endl;
    //     std::cout << "ciphertext1[" << i << "]->current_variance = " << answer[i].current_variance << std::endl;
    //  }
    

    //decrypt and rebuild the answer
    int16_t int_answer = 0;
    for (int i=0; i<16; i++) {
        int ai = bootsSymDecrypt(&answer[i], key)>0;
        int_answer |= (ai<<i);
    }

    std::cout << "answer = " << int_answer << std::endl;

}
