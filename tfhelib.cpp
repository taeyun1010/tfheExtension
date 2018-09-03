#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <iostream>
#include <fstream>
#include <cstdlib>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <cassert>
#include <time.h>
#include <thread>

#include <pthread.h>

#define null 0

using namespace std;

#ifdef __cplusplus
  #include "lua.hpp"
#else
  #include "lua.h"
  #include "lualib.h"
  #include "lauxlib.h"
#endif

#define null 0

//so that name mangling doesn't mess up function names
#ifdef __cplusplus
extern "C"{
#endif


TFheGateBootstrappingSecretKeySet* key;

const TFheGateBootstrappingCloudKeySet* bk;

int bitsize = 16;
int integerbitsize = 16;
int fractionbitsize = 16;

//TODO: deallocate created Doubles
struct Double{
	LweSample *integerpart;
	LweSample *fractionpart;
};

// static int HOMencrypt (lua_State *L) {
//     //check and fetch the arguments
//     //double arg1 = luaL_checknumber (L, 1);
//     int16_t arg1 = luaL_checknumber (L, 1);


//     //reads the cloud key from file
//     FILE* secret_key = fopen("/home/taeyun/Desktop/tensor1_new/secret.key","rb");
//     TFheGateBootstrappingSecretKeySet* key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
//     fclose(secret_key);

//     //if necessary, the params are inside the key
//     const TFheGateBootstrappingParameterSet* params = key->params;
    
//     LweSample* ciphertext1 = new_gate_bootstrapping_ciphertext_array(16, params);
//     for (int i=0; i<16; i++) {
//         bootsSymEncrypt(&ciphertext1[i], (arg1>>i)&1, key);
//     }

//     //push the results
//     lua_pushnumber(L, arg1);

//     //return number of results
//     return 1;
// }

// //encrypts given integer
// static LweSample* encryptInteger(int plaintext, TFheGateBootstrappingSecretKeySet* key){
// 	LweSample *ciphertext = new_gate_bootstrapping_ciphertext_array(bitsize,key->params);
	
// 	for(int i=0;i<bitsize;i++)
// 	{
// 		bootsSymEncrypt(&ciphertext[bitsize-1-i],(plaintext>>i)&0x01,key);
// 	}
// 	return ciphertext;
// }

static void stackDump (lua_State *L) {
    int i;
    int top = lua_gettop(L);
    for (i = 1; i <= top; i++) {  /* repeat for each level */
    int t = lua_type(L, i);
    switch (t) {

        case LUA_TSTRING:  /* strings */
        printf("`%s'", lua_tostring(L, i));
        break;

        case LUA_TBOOLEAN:  /* booleans */
        printf(lua_toboolean(L, i) ? "true" : "false");
        break;

        case LUA_TNUMBER:  /* numbers */
        printf("%g", lua_tonumber(L, i));
        break;

        default:  /* other values */
        printf("%s", lua_typename(L, t));
        break;

    }
    printf("  ");  /* put a separator */
    }
    printf("\n");  /* end the listing */
}

bool is_file_empty(std::ifstream& pFile)
{
    return pFile.peek() == std::ifstream::traits_type::eof();
}

//decrypts ciphertext in /home/taeyun/Desktop/mysqlproxy/datatobedecrypted.txt and returns resulting integer
static int decryptCiphertext(lua_State *L){
    string line;
    int16_t int_answer = 0;
    //reads the secret key from file
    FILE* secret_key = fopen("/home/taeyun/Desktop/tensor1_new/secret.key","rb");
    key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
    fclose(secret_key);
    //if necessary, the params are inside the key
    const TFheGateBootstrappingParameterSet* params = key->params;

    //read the 16 ciphertexts of the result
    LweSample* ciphertext = new_gate_bootstrapping_ciphertext_array(bitsize, params);
    const int32_t n = params->in_out_params->n;
    // //TODO: fix 15
    // ifstream inputfile ("/home/taeyun/Desktop/mysqlproxy/datatobedecrypted15.txt");
    // if (is_file_empty(inputfile)){
    //     lua_pushnil(L);
    //     return 1;
    // }

    for(int i=0; i<16; i++){
        ifstream inputfile ("/home/taeyun/Desktop/mysqlproxy/datatobedecrypted" + to_string(i)+ ".txt");
        if (is_file_empty(inputfile)){
            lua_pushnil(L);
            return 1;
        }
    }

    for (int i=0; i<16; i++) {
        ifstream inputfile ("/home/taeyun/Desktop/mysqlproxy/datatobedecrypted" + to_string(i) + ".txt");
        // if (is_file_empty(inputfile)){
        //     lua_pushnil(L);
        //     return 1;
        // }
        // std::cout << "printing " << i << "th ciphertext" << std::endl;
        for (int j=0; j<n; j++){
            // std::cout << "j = " << j << std::endl;
            // std::cout << "*ciphertext1[" << i << "]->a = " << *(ciphertext1[i].a + sizeof(Torus32) * j) <<std::endl;
            // *(answer[i].a + sizeof(answer[i].a) * j) = *(ciphertext1[i].a + sizeof(ciphertext1[i].a) * j);
            getline(inputfile, line);
            ciphertext[i].a[j] = stoi(line);
        
        }
        // std::cout << "ciphertext1[" << i << "]->b = " << ciphertext1[i].b << std::endl;
        // std::cout << "ciphertext1[" << i << "]->current_variance = " << ciphertext1[i].current_variance << std::endl;
        // *answer[i].a = *ciphertext1[i].a;
        getline(inputfile, line);
        ciphertext[i].b = stoi(line);
        getline(inputfile, line);
        ciphertext[i].current_variance = stod(line);
        inputfile.close();
    }
    //decrypt and rebuild the answer
    for (int i=0; i<16; i++) {
        int ai = bootsSymDecrypt(&ciphertext[i], key)>0;
        int_answer |= (ai<<i);
    }

    // std::cout << "answer = " << int_answer << std::endl;
    
    lua_pushnumber(L, int_answer);
    return 1;
}

//decrypts ciphertext in /home/taeyun/Desktop/mysqlproxy/doubletobedecrypted.txt and returns resulting double
static int decryptDouble(lua_State *L){
    string line;
    double double_answer = 0;
    //reads the secret key from file
    FILE* secret_key = fopen("/home/taeyun/Desktop/tensor1_new/secret.key","rb");
    key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
    fclose(secret_key);
    //if necessary, the params are inside the key
    const TFheGateBootstrappingParameterSet* params = key->params;

    //read the 16 ciphertexts of the result
    LweSample* integerpart = new_gate_bootstrapping_ciphertext_array(integerbitsize, params);
    LweSample* fractionpart = new_gate_bootstrapping_ciphertext_array(fractionbitsize, params);
    const int32_t n = params->in_out_params->n;
    // //TODO: fix 15
    // ifstream inputfile ("/home/taeyun/Desktop/mysqlproxy/datatobedecrypted15.txt");
    // if (is_file_empty(inputfile)){
    //     lua_pushnil(L);
    //     return 1;
    // }

    for(int i=0; i<(integerbitsize + fractionbitsize); i++){
        ifstream inputfile ("/home/taeyun/Desktop/mysqlproxy/doubletobedecrypted" + to_string(i)+ ".txt");
        if (is_file_empty(inputfile)){
            lua_pushnil(L);
            return 1;
        }
    }

    for (int i=0; i<(integerbitsize + fractionbitsize); i++) {
        ifstream inputfile ("/home/taeyun/Desktop/mysqlproxy/doubletobedecrypted" + to_string(i) + ".txt");
        // if (is_file_empty(inputfile)){
        //     lua_pushnil(L);
        //     return 1;
        // }
        // std::cout << "printing " << i << "th ciphertext" << std::endl;
        for (int j=0; j<n; j++){
            // std::cout << "j = " << j << std::endl;
            // std::cout << "*ciphertext1[" << i << "]->a = " << *(ciphertext1[i].a + sizeof(Torus32) * j) <<std::endl;
            // *(answer[i].a + sizeof(answer[i].a) * j) = *(ciphertext1[i].a + sizeof(ciphertext1[i].a) * j);
            getline(inputfile, line);
            ciphertext[i].a[j] = stoi(line);
        
        }
        // std::cout << "ciphertext1[" << i << "]->b = " << ciphertext1[i].b << std::endl;
        // std::cout << "ciphertext1[" << i << "]->current_variance = " << ciphertext1[i].current_variance << std::endl;
        // *answer[i].a = *ciphertext1[i].a;
        getline(inputfile, line);
        ciphertext[i].b = stoi(line);
        getline(inputfile, line);
        ciphertext[i].current_variance = stod(line);
        inputfile.close();
    }
    //decrypt and rebuild the answer
    for (int i=0; i<16; i++) {
        int ai = bootsSymDecrypt(&ciphertext[i], key)>0;
        int_answer |= (ai<<i);
    }

    // std::cout << "answer = " << int_answer << std::endl;
    
    lua_pushnumber(L, double_answer);
    return 1;
}

//encrypts given integer
static int encryptInteger(lua_State *L){
    //check and fetch the arguments
    //double arg1 = luaL_checknumber (L, 1);
    int16_t plaintext = luaL_checknumber (L, 1);

    //reads the secret key from file
    FILE* secret_key = fopen("/home/taeyun/Desktop/tensor1_new/secret.key","rb");
    key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
    fclose(secret_key);

	// //reads the cloud key from file
    // FILE* cloud_key = fopen("/home/taeyun/Desktop/tensor1_new/cloud.key","rb");
    // bk = new_tfheGateBootstrappingCloudKeySet_fromFile(cloud_key);
    // fclose(cloud_key);

	LweSample *ciphertext = new_gate_bootstrapping_ciphertext_array(bitsize,key->params);
	
	// for(int i=0;i<bitsize;i++)
	// {
	// 	bootsSymEncrypt(&ciphertext[bitsize-1-i],(plaintext>>i)&0x01,key);
	// }

    for (int i=0; i<bitsize; i++) {
        bootsSymEncrypt(&ciphertext[i], (plaintext>>i)&1, key);
    }


    // //push the results
    // lua_pushnumber(L, 1124.235);
    // lua_pushnumber(L, 251.346);

    // //return number of results
	// return 2;

    //push the results

    // for(int i=0;i<bitsize;i++)

    // stackDump(L);

    // printf("try to grow stack: %d\n", lua_checkstack(L, (bitsize * 502)));

    //first write to a file so lua script can read encrypted data
    ofstream outfile ("/home/taeyun/Desktop/mysqlproxy/encryptedInteger.txt");
    for(int i=0;i<bitsize;i++)
	{
        //TODO: replace 500 with n
        // for (int j=0; j<500; j++){
        for (int j=0; j<500; j++){
            // cout << "ciphertext[" << i << "].a[" << j << "] = " << ciphertext[i].a[j] << endl;
		    // lua_pushnumber(L, ciphertext[i].a[j]);
            outfile << ciphertext[i].a[j] << endl;

        }
        // cout << "ciphertext[" << i << "].b = " << ciphertext[i].b << endl;
        // lua_pushnumber(L, ciphertext[i].b);
        outfile << ciphertext[i].b << endl;
        // cout << "ciphertext[" << i << "].var = " << ciphertext[i].current_variance << endl;
        // lua_pushnumber(L, ciphertext[i].current_variance);
        outfile << ciphertext[i].current_variance << endl;
	}

    // stackDump(L);

    // lua_pushnumber(L,1);

    // cout << "got to here" << endl;
    delete_gate_bootstrapping_ciphertext_array(bitsize, ciphertext);    
    // cout << "got to here2 " << endl;
    //return number of results
    //TODO: replace 502 with n+2
	return 0;
    // return 1;
    // return (3);

}

//encrypts given integer part of Double
// ciphertext[0] holds least significant bit
// ciphertext[integerbitsize-1] holds the most significant bit 
LweSample* encryptIntegerpart(int plaintext, TFheGateBootstrappingSecretKeySet* key){
	LweSample *ciphertext = new_gate_bootstrapping_ciphertext_array(integerbitsize,key->params);
	
	for(int i=0;i<integerbitsize;i++)
	{
		bootsSymEncrypt(&ciphertext[i],(plaintext>>i)&0x01,key);
		
		// //
		// int temp = bootsSymDecrypt(&ciphertext[integerbitsize-1-i], key);
		// cout << "integerpart[" << i << "] = " << temp << endl;
		// //
	}
	return ciphertext;
}




//when plaintext is given in double type   i.e. 0.xxx
//encrypts given fractional part, where argument plaintext is given as 41 if integer was 124.41
LweSample* encryptFractionpart(double plaintext, TFheGateBootstrappingSecretKeySet* key){
    // plaintext = fabs(plaintext);

	LweSample *ciphertext = new_gate_bootstrapping_ciphertext_array(fractionbitsize,key->params);
	// int numdigitsbefore, numdigitsafter;
	for(int i=fractionbitsize-1;i>=0;i--)
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

//given double, encrypts it to Double
Double encryptDouble(double plaintext, TFheGateBootstrappingSecretKeySet* key){
    Double result;

    //fraction part first, then integerpart, from least significant to most significant
    // for instance, 00100101 for -5.75 using 4 bits for decimal and 4 bits for fraction parts
    int bitholder[(integerbitsize + fractionbitsize)];
    double integral;
    int integralint;
    double fractional = modf(plaintext, &integral);
    integralint = integral;
    LweSample *integerpart = new_gate_bootstrapping_ciphertext_array(integerbitsize,key->params);
    LweSample *fractionpart = new_gate_bootstrapping_ciphertext_array(fractionbitsize,key->params);
    //if plaintext is positive 
    if(plaintext >= 0){
        integerpart = encryptIntegerpart(integralint, key);
        // fractionpart = encryptFractionpart(128, key);
        fractionpart = encryptFractionpart(fractional, key);
        // int result = decryptIntegerpart(integerpart, key);
        // cout << "integerpart decrypted result = " << result << endl;
        // int result = decryptIntegerpart(integerpart1, key);
        // cout << "integerpart decrypted result = " << result << endl;
        // double fractionresult = decryptFractionpart(fractionpart1, key);
        // cout << "fractionpart1 decrypted result = " << fractionresult << endl;
        
    }

    //if plaintext is negative, https://stackoverflow.com/questions/42439749/how-to-convert-negative-fraction-decimal-to-binary to calculate bits of negative double
    else {
        integralint = (-1) * integralint;
        fractional = (-1) * fractional;
        for(int i=0;i<integerbitsize;i++)
        {
            bitholder[fractionbitsize+i] = (integralint>>i)&0x01;


            // bootsSymEncrypt(&ciphertext[integerbitsize-1-i],(plaintext>>i)&0x01,key);
            
            // //
            // int temp = bootsSymDecrypt(&ciphertext[integerbitsize-1-i], key);
            // cout << "integerpart[" << i << "] = " << temp << endl;
            // //
        }
        for(int i=(fractionbitsize-1);i>=0;i--)
        {
            // cout << "plaintext = " << plaintext << endl;
            // numdigitsbefore = numDigits(plaintext);
            fractional = fractional * 2;
            // numdigitsafter = numDigits(plaintext);
            if (fractional >= 1){
                // bootsSymEncrypt(&ciphertext[fractionbitsize-1-i],1,key);
                // bootsSymEncrypt(&ciphertext[i],1,key);
                bitholder[i] = 1;
                // //
                // int temp = bootsSymDecrypt(&ciphertext[i], key);
                // cout << "fractionpart[" << i << "] = " << temp << endl;
                // //
                
                //get rid of the leading 1
                fractional = fractional - 1;
            }
            else {
                // bootsSymEncrypt(&ciphertext[fractionbitsize-1-i],0,key);
                // bootsSymEncrypt(&ciphertext[i],0,key);
                bitholder[i] = 0;

                // //
                // int temp = bootsSymDecrypt(&ciphertext[i], key);
                // cout << "fractionpart[" << i << "] = " << temp << endl;
                // //
            
            }
            // bootsSymEncrypt(&ciphertext[fractionbitsize-1-i],(fractional>>i)&0x01,key);
        }


        // for (int i=0; i<(integerbitsize+fractionbitsize);i++){
        //     cout << "bitholder[" << i << "] = " << bitholder[i] << endl;
        // }

        //bits of positive representation has been calculated, invert all bits
        for (int i=0; i<(integerbitsize+fractionbitsize);i++){
            if (bitholder[i] == 1){
                bitholder[i] = 0;
            }
            else{
                bitholder[i] = 1;
            }
        }

        // cout <<"done with inverting " << endl;
        // for (int i=0; i<(integerbitsize+fractionbitsize);i++){
        //     cout << "bitholder[" << i << "] = " << bitholder[i] << endl;
        // }

        //add 1 to the least significant digit
        int carry = 1;
        for (int i=0; i<(integerbitsize+fractionbitsize);i++){
            switch (bitholder[i] + carry){
                case 2:{
                    bitholder[i] = 0;
                    carry = 1;  
                    break;
                }
                case 1:{
                    bitholder[i] = 1;
                    carry = 0;
                    break;
                }
                case 0:{
                    bitholder[i] = 0;
                    carry = 0;
                    break;
                }
            }
        }

        cout <<"done with addition of 1" << endl;
        for (int i=0; i<(integerbitsize+fractionbitsize);i++){
            cout << "bitholder[" << i << "] = " << bitholder[i] << endl;
        }

        //bitholder now has bits for negative double values, must encrypt
        for(int i=0;i<integerbitsize;i++)
        {
            bootsSymEncrypt(&integerpart[i],bitholder[fractionbitsize+i],key);
            
            // //
            // int temp = bootsSymDecrypt(&ciphertext[integerbitsize-1-i], key);
            // cout << "integerpart[" << i << "] = " << temp << endl;
            // //
        }
        for(int i=0;i<fractionbitsize;i++)
        {
            bootsSymEncrypt(&fractionpart[i],bitholder[i],key);
            
            // //
            // int temp = bootsSymDecrypt(&ciphertext[integerbitsize-1-i], key);
            // cout << "integerpart[" << i << "] = " << temp << endl;
            // //
        }


    }
    result.integerpart = integerpart;
    result.fractionpart = fractionpart;
    return result;

    
}

//encrypts given double
static int encryptdouble(lua_State *L){
    //check and fetch the arguments
    double plaintext = luaL_checknumber (L, 1);

    //reads the secret key from file
    FILE* secret_key = fopen("/home/taeyun/Desktop/tensor1_new/secret.key","rb");
    key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
    fclose(secret_key);

    Double ciphertext = encryptDouble(plaintext, key);

    //first write to a file so lua script can read encrypted data
    ofstream outfile ("/home/taeyun/Desktop/mysqlproxy/encrypteddouble.txt");
    LweSample* integerpart = ciphertext.integerpart;
    LweSample* fractionpart = ciphertext.fractionpart;
    for(int i=0;i<integerbitsize;i++)
	{
        //TODO: replace 500 with n
        // for (int j=0; j<500; j++){
        for (int j=0; j<500; j++){
            // cout << "ciphertext[" << i << "].a[" << j << "] = " << ciphertext[i].a[j] << endl;
		    // lua_pushnumber(L, ciphertext[i].a[j]);
            outfile << integerpart[i].a[j] << endl;

        }
        // cout << "ciphertext[" << i << "].b = " << ciphertext[i].b << endl;
        // lua_pushnumber(L, ciphertext[i].b);
        outfile << integerpart[i].b << endl;
        // cout << "ciphertext[" << i << "].var = " << ciphertext[i].current_variance << endl;
        // lua_pushnumber(L, ciphertext[i].current_variance);
        outfile << integerpart[i].current_variance << endl;
	}
    for(int i=0;i<fractionbitsize;i++)
	{
        //TODO: replace 500 with n
        // for (int j=0; j<500; j++){
        for (int j=0; j<500; j++){
            // cout << "ciphertext[" << i << "].a[" << j << "] = " << ciphertext[i].a[j] << endl;
		    // lua_pushnumber(L, ciphertext[i].a[j]);
            outfile << fractionpart[i].a[j] << endl;

        }
        // cout << "ciphertext[" << i << "].b = " << ciphertext[i].b << endl;
        // lua_pushnumber(L, ciphertext[i].b);
        outfile << fractionpart[i].b << endl;
        // cout << "ciphertext[" << i << "].var = " << ciphertext[i].current_variance << endl;
        // lua_pushnumber(L, ciphertext[i].current_variance);
        outfile << fractionpart[i].current_variance << endl;
	}

    // cout << "got to here" << endl;
    delete_gate_bootstrapping_ciphertext_array(integerbitsize, integerpart);    
    delete_gate_bootstrapping_ciphertext_array(fractionbitsize, fractionpart);
    // cout << "got to here2 " << endl;
    //return number of results
    //TODO: replace 502 with n+2
	return 0;
    // return 1;
    // return (3);

}


// //encrypts given integer
// static int encryptInteger(lua_State *L){
//     //check and fetch the arguments
//     //double arg1 = luaL_checknumber (L, 1);
//     int16_t plaintext = luaL_checknumber (L, 1);

//     cout << "plaintext = " << plaintext << endl;

//     //push the results
//     lua_pushnumber(L, 1124.235);
//     lua_pushnumber(L, 251.346);

//     //return number of results
// 	return 2;
// }

// static int HOMencrypt (lua_State *L) {
//     //check and fetch the arguments
//     //double arg1 = luaL_checknumber (L, 1);
//     int16_t arg1 = luaL_checknumber (L, 1);

//     char *SKfilename = "/home/taeyun/Desktop/tensor1_new/sec.key";
    

//     FHEW::Setup();

//     LWE::SecretKey* SK;

//     SK = LoadSecretKey(SKfilename);

//     LWE::CipherText* ct = new LWE::CipherText;
//     LWE::Encrypt(ct, *SK, arg1);

//     // for (int i=0; i < n; i++){
//     //     std::cout << "a[" << i << "] = " << ct->a[i] << std::endl;

//     // }
//     // std::cout << "b = " << ct->b << std::endl;

//     //push the results
//     lua_pushnumber(L, arg1);

//     //return number of results
//     return 1;
// }


//library to be registered
static const struct luaL_Reg mylib [] = {
      {"HOMencrypt", encryptInteger},
      {"HOMdecrypt", decryptCiphertext},
      {"HOMencryptdouble", encryptdouble},
      {NULL, NULL}  /* sentinel */
    };

//name of this function is not flexible
int luaopen_mylib (lua_State *L){
    luaL_register(L, "mylib", mylib);
    return 1;
}


#ifdef __cplusplus
}
#endif