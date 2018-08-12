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
    //TODO: fix 15
    ifstream inputfile ("/home/taeyun/Desktop/mysqlproxy/datatobedecrypted15.txt");
    if (is_file_empty(inputfile)){
        lua_pushnil(L);
        return 1;
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