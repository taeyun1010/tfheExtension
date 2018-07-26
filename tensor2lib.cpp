#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <iostream>
#include <cstdlib>


// #include <tfhe/tfhe.h>
// #include <tfhe/tfhe_io.h>
#include "/home/taeyun/Desktop/Homomorphic_Encryption/Homomorphic/FHEW.h"
#include "/home/taeyun/Desktop/Homomorphic_Encryption/Homomorphic/cmd/common.h"
#include "/home/taeyun/Desktop/Homomorphic_Encryption/Homomorphic/params.h"


#include <cassert>
#include <time.h>

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


static int HOMencrypt (lua_State *L) {
    //check and fetch the arguments
    //double arg1 = luaL_checknumber (L, 1);
    int16_t arg1 = luaL_checknumber (L, 1);

    char *SKfilename = "/home/taeyun/Desktop/tensor1_new/sec.key";
    

    FHEW::Setup();

    LWE::SecretKey* SK;

    SK = LoadSecretKey(SKfilename);

    LWE::CipherText* ct = new LWE::CipherText;
    LWE::Encrypt(ct, *SK, arg1);

    // for (int i=0; i < n; i++){
    //     std::cout << "a[" << i << "] = " << ct->a[i] << std::endl;

    // }
    // std::cout << "b = " << ct->b << std::endl;

    //push the results
    lua_pushnumber(L, arg1);

    //return number of results
    return 1;
}


//library to be registered
static const struct luaL_Reg mylib [] = {
      {"HOMencrypt", HOMencrypt},
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