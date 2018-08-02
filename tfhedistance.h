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

void comparison_MUX(LweSample *comp, const LweSample *x, const LweSample *y, const int32_t nb_bits,const TFheGateBootstrappingCloudKeySet *bk, const LweParams *in_out_params);
void full_subtractor(LweSample *difference, const LweSample *x, const LweSample *y, const int32_t nb_bits,const TFheGateBootstrappingCloudKeySet *bk, const LweParams *in_out_params);
void full_adder(LweSample *sum, const LweSample *x, const LweSample *y, const int32_t nb_bits,const TFheGateBootstrappingCloudKeySet *bk, const LweParams *in_out_params);
void full_multiplicator(LweSample *product, const LweSample *x, const LweSample *y, const int32_t nb_bits,
                const TFheGateBootstrappingCloudKeySet *bk, const LweParams *in_out_params, TFheGateBootstrappingSecretKeySet* key);
