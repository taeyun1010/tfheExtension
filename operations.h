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


LweSample* CipherMul(LweSample* a,LweSample* b,const TFheGateBootstrappingCloudKeySet* EK);