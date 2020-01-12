# tfheExtension

To use this tfheExtension repository, you first need to install TFHE library from https://tfhe.github.io/tfhe/

Type:
g++ tfhedistance.cpp -o tfhedistance -ltfhe-spqlios-fma -std=gnu++11 -pthread

mex proposedMEX.cpp -ltfhe-spqlios-fma -lpthread

in the repository to compile.

tfhedistance.cpp file can encrypt, decrypt and perform homomorphic calculations on encrypted intergers and doubles.
proposedMex.cpp file is for use in HomFingerPrintAuth repository which is written in Matlab.
