# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# Detect C and C++ compiler options
# if not gcc and g++, default to clang-7
C_COMPILER=$(notdir $(CC))
ifeq ($(C_COMPILER), gcc)
        CXX_COMPILER=$(notdir $(CXX))
        USE_GCC = true
endif

ifeq ($(USE_GCC),)
        CC = clang-7
        CXX = clang++-7
        C_COMPILER=clang
        CXX_COMPILER=clang++
endif

CFLAGS=$(shell pkg-config oeenclave-$(C_COMPILER) --cflags)
CXXFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --libs)

all:
	$(MAKE) genkey
	$(MAKE) build
	$(MAKE) sign

# The enclaves in the sample will check if the other enclave is signed
# with the expected key. Since this sample builds both enclaves, we can
# inject the expected public keys at build time.
#
# If the other public key isn't known, then we would have to load the
# public key from the host. We can't simply load the raw public key since
# a malicious host might change it. So, we would need to load a certicate
# that contains the expected public key that is signed by a trusted CA.
#
# This key pair is used to encrypt/decrypt mrenclave
genkey: public.pem	
	../keys/gen_pubkey_header.sh ./oracle_pubkey_list.h $<

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../oracle.edl --trusted --trusted-dir ../common
	$(CXX) -g -c $(CXXFLAGS) $(INCLUDES) -I.. -std=c++11 -DOE_API_VERSION=2 ecalls.cpp ../common/attestation.cpp ../common/crypto.cpp ../common/dispatcher.cpp
	$(CC) -g -c $(CFLAGS) $(CINCLUDES) -I.. -DOE_API_VERSION=2 ../common/oracle_t.c
	$(CXX) -o oracle attestation.o crypto.o ecalls.o dispatcher.o oracle_t.o $(LDFLAGS)

# private?.pem
sign:
	oesign sign -e oracle -c enc.conf -k ../keys/private1.pem

clean:
	rm -f *.o oracle oralce.signed ../common/oracle_t.* ../common/oracle_args.h *.pem oracle_pubkey_list.h
