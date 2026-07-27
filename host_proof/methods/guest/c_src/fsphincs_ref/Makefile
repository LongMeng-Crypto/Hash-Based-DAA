CC ?= cc
CFLAGS ?= -O3 -std=c11 -Wall -Wextra -Wpedantic
SPHINCS_REF := ../sphincs_ref
PARAMS := sphincs-sha2-128s
FSPHINCS_SECURITY ?= 128

.PHONY: all benchmark kat test clean

all: benchmark

benchmark: fsphincs_benchmark
	@trap '$(RM) fsphincs_benchmark' EXIT; ./fsphincs_benchmark

kat: fsphincs_kat
	@trap '$(RM) fsphincs_kat' EXIT; ./fsphincs_kat

test: benchmark kat

fsphincs_benchmark: fsphincs.c benchmark.c api.h params.h
	$(CC) $(CFLAGS) -DFSPHINCS_PROFILE \
	  -I. -I$(SPHINCS_REF) -I$(SPHINCS_REF)/params \
	  -DPARAMS=$(PARAMS) -DFSPHINCS_SECURITY=$(FSPHINCS_SECURITY) \
	  fsphincs.c benchmark.c \
	  $(SPHINCS_REF)/sha2.c \
	  -o $@

fsphincs_kat: fsphincs.c kat.c api.h params.h
	$(CC) $(CFLAGS) \
	  -I. -I$(SPHINCS_REF) -I$(SPHINCS_REF)/params \
	  -DPARAMS=$(PARAMS) -DFSPHINCS_SECURITY=$(FSPHINCS_SECURITY) \
	  fsphincs.c kat.c \
	  $(SPHINCS_REF)/sha2.c \
	  -o $@

clean:
	$(RM) fsphincs_benchmark fsphincs_kat
