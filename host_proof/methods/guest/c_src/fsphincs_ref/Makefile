CC ?= cc
SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c
CFLAGS ?= -O3 -std=c11 -Wall -Wextra -Wpedantic
SPHINCS_REF := ../sphincs_ref
PARAMS := sphincs-sha2-128s
FSPHINCS_PARAMS ?= 128s
ifneq ($(strip $(FSPHINCS_SECURITY)$(FSPHINCS_K)),)
$(error Use FSPHINCS_PARAMS=128s/128f/192s/192f/256s/256f; legacy selectors were removed)
endif

.PHONY: all benchmark kat test clean fsphincs_benchmark fsphincs_kat

all: benchmark

benchmark: fsphincs_benchmark
	@trap '$(RM) fsphincs_benchmark' EXIT; ./fsphincs_benchmark

kat: fsphincs_kat
	@trap '$(RM) fsphincs_kat' EXIT; ./fsphincs_kat | python3 test_reference.py --params $(FSPHINCS_PARAMS) $(KAT_ARGS)

test: benchmark kat

fsphincs_benchmark: fsphincs.c issuer_anchor.c benchmark.c api.h issuer_anchor.h params.h parameter_sets.h sha2_compat.h
	$(CC) $(CFLAGS) -DFSPHINCS_PROFILE \
	  -I. -I$(SPHINCS_REF) -I$(SPHINCS_REF)/params \
	  -DPARAMS=$(PARAMS) -DFSPHINCS_PARAMS=$(FSPHINCS_PARAMS) \
	  fsphincs.c issuer_anchor.c benchmark.c \
	  $(SPHINCS_REF)/sha2.c \
	  -o $@

fsphincs_kat: fsphincs.c issuer_anchor.c kat.c api.h issuer_anchor.h params.h parameter_sets.h sha2_compat.h
	$(CC) $(CFLAGS) \
	  -I. -I$(SPHINCS_REF) -I$(SPHINCS_REF)/params \
	  -DPARAMS=$(PARAMS) -DFSPHINCS_PARAMS=$(FSPHINCS_PARAMS) \
	  fsphincs.c issuer_anchor.c kat.c \
	  $(SPHINCS_REF)/sha2.c \
	  -o $@

clean:
	$(RM) fsphincs_benchmark fsphincs_kat
