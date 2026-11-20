# ChipWhisperer SimpleSerial SLH-DSA address-PRF capture firmware.
# Build in chipwhisperer/hardware/victims/firmware/simpleserial-SLH-DSA/
# so ../simpleserial/Makefile.simpleserial and ../Makefile.inc can be found.
# Example: make PLATFORM=CW308_STM32F3 CRYPTO_TARGET=MBEDTLS OPT=s
# The Python capture batches regenerate slh_param_config.h before building.

# Target file name (without extension).
# This is the base name of the compiled .hex file.
TARGET = simpleserial-SLH-DSA

# List C source files here.
# Header files (.h) are automatically pulled in.
# SRC += simpleserial-aes.c
SRC += slh_dsa_prf_target.c

# -----------------------------------------------------------------------------
EXTRA_OPTS = NO_EXTRA_OPTS
CFLAGS += -D$(EXTRA_OPTS)


ifeq ($(CRYPTO_TARGET),)
  ${info No CRYPTO_TARGET passed - defaulting to TINYAES128C}
  CRYPTO_TARGET = TINYAES128C
endif

${info Building for platform ${PLATFORM} with CRYPTO_TARGET=$(CRYPTO_TARGET)}

#Add simpleserial project to build
include ../simpleserial/Makefile.simpleserial

FIRMWAREPATH = ../.
include $(FIRMWAREPATH)/Makefile.inc

