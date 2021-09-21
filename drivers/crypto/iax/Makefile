# SPDX-License-Identifier: GPL-2.0
#
# Makefile for IAX crypto device drivers
#

ccflags-y += -I $(srctree)/drivers/dma/idxd -DDEFAULT_SYMBOL_NAMESPACE=IDXD

obj-$(CONFIG_CRYPTO_DEV_IAX_CRYPTO) := iax_crypto.o
iax_crypto-y := iax_crypto_main.o

iax_crypto-$(CONFIG_CRYPTO_DEV_IAX_CRYPTO_STATS) += iax_crypto_stats.o
