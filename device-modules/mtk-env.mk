# SPDX-License-Identifier: GPL-2.0
#
# MediaTek platform/DDK values normally supplied by the Android build
# environment. The in-tree kernel build does not pass them, so derive them
# from the kernel configuration and export them to every device module.

ifneq ($(CONFIG_MTK_PLATFORM),)
MTK_PLATFORM ?= $(subst ",,$(CONFIG_MTK_PLATFORM))
else ifneq ($(CONFIG_MTK_LEGACY_PLATFORM),)
MTK_PLATFORM ?= $(subst ",,$(CONFIG_MTK_LEGACY_PLATFORM))
endif
ifeq ($(MTK_PLATFORM),)
MTK_PLATFORM := mt6768
endif

ifeq ($(CONFIG_MTK_PLATFORM),)
CONFIG_MTK_PLATFORM := $(MTK_PLATFORM)
endif

KERNEL_SRC ?= $(srctree)

MTK_PLATFORM_VERSION ?= $(MTK_PLATFORM)
BUILD_RULE ?= OOT

CONFIG_MALI_MEMORY_GROUP_MANAGER ?= y
CONFIG_MALI_PROTECTED_MEMORY_ALLOCATOR ?= y
CONFIG_DMA_SHARED_BUFFER_TEST_EXPORTER ?= y

export MTK_PLATFORM MTK_PLATFORM_VERSION BUILD_RULE CONFIG_MTK_PLATFORM
export CONFIG_MALI_MEMORY_GROUP_MANAGER
export CONFIG_MALI_PROTECTED_MEMORY_ALLOCATOR
export CONFIG_DMA_SHARED_BUFFER_TEST_EXPORTER
export KERNEL_SRC
