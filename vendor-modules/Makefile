# SPDX-License-Identifier: GPL-2.0
#
# MediaTek vendor modules.
#
# Every module here is built as an external module against the kernel tree
# that contains this directory:
#
#   make -C kernel-6.6 mtk-vendor-modules
#
# or directly:
#
#   make -C kernel-6.6/vendor-modules KERNEL_SRC=$PWD/kernel-6.6 \
#        M=vendor-modules O=$PWD/kernel-6.6/out modules

DEVICE_MODULES_REL_DIR ?= device-modules
KCONFIG_EXT_PREFIX ?= $(DEVICE_MODULES_REL_DIR)/
OUT_DIR ?= $(O)

export DEVICE_MODULES_REL_DIR KCONFIG_EXT_PREFIX OUT_DIR

# Order matters: connectivity/common and connectivity/conninfra export the
# symbols consumed by the remaining connectivity drivers.
VENDOR_MODULES := \
	connectivity/common \
	connectivity/conninfra \
	connectivity/connfem \
	connectivity/gps/gps_stp \
	connectivity/gps/data_link \
	connectivity/gps/gps_pwr \
	connectivity/gps/gps_scp \
	gpu \
	connectivity/fmradio \
	connectivity/wlan/adaptor \
	connectivity/wlan/adaptor/wlan_page_pool \
	connectivity/bt/linux_v2 \
	connectivity/bt/linux_v2_mt6653 \
	hbt_driver_cus \
	mtkcam

.PHONY: modules modules_install clean
modules modules_install clean:
	@set -e; \
	for m in $(VENDOR_MODULES); do \
		echo "  $(@) $$m"; \
		$(MAKE) -C $$m M=$(M)/$$m KERNEL_SRC=$(KERNEL_SRC) O=$(O) \
			OUT_DIR=$(OUT_DIR) $(@); \
	done
