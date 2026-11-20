# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2021 Mediatek Inc.
#
include $(wildcard $(KERNEL_SRC)/$(DEVICE_MODULES_REL_DIR)/Makefile.include)

EXTRA_SYMBOLS += $(OUT_DIR)/vendor-modules/connectivity/common/Module.symvers
EXTRA_SYMBOLS += $(OUT_DIR)/vendor-modules/connectivity/conninfra/Module.symvers

modules modules_install clean:
	$(MAKE) -C $(KERNEL_SRC) M=$(M) $(KBUILD_OPTIONS) KBUILD_EXTRA_SYMBOLS="$(EXTRA_SYMBOLS)" $(@)
