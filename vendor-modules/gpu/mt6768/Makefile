export MTK_PLATFORM_VERSION := mt6768
# The Mali DDK Makefiles select the per-SoC configuration from the
# BUILD_RULE=OOT blocks. In-tree vendor-module builds descend into this
# Makefile, so set the same variables the out-of-tree wrapper uses.
export BUILD_RULE := OOT
export CONFIG_MALI_MEMORY_GROUP_MANAGER := y
export CONFIG_MALI_PROTECTED_MEMORY_ALLOCATOR := y
export CONFIG_DMA_SHARED_BUFFER_TEST_EXPORTER := y

obj-m += mali_avalon/mali-r49p1/drivers/gpu/arm/midgard/
obj-m += mali_avalon/mali-r49p1/drivers/base/arm/memory_group_manager/
obj-m += mali_avalon/mali-r49p1/drivers/base/arm/protected_memory_allocator/
obj-m += mali_avalon/mali-r49p1/drivers/base/arm/dma_buf_test_exporter/
