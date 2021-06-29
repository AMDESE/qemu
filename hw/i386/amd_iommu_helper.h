
/*
 * Helpers for AMD IOMMU (AMD-Vi)
 *
 * Copyright (C) 2011 Eduard - Gabriel Munteanu
 * Copyright (C) 2015, 2016 David Kiarie Kahurani
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 * Cache implementation inspired by hw/i386/intel_iommu.c
 */

#ifndef AMD_IOMMU_HELPER_H
#define AMD_IOMMU_HELPER_H

#include "amd_iommu.h"

void amdvi_set_quad(AMDVIState *s, hwaddr addr, uint64_t val,
                    uint64_t romask, uint64_t w1cmask);

uint16_t amdvi_readw(AMDVIState *s, hwaddr addr);

uint32_t amdvi_readl(AMDVIState *s, hwaddr addr);

uint64_t amdvi_readq(AMDVIState *s, hwaddr addr);

void amdvi_writeq_raw(AMDVIState *s, hwaddr addr, uint64_t val);

void amdvi_writew(AMDVIState *s, hwaddr addr, uint16_t val);

void amdvi_writel(AMDVIState *s, hwaddr addr, uint32_t val);

void amdvi_writeq(AMDVIState *s, hwaddr addr, uint64_t val);

bool amdvi_test_mask(AMDVIState *s, hwaddr addr, uint64_t val);

void amdvi_assign_orq(AMDVIState *s, hwaddr addr, uint64_t val);

void amdvi_assign_andq(AMDVIState *s, hwaddr addr, uint64_t val);

#endif
