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

#include "qemu/osdep.h"
#include "hw/i386/pc.h"
#include "hw/pci/msi.h"
#include "hw/pci/pci_bus.h"
#include "amd_iommu_helper.h"

/* configure MMIO registers at startup/reset */
void amdvi_set_quad(AMDVIState *s, hwaddr addr, uint64_t val,
                           uint64_t romask, uint64_t w1cmask)
{
    stq_le_p(&s->mmior[addr], val);
    stq_le_p(&s->romask[addr], romask);
    stq_le_p(&s->w1cmask[addr], w1cmask);
}

uint16_t amdvi_readw(AMDVIState *s, hwaddr addr)
{
    return lduw_le_p(&s->mmior[addr]);
}

uint32_t amdvi_readl(AMDVIState *s, hwaddr addr)
{
    return ldl_le_p(&s->mmior[addr]);
}

uint64_t amdvi_readq(AMDVIState *s, hwaddr addr)
{
    return ldq_le_p(&s->mmior[addr]);
}

/* internal write */
void amdvi_writeq_raw(AMDVIState *s, uint64_t val, hwaddr addr)
{
    stq_le_p(&s->mmior[addr], val);
}

/* external write */
void amdvi_writew(AMDVIState *s, hwaddr addr, uint16_t val)
{
    uint16_t romask = lduw_le_p(&s->romask[addr]);
    uint16_t w1cmask = lduw_le_p(&s->w1cmask[addr]);
    uint16_t oldval = lduw_le_p(&s->mmior[addr]);
    stw_le_p(&s->mmior[addr],
            ((oldval & romask) | (val & ~romask)) & ~(val & w1cmask));
}

void amdvi_writel(AMDVIState *s, hwaddr addr, uint32_t val)
{
    uint32_t romask = ldl_le_p(&s->romask[addr]);
    uint32_t w1cmask = ldl_le_p(&s->w1cmask[addr]);
    uint32_t oldval = ldl_le_p(&s->mmior[addr]);
    stl_le_p(&s->mmior[addr],
            ((oldval & romask) | (val & ~romask)) & ~(val & w1cmask));
}

void amdvi_writeq(AMDVIState *s, hwaddr addr, uint64_t val)
{
    uint64_t romask = ldq_le_p(&s->romask[addr]);
    uint64_t w1cmask = ldq_le_p(&s->w1cmask[addr]);
    uint32_t oldval = ldq_le_p(&s->mmior[addr]);
    stq_le_p(&s->mmior[addr],
            ((oldval & romask) | (val & ~romask)) & ~(val & w1cmask));
}

/* OR a 64-bit register with a 64-bit value */
bool amdvi_test_mask(AMDVIState *s, hwaddr addr, uint64_t val)
{
    return amdvi_readq(s, addr) | val;
}

/* OR a 64-bit register with a 64-bit value storing result in the register */
void amdvi_assign_orq(AMDVIState *s, hwaddr addr, uint64_t val)
{
    amdvi_writeq_raw(s, addr, amdvi_readq(s, addr) | val);
}

/* AND a 64-bit register with a 64-bit value storing result in the register */
void amdvi_assign_andq(AMDVIState *s, hwaddr addr, uint64_t val)
{
   amdvi_writeq_raw(s, addr, amdvi_readq(s, addr) & val);
}

