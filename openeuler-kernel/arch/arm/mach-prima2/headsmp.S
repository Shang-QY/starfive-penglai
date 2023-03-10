/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Entry of the second core for CSR Marco dual-core SMP SoCs
 *
 * Copyright (c) 2012 Cambridge Silicon Radio Limited, a CSR plc group company.
 */

#include <linux/linkage.h>
#include <linux/init.h>

#include <asm/assembler.h>

/*
 * SIRFSOC specific entry point for secondary CPUs.  This provides
 * a "holding pen" into which all secondary cores are held until we're
 * ready for them to initialise.
 */
ENTRY(sirfsoc_secondary_startup)
        mrc     p15, 0, r0, c0, c0, 5
        and     r0, r0, #15
        adr_l   r6, prima2_pen_release
pen:    ldr     r7, [r6]
        cmp     r7, r0
        bne     pen

        /*
         * we've been released from the holding pen: secondary_stack
         * should now contain the SVC stack for this core
         */
        b       secondary_startup
ENDPROC(sirfsoc_secondary_startup)
