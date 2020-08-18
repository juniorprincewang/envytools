/*
 * Copyright (C) 2010-2011 Marcelina Kościelnicka <mwk@0x04.net>
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include "nva.h"
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
	if (nva_init()) {
		fprintf (stderr, "PCI init failure!\n");
		return 1;
	}
	int c;
	struct nva_regspace rs = { 0 };
	while ((c = getopt (argc, argv, "c:i:b:t:")) != -1)
		switch (c) {
			case 'c':
				sscanf(optarg, "%d", &rs.cnum);
				break;
			case 'i':
				sscanf(optarg, "%d", &rs.idx);
				break;
			case 'b':
				sscanf(optarg, "%d", &rs.regsz);
				if (rs.regsz != 1 && rs.regsz != 2 && rs.regsz != 4 && rs.regsz != 8) {
					fprintf (stderr, "Invalid size.\n");
					return 1;
				}
				break;
			case 't':
				rs.type = nva_rstype(optarg);
				if (rs.type == NVA_REGSPACE_UNKNOWN) {
					fprintf (stderr, "Unknown register space.\n");
					return 1;
				}
				break;
		}
	if (rs.cnum >= nva_cardsnum) {
		if (nva_cardsnum)
			fprintf (stderr, "No such card.\n");
		else
			fprintf (stderr, "No cards found.\n");
		return 1;
	}
	rs.card = nva_cards[rs.cnum];
	if (rs.regsz == 0)
		rs.regsz = nva_rsdefsz(&rs);
	//int unit = nva_rsunitsz(&rs);

    int chid = 2;
    uint32_t pfifo_chan_base=0x800000;
    uint32_t pfifo_chan = pfifo_chan_base + 0x8 * chid;
    uint64_t chan_desc;
    int err;
    err = nva_rd(&rs, pfifo_chan, &chan_desc);
	printf ("CHAN\t%08x:", pfifo_chan);
    nva_rsprint(&rs, err, chan_desc);
	printf ("\n");
    uint32_t ADDRESS_MASK = 0xfffffff; // bits 0 ~ 27
    uint32_t chan_addr = ((chan_desc & ADDRESS_MASK) << 12)+ 0x200;
    nva_wr32(rs.cnum, 0x1700, chan_addr >> 16);
    uint32_t chan_vmm_pd = nva_rd32(rs.cnum, 0x700000 | (chan_addr&0xffff));
	printf ("PD\t%08x:", chan_addr);
    nva_rsprint(&rs, err, chan_vmm_pd);
	printf ("\n");
    uint64_t vma = 0x53200;
    uint32_t vma_size = 0x24;
    int pdei = (vma >> (15+8)) & 0x1fff;
    int ptei = (vma >> 8) & 0x7fff;
	printf ("PDE:PTE\t%05x:%05x\n", pdei, ptei);
    // PDE
    uint32_t pd_addr = chan_vmm_pd+0x4+pdei*8;
    nva_wr32(rs.cnum, 0x1700, pd_addr >> 16);
    uint32_t chan_vmm_pt = nva_rd32(rs.cnum, 0x700000 | (pd_addr&0xffff));
	printf ("PT\t%08x:", pd_addr);
    nva_rsprint(&rs, 0, chan_vmm_pt);
	printf ("\n");
    // PTE
    uint32_t pt_addr = ((chan_vmm_pt>>4)<<12) + ptei*8;
    nva_wr32(rs.cnum, 0x1700, pt_addr >> 16);
    uint32_t chan_vmm_page = nva_rd32(rs.cnum, 0x700000 | (pt_addr&0xffff));
	printf ("PG\t%08x:", pt_addr);
    nva_rsprint(&rs, 0, chan_vmm_page);
	printf ("\n");
    // dump PAGE
    uint32_t pg_addr = ((chan_vmm_page>>4)<<12);
    uint32_t step = 0;
    while(step<vma_size) {
        nva_wr32(rs.cnum, 0x1700, pg_addr >> 16);
        uint32_t content = nva_rd32(rs.cnum, 0x700000 | (pg_addr&0xffff));
	    printf ("CTX\t%08x:", pg_addr);
        nva_rsprint(&rs, 0, content);
        pg_addr += 4;
        step+=4;
    	printf ("\n");
    }
	return 0;
}
