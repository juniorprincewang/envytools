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
#include <assert.h>

#define upper_32_bits(a) ((a) >> 32)
#define lower_32_bits(a) ((a) & 0xffffffff)

static struct nva_regspace rs = { 0 };

uint32_t vram_rd32(uint32_t addr)
{
    nva_wr32(rs.cnum, 0x1700, addr >> 16);
    return nva_rd32(rs.cnum, 0x700000 | (addr & 0xffff));
}

void vram_wr32(uint32_t addr, uint32_t data)
{
    nva_wr32(rs.cnum, 0x1700, addr >> 16);
    nva_wr32(rs.cnum, 0x700000 | (addr & 0xffff), data);
}

void vram_wr64(uint32_t addr, uint64_t data)
{
    vram_wr32(addr,     lower_32_bits(data));
    vram_wr32(addr+4,   upper_32_bits(data));
}

uint32_t get_pgd(int chid)
{
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
    uint32_t chan_vmm_pd = vram_rd32(chan_addr);
	printf ("PD\t%08x:", chan_addr);
    nva_rsprint(&rs, err, chan_vmm_pd);
	printf ("\n");
    return chan_vmm_pd;
}

void dump_page(uint32_t pg_addr, size_t offset, size_t size)
{
    size_t step = 0;
    uint32_t content;
    uint32_t addr = pg_addr+offset;
    while(step < size) {
        content = vram_rd32(addr);
	    printf ("CTX\t%08x:", addr);
        nva_rsprint(&rs, 0, content);
        addr += 4;
        step+=4;
    	printf ("\n");
    }
}

int get_pdei_spt(uint64_t vma)
{
    return (vma >> (15+12)) & 0x1fff;
}

int get_ptei_spt(uint64_t vma)
{
    return (vma >> 12) & 0x7fff;
}

int get_pdei_lpt(uint64_t vma)
{
    return (vma >> (10+17)) & 0x1fff;
}

int get_ptei_lpt(uint64_t vma)
{
    return (vma >> 17) & 0x3ff;
}

int get_page_shift(uint32_t size)
{
    if(size >= (1UL<<17))
        return 17;
    return 12;
}

uint32_t get_pte_addr(int chid, uint64_t vma, uint32_t size)
{
    int pdei = 0, ptei = 0;
    uint32_t pd_addr = 0;
    uint32_t pt_addr = 0;
    uint32_t chan_vmm_pt = 0;
    uint32_t chan_vmm_pd = get_pgd(chid);
    int page = get_page_shift(size);
    if(page == 17) {
        pdei = get_pdei_lpt(vma);
        ptei = get_ptei_lpt(vma);
	    printf ("LPT PDE:PTE\t%05x:%05x\n", pdei, ptei);
    } else {
        pdei = get_pdei_spt(vma);
        ptei = get_ptei_spt(vma);
	    printf ("SPT PDE:PTE\t%05x:%05x\n", pdei, ptei);
    }

    // PDE
    pd_addr = chan_vmm_pd+ 0x4 * (page==12) +pdei*8;
    chan_vmm_pt = vram_rd32(pd_addr);
	printf ("PT\t%08x:", pd_addr);
    nva_rsprint(&rs, 0, chan_vmm_pt);
	printf ("\n");
    // PTE
    pt_addr = ((chan_vmm_pt>>4)<<12) + ptei*8;
	printf ("PTE addr\t%08x", pt_addr);
	printf ("\n");
    return pt_addr;
}

uint32_t get_page(int chid, uint64_t vma, uint32_t size)
{
    uint32_t pt_addr = get_pte_addr(chid, vma, size);
    uint32_t chan_vmm_page = vram_rd32(pt_addr);
	printf ("PG\t%08x:", pt_addr);
    nva_rsprint(&rs, 0, chan_vmm_page);
	printf ("\n");
    // dump PAGE
    uint32_t pg_addr = ((chan_vmm_page>>4)<<12);
    return pg_addr;
}

void replace_ptes(uint32_t pte_addr, uint32_t pg_addr_src, uint32_t size)
{
    uint32_t page_victim = 0;
    uint64_t map_type = 1;
    uint64_t base = pg_addr_src >> 8 | map_type;
    int page = get_page_shift(size);
    int pten = size >> page;
    uint32_t step = 1 << (page-8);

    while(pten--) {
        vram_wr64(pte_addr, base);
        page_victim = vram_rd32(pte_addr);
    	printf ("Victim PG\t%08x:", pte_addr);
        nva_rsprint(&rs, 0, page_victim);
    	printf ("\n");
        base        += step;
        pte_addr    += 8;
    }
}

#define PFIFO_FLUSH         0x70000
#define PFIFO_FLUSH_TRIGGER 0x1
#define SHARED_ICACHE       0x419000
#define SHARED_ICACHE_TRIGGER   0x2
#define LEVEL1_ICACHE_FLUSH 0x419ea4
#define LEVEL1_ICACHE_FLUSH_TRIGGER 0x101
#define TLB_FLUSH_VSPACE    0x100cb8
#define TLB_FLUSH           0x100cbc
#define TLB_FLUSH_TRIGGER   0x80000003

/*
 * This is a test case of pte replacement for madd from Gdev
 * Somehow, only size>0x10000, tlb flush works
 */
void test_pte_replace()
{
    int chid = 2;
    // default
    //uint64_t vma_src        = 0x532000;
    //uint64_t vma_victim     = 0x534000;
    //uint32_t vma_src_size   = 0x400;
    //uint32_t vma_victim_size= 0x400;

    /* // madd n = 64 */
    /* uint64_t vma_src        = 0x532000; */
    /* uint64_t vma_victim     = 0x536000; */
    /* uint32_t vma_src_size   = 0x4000; */
    /* uint32_t vma_victim_size= 0x4000; */

    // madd n = 128
    uint64_t vma_src        = 0xb80000;
    uint64_t vma_victim     = 0xba0000;
    uint32_t vma_src_size   = 0x10000;
    uint32_t vma_victim_size= 0x10000;

    /* // madd n = 256 */
    /* uint64_t vma_src        = 0xb80000; */
    /* uint64_t vma_victim     = 0xc00000; */
    /* uint32_t vma_src_size   = 0x40000; */
    /* uint32_t vma_victim_size= 0x40000; */

    // madd n=512
    //uint64_t vma_src        = 0xb80000;
    //uint64_t vma_victim     = 0xd80000;
    //uint32_t vma_src_size   = 0x100000;
    //uint32_t vma_victim_size= 0x100000;

    // madd n=1024
    //uint64_t vma_src        = 0xb80000;
    //uint64_t vma_victim     = 0x1380000;
    //uint32_t vma_src_size   = 0x400000;
    //uint32_t vma_victim_size= 0x400000;

    uint32_t pgd = get_pgd(chid);
    uint32_t pg_addr_victim     = get_page(chid, vma_victim, vma_victim_size);
    printf("victim page:\n");
    dump_page(pg_addr_victim, 0, 0x24);
    uint32_t pte_addr_victim    = get_pte_addr(chid, vma_victim, vma_victim_size);
    uint32_t pg_addr_src        = get_page(chid, vma_src, vma_src_size);
    printf("src page:\n");
    dump_page(pg_addr_src, 0, 0x24);

    replace_ptes(pte_addr_victim, pg_addr_src, vma_victim_size);

    nva_wr32(rs.cnum, PFIFO_FLUSH, PFIFO_FLUSH_TRIGGER);
	printf ("Flush\t%08x\n", pgd);
    nva_wr32(rs.cnum, TLB_FLUSH_VSPACE, pgd>>8);
    nva_wr32(rs.cnum, TLB_FLUSH, TLB_FLUSH_TRIGGER);
    nva_wr32(rs.cnum, SHARED_ICACHE, SHARED_ICACHE_TRIGGER);
    nva_wr32(rs.cnum, LEVEL1_ICACHE_FLUSH, LEVEL1_ICACHE_FLUSH_TRIGGER);

}

uint32_t test_cmds()
{
    int chid = 2;
    uint64_t ioffset = 0;
    uint64_t ilength = 0;
    uint32_t chan_id = 0;
    uint64_t usermem = 0;
    uint64_t dma_vma = 0;
    uint32_t dma_buffer = 0;
    uint32_t ib_entry = 0;
    uint32_t low_tmp = 0;
    uint64_t high_tmp = 0;
    uint32_t chan_ib_get = 0;
    uint32_t chan_ib_put = 0;
    uint32_t pfifo_chan_base=0x800000;
    uint32_t pfifo_chan = pfifo_chan_base + 0x8 * chid;
    uint64_t chan_desc;
    uint32_t ADDRESS_MASK = 0xfffffff; // bits 0 ~ 27
    int err;
    err = nva_rd(&rs, pfifo_chan, &chan_desc);
    if(err) {
        printf("Failed to read pfifo chan\n");
        return 0;
    }
    uint32_t chan_base = (chan_desc & ADDRESS_MASK) << 12;
    // check channel id
    chan_id = vram_rd32(chan_base + 0xe8);
    assert(chan_id == chid);
    // get ring buffer
    low_tmp     = vram_rd32(chan_base + 0x48);
    high_tmp    = vram_rd32(chan_base + 0x4c);
    ioffset     = ((high_tmp & 0xffff) <<32) | low_tmp;
    ilength = high_tmp >> 16;
	printf ("ioffset\t%016lx\n", ioffset);
	printf ("ilength\t%016lx\n", ilength);
    dma_vma     = ioffset - 0x10000;
    dma_buffer  = get_page(chid, dma_vma, ilength);
    //printf("dma buffer page:\n");
    //dump_page(dma_buffer, 0, 0x100);
    // get ib_put
    low_tmp     = vram_rd32(chan_base + 0x08);
    high_tmp    = vram_rd32(chan_base + 0x0c);
    usermem     = high_tmp << 32 | low_tmp;
	printf ("usermem\t%016lx\n", usermem);
    chan_ib_get = vram_rd32(usermem + 0x88);
    chan_ib_put = vram_rd32(usermem + 0x8c);
	printf ("IB_GET\t%08x\n", chan_ib_get);
	printf ("IB_PUT\t%08x\n", chan_ib_put);
    chan_ib_put -=2;
    int ip =(chan_ib_put * 2) + 0x4000;
    ib_entry = ip*4 + dma_buffer;
	printf ("IB entry %#x\t%08x\n", chan_ib_put, vram_rd32(ib_entry));
    ib_entry += 4;
	printf ("IB entry %#x\t%08x\n", chan_ib_put, vram_rd32(ib_entry));

    chan_ib_put += 1;
    ip =(chan_ib_put * 2) + 0x4000;
    ib_entry = ip*4 + dma_buffer;
	printf ("IB entry %#x\t%08x\n", chan_ib_put, vram_rd32(ib_entry));
    ib_entry += 4;
	printf ("IB entry %#x\t%08x\n", chan_ib_put, vram_rd32(ib_entry));
    return chan_ib_put;
}

int main(int argc, char **argv) {
	if (nva_init()) {
		fprintf (stderr, "PCI init failure!\n");
		return 1;
	}
	int c;
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
    //test_cmds();
    test_pte_replace();
	return 0;
}
