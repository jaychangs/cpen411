/* sim-safe.c - sample functional simulator implementation */

/* SimpleScalar(TM) Tool Suite
 * Copyright (C) 1994-2003 by Todd M. Austin, Ph.D. and SimpleScalar, LLC.
 * All Rights Reserved. 
 * 
 * THIS IS A LEGAL DOCUMENT, BY USING SIMPLESCALAR,
 * YOU ARE AGREEING TO THESE TERMS AND CONDITIONS.
 * 
 * No portion of this work may be used by any commercial entity, or for any
 * commercial purpose, without the prior, written permission of SimpleScalar,
 * LLC (info@simplescalar.com). Nonprofit and noncommercial use is permitted
 * as described below.
 * 
 * 1. SimpleScalar is provided AS IS, with no warranty of any kind, express
 * or implied. The user of the program accepts full responsibility for the
 * application of the program and the use of any results.
 * 
 * 2. Nonprofit and noncommercial use is encouraged. SimpleScalar may be
 * downloaded, compiled, executed, copied, and modified solely for nonprofit,
 * educational, noncommercial research, and noncommercial scholarship
 * purposes provided that this notice in its entirety accompanies all copies.
 * Copies of the modified software can be delivered to persons who use it
 * solely for nonprofit, educational, noncommercial research, and
 * noncommercial scholarship purposes provided that this notice in its
 * entirety accompanies all copies.
 * 
 * 3. ALL COMMERCIAL USE, AND ALL USE BY FOR PROFIT ENTITIES, IS EXPRESSLY
 * PROHIBITED WITHOUT A LICENSE FROM SIMPLESCALAR, LLC (info@simplescalar.com).
 * 
 * 4. No nonprofit user may place any restrictions on the use of this software,
 * including as modified by the user, by any other authorized user.
 * 
 * 5. Noncommercial and nonprofit users may distribute copies of SimpleScalar
 * in compiled or executable form as set forth in Section 2, provided that
 * either: (A) it is accompanied by the corresponding machine-readable source
 * code, or (B) it is accompanied by a written offer, with no time limit, to
 * give anyone a machine-readable copy of the corresponding source code in
 * return for reimbursement of the cost of distribution. This written offer
 * must permit verbatim duplication by anyone, or (C) it is distributed by
 * someone who received only the executable form, and is accompanied by a
 * copy of the written offer of source code.
 * 
 * 6. SimpleScalar was developed by Todd M. Austin, Ph.D. The tool suite is
 * currently maintained by SimpleScalar LLC (info@simplescalar.com). US Mail:
 * 2395 Timbercrest Court, Ann Arbor, MI 48105.
 * 
 * Copyright (C) 1994-2003 by Todd M. Austin, Ph.D. and SimpleScalar, LLC.
 */


#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <assert.h>

#include "host.h"
#include "misc.h"
#include "machine.h"
#include "regs.h"
#include "memory.h"
#include "loader.h"
#include "syscall.h"
#include "options.h"
#include "stats.h"
#include "sim.h"

/*
 * This file implements a functional simulator.  This functional simulator is
 * the simplest, most user-friendly simulator in the simplescalar tool set.
 * Unlike sim-fast, this functional simulator checks for all instruction
 * errors, and the implementation is crafted for clarity rather than speed.
 */

/* simulated registers */
static struct regs_t regs;

/* simulated memory */
static struct mem_t *mem = NULL;

/* track number of refs */
static counter_t sim_num_refs = 0;

/* this part a*/
static counter_t g_icache_miss;

static counter_t g_icache_miss_aii;

static counter_t g_store_total;
static counter_t g_store_miss;

static counter_t g_load_total;
static counter_t g_load_miss;

static counter_t g_writeback;

/* maximum number of inst's to execute */
static unsigned int max_insts;

/* register simulator-specific options */
void
sim_reg_options(struct opt_odb_t *odb)
{
  opt_reg_header(odb, 
"sim-safe: This simulator implements a functional simulator.  This\n"
"functional simulator is the simplest, most user-friendly simulator in the\n"
"simplescalar tool set.  Unlike sim-fast, this functional simulator checks\n"
"for all instruction errors, and the implementation is crafted for clarity\n"
"rather than speed.\n"
		 );

  /* instruction limit */
  opt_reg_uint(odb, "-max:inst", "maximum number of inst's to execute",
	       &max_insts, /* default */0,
	       /* print */TRUE, /* format */NULL);

}

/* check simulator-specific option values */
void
sim_check_options(struct opt_odb_t *odb, int argc, char **argv)
{
  /* nada */
}

/* register simulator-specific statistics */
void
sim_reg_stats(struct stat_sdb_t *sdb)
{
  stat_reg_counter(sdb, "sim_num_insn",
		   "total number of instructions executed",
		   &sim_num_insn, sim_num_insn, NULL);
  stat_reg_counter(sdb, "sim_num_refs",
		   "total number of loads and stores executed",
		   &sim_num_refs, 0, NULL);
  stat_reg_int(sdb, "sim_elapsed_time",
	       "total simulation time in seconds",
	       &sim_elapsed_time, 0, NULL);
  stat_reg_formula(sdb, "sim_inst_rate",
		   "simulation speed (in insts/sec)",
		   "sim_num_insn / sim_elapsed_time", NULL);
/* this is a*/
  stat_reg_counter(sdb, "sim_num_icache_miss", "total number of instruction cache misses", &g_icache_miss, 0, NULL);
  stat_reg_formula(sdb, "sim_icache_miss_rate", "instruction cache miss rate (percentage)", "100*(sim_num_icache_miss / sim_num_insn)", NULL);

  stat_reg_counter(sdb, "sim_num_icache_miss_aii", "total number of instruction cache misses aii", &g_icache_miss_aii, 0, NULL);
  stat_reg_formula(sdb, "sim_icache_miss_rate_aii", "instruction cache miss rate aii (percentage)", "100*(sim_num_icache_miss_aii / sim_num_insn)", NULL);

/*B*/
  stat_reg_counter(sdb, "sim_num_load_total", "total number of load", &g_load_total, 0, NULL);
  stat_reg_counter(sdb, "sim_num_load_miss", "total number of load miss", &g_load_miss, 0, NULL);
  stat_reg_formula(sdb, "sim_load", "load miss rate (percentage)", "100*(sim_num_load_miss / sim_num_load_total)", NULL);

  stat_reg_counter(sdb, "sim_num_store_total", "total number of store", &g_store_total, 0, NULL);
  stat_reg_counter(sdb, "sim_num_store_miss", "total number of store miss", &g_store_miss, 0, NULL);
  stat_reg_formula(sdb, "sim_store", "store miss rate (percentage)", "100*(sim_num_store_miss / sim_num_store_total)", NULL);

  stat_reg_counter(sdb, "sim_writeback", "total number of writeback", &g_writeback, 0, NULL);
  stat_reg_formula(sdb, "sim_wb_ratio", "writeback to store ratio", "(sim_writeback / sim_num_store_total)", NULL);

//  stat_reg_formula(sdb, "sim_icache_miss_rate_aii", "instruction cache miss rate aii (percentage)", "100*(sim_num_icache_miss_aii / sim_num_insn)", NULL);

  ld_reg_stats(sdb);
  mem_reg_stats(mem, sdb);
}

/* initialize the simulator */
void
sim_init(void)
{
  sim_num_refs = 0;

  /* allocate and initialize register file */
  regs_init(&regs);

  /* allocate and initialize memory space */
  mem = mem_create("mem");
  mem_init(mem);
}

/* load program into simulated state */
void
sim_load_prog(char *fname,		/* program to load */
	      int argc, char **argv,	/* program arguments */
	      char **envp)		/* program environment */
{
  /* load program text and data, set up environment, memory, and regs */
  ld_load_prog(fname, argc, argv, envp, &regs, mem, TRUE);
}

/* print simulator-specific configuration information */
void
sim_aux_config(FILE *stream)		/* output stream */
{
  /* nothing currently */
}

/* dump simulator-specific auxiliary simulator statistics */
void
sim_aux_stats(FILE *stream)		/* output stream */
{
  /* nada */
}

/* un-initialize simulator-specific state */
void
sim_uninit(void)
{
  /* nada */
}


/*
 * configure the execution engine
 */

/*
 * precise architected register accessors
 */

/* next program counter */
#define SET_NPC(EXPR)		(regs.regs_NPC = (EXPR))

/* current program counter */
#define CPC			(regs.regs_PC)

/* general purpose registers */
#define GPR(N)			(regs.regs_R[N])
#define SET_GPR(N,EXPR)		(regs.regs_R[N] = (EXPR))

#if defined(TARGET_PISA)

/* floating point registers, L->word, F->single-prec, D->double-prec */
#define FPR_L(N)		(regs.regs_F.l[(N)])
#define SET_FPR_L(N,EXPR)	(regs.regs_F.l[(N)] = (EXPR))
#define FPR_F(N)		(regs.regs_F.f[(N)])
#define SET_FPR_F(N,EXPR)	(regs.regs_F.f[(N)] = (EXPR))
#define FPR_D(N)		(regs.regs_F.d[(N) >> 1])
#define SET_FPR_D(N,EXPR)	(regs.regs_F.d[(N) >> 1] = (EXPR))

/* miscellaneous register accessors */
#define SET_HI(EXPR)		(regs.regs_C.hi = (EXPR))
#define HI			(regs.regs_C.hi)
#define SET_LO(EXPR)		(regs.regs_C.lo = (EXPR))
#define LO			(regs.regs_C.lo)
#define FCC			(regs.regs_C.fcc)
#define SET_FCC(EXPR)		(regs.regs_C.fcc = (EXPR))

#elif defined(TARGET_ALPHA)

/* floating point registers, L->word, F->single-prec, D->double-prec */
#define FPR_Q(N)		(regs.regs_F.q[N])
#define SET_FPR_Q(N,EXPR)	(regs.regs_F.q[N] = (EXPR))
#define FPR(N)			(regs.regs_F.d[(N)])
#define SET_FPR(N,EXPR)		(regs.regs_F.d[(N)] = (EXPR))

/* miscellaneous register accessors */
#define FPCR			(regs.regs_C.fpcr)
#define SET_FPCR(EXPR)		(regs.regs_C.fpcr = (EXPR))
#define UNIQ			(regs.regs_C.uniq)
#define SET_UNIQ(EXPR)		(regs.regs_C.uniq = (EXPR))

#else
#error No ISA target defined...
#endif

/* precise architected memory state accessor macros */
#define READ_BYTE(SRC, FAULT)						\
  ((FAULT) = md_fault_none, addr = (SRC), MEM_READ_BYTE(mem, addr))
#define READ_HALF(SRC, FAULT)						\
  ((FAULT) = md_fault_none, addr = (SRC), MEM_READ_HALF(mem, addr))
#define READ_WORD(SRC, FAULT)						\
  ((FAULT) = md_fault_none, addr = (SRC), MEM_READ_WORD(mem, addr))
#ifdef HOST_HAS_QWORD
#define READ_QWORD(SRC, FAULT)						\
  ((FAULT) = md_fault_none, addr = (SRC), MEM_READ_QWORD(mem, addr))
#endif /* HOST_HAS_QWORD */

#define WRITE_BYTE(SRC, DST, FAULT)					\
  ((FAULT) = md_fault_none, addr = (DST), MEM_WRITE_BYTE(mem, addr, (SRC)))
#define WRITE_HALF(SRC, DST, FAULT)					\
  ((FAULT) = md_fault_none, addr = (DST), MEM_WRITE_HALF(mem, addr, (SRC)))
#define WRITE_WORD(SRC, DST, FAULT)					\
  ((FAULT) = md_fault_none, addr = (DST), MEM_WRITE_WORD(mem, addr, (SRC)))
#ifdef HOST_HAS_QWORD
#define WRITE_QWORD(SRC, DST, FAULT)					\
  ((FAULT) = md_fault_none, addr = (DST), MEM_WRITE_QWORD(mem, addr, (SRC)))
#endif /* HOST_HAS_QWORD */

/* system call handler macro */
#define SYSCALL(INST)	sys_syscall(&regs, mem_access, mem, INST, TRUE)

#define DNA         (0)

/* general register dependence decoders */
#define DGPR(N)         (N)
#define DGPR_D(N)       ((N) &~1)

/* floating point register dependence decoders */
#define DFPR_L(N)       (((N)+32)&~1)
#define DFPR_F(N)       (((N)+32)&~1)
#define DFPR_D(N)       (((N)+32)&~1)

/* miscellaneous register dependence decoders */
#define DHI         (0+32+32)
#define DLO         (1+32+32)
#define DFCC            (2+32+32)
#define DTMP            (3+32+32)

/* part a_i stuff*/

struct block {
  int m_valid; // is block valid?
  md_addr_t m_tag; // tag used to determine whether we have a cache hit
};

struct cache {
  struct block *m_tag_array;
  unsigned m_total_blocks;
  unsigned m_set_shift;
  unsigned m_set_mask;
  unsigned m_tag_shift;
};

void cache_access( struct cache *c, unsigned addr, counter_t *miss_counter ) {
  unsigned index, tag;
  index = (addr>>c->m_set_shift)&c->m_set_mask;
  tag = (addr>>c->m_tag_shift);
  assert( index < c->m_total_blocks );
  if(!(c->m_tag_array[index].m_valid&&(c->m_tag_array[index].m_tag==tag))) {
    *miss_counter = *miss_counter + 1;
    c->m_tag_array[index].m_valid = 1;
    c->m_tag_array[index].m_tag = tag;
  }
}

/* part a_ii stuff*/

struct block_aii {
  int m_valid; // is block valid?
  int m_timestamp;
  md_addr_t m_tag; // tag used to determine whether we have a cache hit
};

struct cache_aii {
  struct block_aii *m_tag_array;
  unsigned m_total_blocks;
  unsigned m_set_shift;
  unsigned m_set_mask;
  unsigned m_tag_shift;
  unsigned m_nways;
};

void cache_access_aii( struct cache_aii *c, unsigned addr, counter_t *miss_counter ) {
  unsigned index, tag, lru_index, count;
  int lru;
  index = (addr>>c->m_set_shift)&c->m_set_mask;
  tag = (addr>>c->m_tag_shift);
  unsigned  set_factor = c->m_nways;
  assert( index < (c->m_total_blocks)/set_factor );
  for(count=0; count < 4; count++) { //this checks if its in the cache by iterating the set
    assert( index*set_factor+count < c->m_total_blocks );
    if((c->m_tag_array[index*set_factor+count].m_tag==tag)&&(c->m_tag_array[index*set_factor+count].m_valid)) {
      c->m_tag_array[index*set_factor+count].m_timestamp = sim_num_insn; //if in set, update lru and return
      return;
    }
  }
  *miss_counter = *miss_counter + 1; //if not in set increment mis counter
  for(count=0; count < 4; count++) {
    assert( index*set_factor+count < c->m_total_blocks );
    if(!(c->m_tag_array[index*set_factor+count].m_valid)) { //check if theres an empty space in set
      c->m_tag_array[index*set_factor+count].m_valid = 1; //if empty space add the tag to it and update lru
      c->m_tag_array[index*set_factor+count].m_tag = tag;
      c->m_tag_array[index*set_factor+count].m_timestamp = sim_num_insn;
      return;
    }
  }
  //if theres no empty set, use lru
  lru = c->m_tag_array[index*set_factor].m_timestamp; //add the index0 lru timestamp
  lru_index = index*set_factor; //save this index
  for(count=0; count < 3; count++) {
    assert( index*set_factor+count+1 < c->m_total_blocks );
    if(c->m_tag_array[index*set_factor+count+1].m_timestamp < lru) { //if the next index has a lower timestamp, replace lru
      lru = c->m_tag_array[index*set_factor+count+1].m_timestamp;
      lru_index = index*set_factor+count+1;
      }
  }
  //after itterating through whole thing, update cache and lru
  c->m_tag_array[lru_index].m_valid = 1;
  c->m_tag_array[lru_index].m_tag = tag;
  c->m_tag_array[lru_index].m_timestamp = sim_num_insn;
}


// this is b stuff

struct block_b {
  int m_valid; // is block valid?
  int m_timestamp;
  md_addr_t m_tag; // tag used to determine whether we have a cache hit
};

struct cache_b {
  struct block_b *m_tag_array;
  unsigned m_total_blocks;
  unsigned m_set_shift;
  unsigned m_set_mask;
  unsigned m_tag_shift;
  unsigned m_nways;
};

void cache_access_b( struct cache_b *c, unsigned addr, counter_t *miss_counter ) {
  unsigned index, tag, lru_index, count;
  int lru;
  index = (addr>>c->m_set_shift)&c->m_set_mask;
  tag = (addr>>c->m_tag_shift);
  unsigned  set_factor = c->m_nways;
  assert( index < (c->m_total_blocks)/set_factor );
  for(count=0; count < 8; count++) { //this checks if its in the cache by iterating the set
    assert( index*set_factor+count < c->m_total_blocks );
    if((c->m_tag_array[index*set_factor+count].m_tag==tag)&&(c->m_tag_array[index*set_factor+count].m_valid)) {
      c->m_tag_array[index*set_factor+count].m_timestamp = sim_num_insn; //if in set, update lru and return
      return;
    }
  }
  *miss_counter = *miss_counter + 1; //if not in set increment mis counter
  for(count=0; count < 8; count++) {
    assert( index*set_factor+count < c->m_total_blocks );
    if(!(c->m_tag_array[index*set_factor+count].m_valid)) { //check if theres an empty space in set
      c->m_tag_array[index*set_factor+count].m_valid = 1; //if empty space add the tag to it and update lru
      c->m_tag_array[index*set_factor+count].m_tag = tag;
      c->m_tag_array[index*set_factor+count].m_timestamp = sim_num_insn;
      return;
    }
  }
  //if theres no empty set, use lru
  lru = c->m_tag_array[index*set_factor].m_timestamp; //add the index0 lru timestamp
  lru_index = index*set_factor; //save this index
  for(count=0; count < 7; count++) {
    assert( index*set_factor+count+1 < c->m_total_blocks );
    if(c->m_tag_array[index*set_factor+count+1].m_timestamp < lru) { //if the next index has a lower timestamp, replace lru
      lru = c->m_tag_array[index*set_factor+count+1].m_timestamp;
      lru_index = index*set_factor+count+1;
      }
  }
  //after itterating through whole thing, update cache and lru
  c->m_tag_array[lru_index].m_valid = 1;
  c->m_tag_array[lru_index].m_tag = tag;
  c->m_tag_array[lru_index].m_timestamp = sim_num_insn;
}


/* start simulation, program loaded, processor precise state initialized */
void
sim_main(void)
{
  md_inst_t inst;
  register md_addr_t addr;
  enum md_opcode op;
  register int is_write;
  enum md_fault_type fault;

/* part a_i */
  struct cache *icache = (struct cache *) calloc( sizeof(struct cache), 1 );
  icache->m_tag_array = (struct block *) calloc( sizeof(struct block), 512 );
  icache->m_total_blocks = 512;
  icache->m_set_shift = 6;
  icache->m_set_mask = (1<<9)-1; icache->m_tag_shift = 15;

/*part a_ii*/

  struct cache_aii *icache_aii = (struct cache_aii *) calloc( sizeof(struct cache_aii), 1 );
  icache_aii->m_tag_array = (struct block_aii *) calloc( sizeof(struct block_aii), 1024 );
  icache_aii->m_total_blocks = 1024;
  icache_aii->m_set_shift = 5; //offset
  icache_aii->m_set_mask = (1<<8)-1; //8 bit index (255)
  icache_aii->m_tag_shift = 13; //the rest
  icache_aii->m_nways = 4;

/*part b*/

  struct cache_b *icache_b = (struct cache_b *) calloc( sizeof(struct cache_b), 1 );
  icache_b->m_tag_array = (struct block_b *) calloc( sizeof(struct block_b), 256 );
  icache_b->m_total_blocks = 256;
  icache_b->m_set_shift = 6; //offset
  icache_b->m_set_mask = (1<<5)-1; //7 bit index (127)
  icache_b->m_tag_shift = 11; //the rest
  icache_b->m_nways = 8;

  fprintf(stderr, "sim: ** starting functional simulation **\n");

  /* set up initial default next PC */
  regs.regs_NPC = regs.regs_PC + sizeof(md_inst_t);

  while (TRUE)
    {
      /* maintain $r0 semantics */
      regs.regs_R[MD_REG_ZERO] = 0;
#ifdef TARGET_ALPHA
      regs.regs_F.d[MD_REG_ZERO] = 0.0;
#endif /* TARGET_ALPHA */

      /* get the next instruction to execute */
      MD_FETCH_INST(inst, mem, regs.regs_PC);

      /* keep an instruction count */
      sim_num_insn++;

      /* set default reference address and access mode */
      addr = 0; is_write = FALSE;

      /* set default fault - none */
      fault = md_fault_none;

      /* decode the instruction */
      MD_SET_OPCODE(op, inst);

      /* execute the instruction */
      switch (op)
	{
#define DEFINST(OP,MSK,NAME,OPFORM,RES,FLAGS,O1,O2,I1,I2,I3)		\
	case OP:							\
          SYMCAT(OP,_IMPL);						\
          break;
#define DEFLINK(OP,MSK,NAME,MASK,SHIFT)					\
        case OP:							\
          panic("attempted to execute a linking opcode");
#define CONNECT(OP)
#define DECLARE_FAULT(FAULT)						\
	  { fault = (FAULT); break; }
#include "machine.def"
	default:
	  panic("attempted to execute a bogus opcode");
      }

      if (fault != md_fault_none)
	fatal("fault (%d) detected @ 0x%08p", fault, regs.regs_PC);

      if (verbose)
	{
	  myfprintf(stderr, "%10n [xor: 0x%08x] @ 0x%08p: ",
		    sim_num_insn, md_xor_regs(&regs), regs.regs_PC);
	  md_print_insn(inst, regs.regs_PC, stderr);
	  if (MD_OP_FLAGS(op) & F_MEM)
	    myfprintf(stderr, "  mem: 0x%08p", addr);
	  fprintf(stderr, "\n");
	  /* fflush(stderr); */
	}

      if (MD_OP_FLAGS(op) & F_MEM)
	{
	  sim_num_refs++;
	  if (MD_OP_FLAGS(op) & F_STORE)
	    is_write = TRUE;
	}

      /* part a_i stuff*/
      cache_access(icache, regs.regs_PC, &g_icache_miss);

      /* a_ii stuff */
      cache_access_aii(icache_aii, regs.regs_PC, &g_icache_miss_aii);

      /* Calculate the miss rate of load and store and wb ratio */
      if((MD_OP_FLAGS(op)&F_LOAD)!=0) {
        g_load_total++;
        g_writeback++;
        cache_access_b(icache_b, regs.regs_PC, &g_load_miss);
      }

      if((MD_OP_FLAGS(op)&F_STORE)!=0) {
        g_store_total++;
        g_writeback++;
        cache_access_b(icache_b, regs.regs_PC, &g_store_miss);
      }

      /* go to the next instruction */
      regs.regs_PC = regs.regs_NPC;
      regs.regs_NPC += sizeof(md_inst_t);

      /* finish early? */
      if (max_insts && sim_num_insn >= max_insts)
	return;
    }
}
