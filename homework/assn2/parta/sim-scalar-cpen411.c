/* sim-scalar-cpen411.c */

/*
 * Tor M. Aamodt (aamodt@ece.ubc.ca) - Sept. 25, 2006
 *
 * Based upon sim-safe.c from:
 *
 * SimpleScalar(TM) Tool Suite
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

/* maximum number of inst's to execute */
static unsigned int max_insts;

/* cycle counter */
unsigned sim_cycle;


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

  stat_reg_uint(sdb, "sim_cycles",
           "total number of cycles",
           &sim_cycle, 0, NULL);
  stat_reg_formula(sdb, "sim_cpi",
           "cycles per instruction (CPI)",
           "sim_cycles / sim_num_insn", NULL);

  stat_reg_counter(sdb, "sim_num_refs",
           "total number of loads and stores executed",
           &sim_num_refs, 0, NULL);
  stat_reg_int(sdb, "sim_elapsed_time",
           "total simulation time in seconds",
           &sim_elapsed_time, 0, NULL);
  stat_reg_formula(sdb, "sim_inst_rate",
           "simulation speed (in insts/sec)",
           "sim_num_insn / sim_elapsed_time", NULL);
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
sim_load_prog(char *fname,      /* program to load */
          int argc, char **argv,    /* program arguments */
          char **envp)      /* program environment */
{
  /* load program text and data, set up environment, memory, and regs */
  ld_load_prog(fname, argc, argv, envp, &regs, mem, TRUE);
}

/* print simulator-specific configuration information */
void
sim_aux_config(FILE *stream)        /* output stream */
{
  /* nothing currently */
}

/* dump simulator-specific auxiliary simulator statistics */
void
sim_aux_stats(FILE *stream)     /* output stream */
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
#define SET_NPC(EXPR)       (regs.regs_NPC = (EXPR))

/* current program counter */
#define CPC         (regs.regs_PC)

/* general purpose registers */
#define GPR(N)          (regs.regs_R[N])
#define SET_GPR(N,EXPR)     (regs.regs_R[N] = (EXPR))

#if defined(TARGET_PISA)

/* floating point registers, L->word, F->single-prec, D->double-prec */
#define FPR_L(N)        (regs.regs_F.l[(N)])
#define SET_FPR_L(N,EXPR)   (regs.regs_F.l[(N)] = (EXPR))
#define FPR_F(N)        (regs.regs_F.f[(N)])
#define SET_FPR_F(N,EXPR)   (regs.regs_F.f[(N)] = (EXPR))
#define FPR_D(N)        (regs.regs_F.d[(N) >> 1])
#define SET_FPR_D(N,EXPR)   (regs.regs_F.d[(N) >> 1] = (EXPR))

/* miscellaneous register accessors */
#define SET_HI(EXPR)        (regs.regs_C.hi = (EXPR))
#define HI          (regs.regs_C.hi)
#define SET_LO(EXPR)        (regs.regs_C.lo = (EXPR))
#define LO          (regs.regs_C.lo)
#define FCC         (regs.regs_C.fcc)
#define SET_FCC(EXPR)       (regs.regs_C.fcc = (EXPR))

#else
#error No ISA target defined...
#endif

/* precise architected memory state accessor macros */
#define READ_BYTE(SRC, FAULT)                       \
  ((FAULT) = md_fault_none, addr = (SRC), MEM_READ_BYTE(mem, addr))
#define READ_HALF(SRC, FAULT)                       \
  ((FAULT) = md_fault_none, addr = (SRC), MEM_READ_HALF(mem, addr))
#define READ_WORD(SRC, FAULT)                       \
  ((FAULT) = md_fault_none, addr = (SRC), MEM_READ_WORD(mem, addr))
#ifdef HOST_HAS_QWORD
#define READ_QWORD(SRC, FAULT)                      \
  ((FAULT) = md_fault_none, addr = (SRC), MEM_READ_QWORD(mem, addr))
#endif /* HOST_HAS_QWORD */

#define WRITE_BYTE(SRC, DST, FAULT)                 \
  ((FAULT) = md_fault_none, addr = (DST), MEM_WRITE_BYTE(mem, addr, (SRC)))
#define WRITE_HALF(SRC, DST, FAULT)                 \
  ((FAULT) = md_fault_none, addr = (DST), MEM_WRITE_HALF(mem, addr, (SRC)))
#define WRITE_WORD(SRC, DST, FAULT)                 \
  ((FAULT) = md_fault_none, addr = (DST), MEM_WRITE_WORD(mem, addr, (SRC)))
#ifdef HOST_HAS_QWORD
#define WRITE_QWORD(SRC, DST, FAULT)                    \
  ((FAULT) = md_fault_none, addr = (DST), MEM_WRITE_QWORD(mem, addr, (SRC)))
#endif /* HOST_HAS_QWORD */

/* system call handler macro */
#define SYSCALL(INST)   sys_syscall(&regs, mem_access, mem, INST, TRUE)

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


////////////////////////////////////////////////////////////////////////////////

// pipeline registeres
enum pipeline_register {
    IF_ID_REGISTER=0,
    ID_EX_REGISTER,
    EX_MEM_REGISTER,
    MEM_WB_REGISTER,
    PIPEDEPTH
};

// instruction status
enum instruction_status {
    ALLOCATED,
    FETCHED,
    DECODED,
    EXECUTED,
    MEMORY_STAGE_COMPLETED,
    DONE
};

// the instruction type
typedef struct Inst {
    unsigned     uid;       // instruction number
    unsigned     pc;	    // instruction address
    unsigned	 next_pc;   // next instruction address
    md_inst_t    inst;      // instruction bits from memory
    enum md_opcode op;	    // opcode
    int          taken;     // if branch, is it taken?
    int          status;    // where is the instruction in the pipeline?
    struct Inst *src[3];    // src operand instructions
    int          dst[2];    // registers written by this instruction
    int          stalled;   // instruction is stalled
    unsigned     donecycle; // cycle when destination operand(s) generated
    struct Inst *next;      // used for custom memory allocation/deallocation
} inst_t;

// fast memory allocator for instruction type (improves simulation speed)
#define NI 32
inst_t g_inst[NI];
inst_t *g_head, *g_tail;

void init_pool()
{
    int i;
    for( i=0; i<(NI-1); ++i ) {
        g_inst[i].next = &g_inst[i+1];
    }
    g_head = g_inst;
    g_tail = g_inst;
    while( g_tail->next ) g_tail = g_tail->next;
}

inst_t *alloc_inst()
{
    inst_t *tmp = g_head;
    g_head = g_head->next; // seg. fault only if there is a "memory leak"
    assert( g_head );
    tmp->next = NULL;
    return tmp;
}

void free_inst( inst_t *x )
{
    assert( g_tail->next == NULL );
    assert( x->next == NULL );
    g_tail->next = x;
    g_tail = x;
}

// global pipeline variables
inst_t   *g_piperegister[PIPEDEPTH];
inst_t   *g_raw[MD_TOTAL_REGS];     // track register dependencies
int       g_misfetch;
int       g_resolve_at_decode=1; 
md_addr_t g_fetch_pc = 0;
md_addr_t g_target_pc = 0;
int       g_fetch_redirected = 0;
unsigned g_uid = 1;

void cpen411_init()
{
    fprintf(stderr, "sim: ** starting CPEN 411 pipeline simulation **\n");

    init_pool();

    /* set up initial default next PC */
    g_fetch_pc = regs.regs_PC;
    regs.regs_NPC = regs.regs_PC + sizeof(md_inst_t);
}

void fetch(void)
{
    md_inst_t inst;
    inst_t *pI = NULL;

    if( g_piperegister[IF_ID_REGISTER] != NULL )
        return; // pipeline is stalled

    // allocate an instruction record, fill in basic information
    pI            = alloc_inst();
    pI->taken     = 0;
    pI->stalled   = 0;
    pI->pc        = g_fetch_pc;
    pI->status    = ALLOCATED;
    pI->op        = 0;
    pI->donecycle = 0xFFFFFFFF; // i.e., largest unsigned integer
    pI->uid       = g_uid++;

    /* get the instruction bits from the instruction memory */
    MD_FETCH_INST(inst, mem, g_fetch_pc);
    pI->inst = inst;

    if( g_fetch_redirected ) {
       // set PC to target of branch/jump
       g_fetch_pc = g_target_pc;

       // Opps... it looks like we fetched the wrong instruction. So, turn it into a "bubble" by 
       // deleting the instruction and leaving the IF/ID register "empty".  Note that, in 
       // hardware we would mux a nop (all zeros) into the IF/ID instruction register field.
       free_inst(pI);
       g_fetch_redirected = 0;
    } else {
       // set PC to point to next sequential instruction
       g_fetch_pc += sizeof(md_inst_t);

       // place the instruction in the IF/ID register
       pI->status = FETCHED; 
       g_piperegister[IF_ID_REGISTER] = pI; 
    }
}

void decode(void)
{
    md_inst_t inst;
    register md_addr_t addr;
    enum md_opcode op;
    register int is_write;
    enum md_fault_type fault;
    int i;
    int i1, i2, i3, o1, o2;

    inst_t *pI = g_piperegister[IF_ID_REGISTER];

    if( g_piperegister[ID_EX_REGISTER] != NULL )
        return; // stall
    if( pI == NULL )
        return; // bubble

    if( !pI->stalled ) {
        // BEGIN FUNCTIONAL EXECUTION -->
        assert( pI->pc == regs.regs_PC );

        /* maintain $r0 semantics */
        regs.regs_R[MD_REG_ZERO] = 0;
        inst = pI->inst;

        /* keep an instruction count */
        sim_num_insn++;

        /* set default reference address and access mode */
        addr = 0; is_write = FALSE;

        /* set default fault - none */
        fault = md_fault_none;

        /* decode the instruction */
        MD_SET_OPCODE(op, inst);
        pI->op = op;

        /* execute the instruction */
        switch (op)
        {
#define DEFINST(OP,MSK,NAME,OPFORM,RES,FLAGS,O1,O2,I1,I2,I3)    \
        case OP:                                                    \
              i1 = I1; i2 = I2; i3 = I3; o1 = O1; o2 = O2;          \
              SYMCAT(OP,_IMPL);                                     \
              break;
#define DEFLINK(OP,MSK,NAME,MASK,SHIFT)                         \
            case OP:                                                \
              panic("attempted to execute a linking opcode");
#define CONNECT(OP)
#define DECLARE_FAULT(FAULT)                                    \
          { fault = (FAULT); break; }
#include "machine.def"
        default:
          panic("attempted to execute a bogus opcode");
        }

        if (fault != md_fault_none)
            fatal("fault (%d) detected @ 0x%08p", fault, regs.regs_PC);

        if (verbose) {
            myfprintf(stderr, "%10n [xor: 0x%08x] @ 0x%08p: ",
            sim_num_insn, md_xor_regs(&regs), regs.regs_PC);
            md_print_insn(inst, regs.regs_PC, stderr);
            if (MD_OP_FLAGS(op) & F_MEM)
            myfprintf(stderr, "  mem: 0x%08p", addr);
            fprintf(stderr, "\n");
            /* fflush(stderr); */
        }

        if (MD_OP_FLAGS(op) & F_MEM) {
          sim_num_refs++;
          if (MD_OP_FLAGS(op) & F_STORE)
            is_write = TRUE;
        }

        /* go to the next instruction */
        regs.regs_PC = regs.regs_NPC;
        regs.regs_NPC += sizeof(md_inst_t);

        // <---  END FUNCTIONAL EXECUTION

	// record correct next instruction address (use for branches/jumps)
	pI->next_pc = regs.regs_PC;

        // record dependencies on instructions already in the pipeline 
        pI->src[0] = g_raw[i1];
        pI->src[1] = g_raw[i2];
        pI->src[2] = g_raw[i3];

        // record which register(s) this instruction writes to
        if( o1 != DNA ) g_raw[o1] = pI;
        if( o2 != DNA ) g_raw[o2] = pI;
        pI->dst[0] = o1;
        pI->dst[1] = o2;

        // determine instruction type
        if( MD_OP_FLAGS(op) & F_CTRL ) 
            pI->taken = (regs.regs_PC != (pI->pc+sizeof(md_inst_t)));
    }

    // check for RAW hazard
    for ( i=0; i < 3; ++i ) { // for each potential source operand...
        if ( pI->src[i] != NULL ) {
            // this is changed code for our assn2
	    // Stalling for LOAD into ALU
            if((MD_OP_FLAGS(op) && F_ICOMP) && (MD_OP_FLAGS(pI->src[i]->op) && F_LOAD)) { // Current instruction is ALU and previous is LOAD
              if(pI->src[i]->status == DECODED) { // When last instruction finished decode
		pI->stalled = 1; // Stall
                return;
              }
	    // Stalling for LOAD into BRANCH
            } else if((MD_OP_FLAGS(op) && F_COND) && (MD_OP_FLAGS(pI->src[i]->op) && F_LOAD)) { // Current instruction is BRANCH and previous LOAD
              if((pI->src[i]->status == DECODED) || (pI->src[i]->status == EXECUTED)) { // When last instruction finished decode or execute
                // There are 2 stalls thats why theres an OR statement
                pI->stalled = 1; // Stall
                return;
              }
            // Stalling when BRANCH, if LOAD into BRANCH, it is covered above
            } else if(MD_OP_FLAGS(op) && F_COND) { // Current instruction is BRANCH
              if(pI->src[i]->status == DECODED) { // When last instruction finished decode
                pI->stalled = 1; // Stall
                return;
              }
            }
        }
    }

    if( pI->taken ) {
        g_fetch_redirected = 1;
        g_target_pc = pI->next_pc;
    }

    // move instruction from IF/ID to ID/EX register...
    pI->stalled = 0;
    pI->status = DECODED;
    g_piperegister[ID_EX_REGISTER] = pI; // move to ID/EX register
    g_piperegister[IF_ID_REGISTER] = NULL;
}

void execute()
{
    inst_t *pI = g_piperegister[ID_EX_REGISTER];

    if( g_piperegister[EX_MEM_REGISTER] != NULL )
        return; // stall
    if( pI == NULL )
        return; // bubble
    pI->stalled = 0;
    pI->status = EXECUTED;

    g_piperegister[EX_MEM_REGISTER] = pI; // move to EX/MEM register
    g_piperegister[ID_EX_REGISTER] = NULL;
}

void memory()
{
    inst_t *pI = g_piperegister[EX_MEM_REGISTER];
    if( g_piperegister[MEM_WB_REGISTER] != NULL )
        return; // stall
    if( pI == NULL )
        return; // bubble, nothing to do

    pI->status = MEMORY_STAGE_COMPLETED;
    g_piperegister[MEM_WB_REGISTER] = pI; // move to MEM/WB register
    g_piperegister[EX_MEM_REGISTER] = NULL;
}

void writeback(void)
{
    inst_t *pI = g_piperegister[MEM_WB_REGISTER];
    if( pI == NULL )
        return; // bubble, nothing to do

    // instruction has completely finished executing

    // if this instruction is last update to its destination register that is
    // currently in the pipeline, we erase the mapping from architected
    // register to this instruction here:

    if( (pI->dst[0] != DNA) && (g_raw[pI->dst[0]] == pI) )
        g_raw[ pI->dst[0] ] = NULL;
    if( (pI->dst[1] != DNA) && (g_raw[pI->dst[1]] == pI) )
        g_raw[ pI->dst[1] ] = NULL;

    pI->donecycle = sim_cycle;
    pI->status = DONE; // i.e., finished writing back this cycle
    g_piperegister[MEM_WB_REGISTER] = NULL;
    free_inst(pI);
        // instruction will not be reused immediately (see implementation of
        // alloc_inst, and free_inst) so "status" will remain "DONE" while
        // any dependent instructions continue through pipeline
}

void print_instruction( inst_t *x )
{
    enum md_opcode op;
    if( x == NULL ) {
        printf( "            *** bubble ***\n" );
        return;
    }
    printf("%8u:", x->uid);
    MD_SET_OPCODE(op, x->inst);
    if( MD_OP_FLAGS(x->op) & F_LOAD ) {
        printf( "L  " );
    } else if( MD_OP_FLAGS(x->op) & F_CTRL ) {
        printf( "B" );
        if( x->taken ) printf( "T " );
        else printf( "N " );
    } else printf( "   " );
    printf("0x%6x ", x->pc );
    md_print_insn( x->inst, x->pc, stdout );
    if( x->stalled )
        printf(" *** stalled *** ");
    printf("\n");
    // add other interesting information you want to see
}

void display_pipeline()
{
    // call this function from within gdb to print out status of pipeline
    // if you encounter a bug, or to visualize pipeline operation
    // (this is a good way to "verify" your pipeline model makes sense!)

    printf("========================================\n");
    printf("pipeline status at end of cycle %u:\n", sim_cycle);
    printf("========================================\n");
    printf("PC     :=             0x%6x\n", g_fetch_pc );
    printf("IF/ID  := ");
    print_instruction( g_piperegister[IF_ID_REGISTER] );
    printf("ID/EX  := ");
    print_instruction( g_piperegister[ID_EX_REGISTER] );
    printf("EX/MEM := ");
    print_instruction( g_piperegister[EX_MEM_REGISTER] );
    printf("MEM/WB := ");
    print_instruction( g_piperegister[MEM_WB_REGISTER] );
    printf("\n");
}

/* start simulation, program loaded, processor precise state initialized */
void sim_main(void)
{
    cpen411_init();

    do {
        writeback();
        memory();
        execute();
        decode();
        fetch();

        sim_cycle++;
    } while (!max_insts || sim_num_insn < max_insts);
}
