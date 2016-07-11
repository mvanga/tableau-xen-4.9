#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/domain.h>
#include <xen/delay.h>
#include <xen/event.h>
#include <xen/time.h>
#include <xen/sched-if.h>
#include <xen/softirq.h>
#include <asm/atomic.h>
#include <asm/div64.h>
#include <asm/div64.h>
#include <xen/errno.h>
#include <xen/keyhandler.h>
#include <xen/trace.h>
#include <xen/guest_access.h>
#include <xen/ctype.h>
#include <xen/ctype.h>
#include <xen/string.h>
#include <xen/stdbool.h>
#include <xen/trace.h>

/* Debugging and tracing macros */
//#define DEBUG
//#define TRACE

/* Useful trace points in the scheduler for measuring overheads */
#define TRC_TTXEN_TABLE_SWITCHED    TRC_SCHED_CLASS_EVT(TABLEAU, 1)
#define TRC_TTXEN_TABLE_WRAPPED     TRC_SCHED_CLASS_EVT(TABLEAU, 2)
#define TRC_TTXEN_SCHED_START       TRC_SCHED_CLASS_EVT(TABLEAU, 3)
#define TRC_TTXEN_SCHED_END         TRC_SCHED_CLASS_EVT(TABLEAU, 4)

/* Per-core schedule() call counter. In traces so start/end's can be matched */
DEFINE_PER_CPU(unsigned long long, ttxen_sched_iteration);

/* Custom debug output with CPU number */
#ifdef DEBUG
# define debug(fmt, args...) \
    printk(KERN_DEBUG "%s(CPU=%d): " fmt "\n", \
            __FUNCTION__, \
            smp_processor_id(), \
            ##args)
#else
# define debug(fmt, args...) do {} while(0)
#endif

/* Custom trace output that prints the function/line */
#ifdef TRACE
# define trace() \
    printk(KERN_DEBUG "%s:%d @ CPU%d\n", \
            __FUNCTION__, \
            __LINE__, \
            smp_processor_id())
#else
# define trace() do {} while(0)
#endif

/*
 * Core Rendevous for TSC Offset Calculation
 *
 * On larger multi-socket systems, the timestamp counters (tsc) can be
 * offset across cores. This is problematic when measuring overheads
 * of cross-core operations (e.g., the overhead of a wakeup IPI). To
 * have sensible results, the offsets of timestamp counters on individual
 * cores are empirically calculated via a "rendevous" phase at boot time.
 *
 * During rendevous, the each core spin on a special per-core "rendevous
 * location" in memory. When core 0 (to which all other cores are
 * synchronized) writes a timestamp to this location, the spinning core
 * responds immediately with its own local timestamp. This is performed
 * multiple times per core and the offset is taken to be the average of
 * these samples.
 */

/* The number of rendevous loops that are performed per core */
#define CONFIG_RENDEVOUS_LOOPS              1000
/* The number of initial samples to discard (to remove cache-related effects */
#define CONFIG_RENDEVOUS_DISCARD_SAMPLES    10

/* The rendevous structure. Each core has access to an array of these. */
struct rendevous {
    volatile s_time_t rendevous;
    volatile s_time_t response;
};

/* Various constants used across the scheduler implementation */

/* A constant that specifies "none of the CPUs in the system" */
#define CPU_NONE            (-1)

/*
 * vCPUs in Tableau can be of two types: tier-2 vCPUs are scheduled on a
 * best-effort basis during idle time on cores. tier-1 vCPUs are scheduled
 * via a statically generated scheduling table that guarantees a specific
 * utilization and a bound on scheduling delay.
 */
#define VCPU_TYPE_TIER2  0
#define VCPU_TYPE_TIER1  1

/* The timeslice to use for scheduling tier-2 VMs */
#define CONFIG_TIER2_TIMESLICE      MILLISECS(30)
#define CONFIG_LEVEL2_TIMESLICE     MILLISECS(1)
#define CONFIG_LEVEL2_EPOCH         MILLISECS(20)
#define CONFIG_INITTABLE_LEN        MILLISECS(30)

struct ttxen_table;

/* Per-CPU structure */
struct ttxen_pcpu {
    struct list_head t2_runq;   /* Runqueue of runnable tier-2 VCPU's */
    spinlock_t t2_lock;         /* Spinlock for concurrent runqueue access */
};

struct ttxen_vcpu {
    /*
     * This is a per-VCPU lock protecting internal state. This lock is
     * always acquired _only when holding a runqueue lock_. The pseudocode
     * below uses vcpu_lock() and vcpu_unlock() to lock this field.
     */
    spinlock_t lock;

    struct ttxen_dom *sdom;     /* The domain this VCPU belongs to */
    struct vcpu *vcpu;          /* The Xen VCPU structure for this VCPU */

    /*
     * The CPU number of the CPU that this vCPU has a slot currently on. If
     * it has no slot currently, this is set to CPU_NONE. Note that a vCPU
     * may currently have a slot on a particular CPU but not be *running*
     * there (e.g., if it is still being migrated).
     */
    int slot_on_cpu;

    /*
     * The CPU that this vCPU is *running* on. That is it is being currently
     * scheduled on that core. If the vCPU is not running on any core, this
     * is set to CPU_NONE.
     */
    int running_on_cpu;

    /*
     * If a slot for a vCPU begins one core but it is still being descheduled
     * on another, the CPU with the newly active slot simply sets this field
     * to its own ID. If, after descheduling, this field is set, the CPU that
     * performed the descheduling sends an IPI to initiate a retry on the core.
     */
    int needs_wakeup;

    /* vCPU type (tier-1: VCPU_TYPE_TIER1, or tier-2: VCPU_TYPE_TIER2 */
    int type;

    /* If this is a tier-2 vCPU, this holds the CPU it is partitioned on */
    int t2_cpu;

    /* The budget and last replenishment time for tier-2 scheduling */
    long long budget;
    unsigned long long last_replenish;

    struct list_head dom_elem;  /* List structure for storing in domain list */
    struct list_head t2_elem;   /* List structure for storing in Tier-2 list */

    int scheduled_by_l2;
};

/* Domain structure */
struct ttxen_dom {
    uint16_t num_vcpus;         /* The number of VCPU's this domain has */
    struct list_head vcpu_list; /* List of ttxen_vcpu structures for domain */
    struct domain *dom;         /* The Xen domain structure for this domain */
    struct list_head elem;      /* List structure for global domain list */
};

/* Per-CPU structure storing useful stuff */
struct ttxen_percpu {
    /*
     * Each table in Tableau consists of a single global header containing
     * global information as well as per-CPU schedules. The *_table pointer
     * points to the per-CPU structure and the *_table_global pointers point
     * to the global structure.
     */

    /* The current table being scheduled */
    struct ttxen_percpu_head *curr_table;   /* Current table being scheduled */
    struct ttxen_global_head *curr_table_global;   /* Current table being scheduled */

    /* The next table to be scheduled */
    struct ttxen_percpu_head *next_table;   /* Next table to be scheduled */
    struct ttxen_global_head *next_table_global;   /* Next table to be scheduled */

    struct ttxen_slot *slot;    /* Current slot in the table being scheduled */
    uint64_t round;             /* Current round (increments on table wrap) */
    s_time_t table_start;       /* Start time of current round */
    s_time_t last_t2_start;     /* Start time of current tier2 slice */

    s_time_t last_l2_start;     /* Start time of current level-2 slice */
    s_time_t last_l2_epoch;     /* Start time of last level-2 epoch */
};

/* Define the Per-CPU table structure */
DEFINE_PER_CPU(struct ttxen_percpu, ttxen_cputable);

/*
 * Per-CPU Statistics
 *
 * The total idle time in each round of the table is tracked. This is used
 * by the userspace tier-2 load balancer to re-partition tier-2 vCPUs onto
 * cores. That is, cores with more idle time in the last few rounds get
 * assigned more vCPUs.
 *
 * This is encapsulated in a more generic "stats" structure that can be
 * extended to collect other stats (e.g., CPI, cache misses etc.)
 */

/*
 * The number of "slots" of stats that are stored. That is, with a value 10,
 * the stats from last 10 rounds are stored.
 */
#define CONFIG_MAX_STATS    10

struct ttxen_stats_single {
    /* Boundaries of the round during which these stats were collected */
    s_time_t start;
    s_time_t end;

    /* Statistic: the total idle time during the last round */
    s_time_t total_idle_time;
};

struct ttxen_stats {
    unsigned long cslot;                                /* stats slot no. to use */
    struct ttxen_stats_single slots[CONFIG_MAX_STATS];  /* per-core stats */
};

/* System-wide private data */
struct ttxen_private {
    unsigned long num_pcpus;    /* Number of physical CPU's in the system */
    struct list_head domains;   /* List of active domains in the system */
    cpumask_var_t pcpu_mask;    /* Bitmap of physical CPU's in the system */
    spinlock_t lock;            /* Lock for accessing the global state */
    int switch_in_progress;

    /* Array of per-core rendevous stations */
    struct rendevous rendevous[NR_CPUS];
    /* Array of per-core stats structs */
    struct ttxen_stats stats[NR_CPUS];
    /* Array of per-core timestamp offsets (rel. to CPU0) */
    int64_t tsc_off[NR_CPUS];
};

/*
 * Tableau implements a new hypercall for passing a table from userspace.
 * The following ops structure is used to pass the needed information.
 */

/* Magic value for ensuring a correct structure*/
#define TTXEN_OP_MAGIC  0xdeadbeef
struct ttxen_op_vcpu {
    unsigned long magic;
    unsigned long dom_id;
    unsigned long vcpu_id;
    long cpu;
};

/* The global timer whose callback is used to switch table pointers */
static struct timer switch_timer;
/* The global timer whose callback is used to garbage collect old tables */
static struct timer gc_timer;

/* Useful macros */
#define TTXEN_PRIV(_ops) \
    ((struct ttxen_private *)((_ops)->sched_data))
#define TTXEN_PCPU(_c)   \
    ((struct ttxen_pcpu *)per_cpu(schedule_data, _c).sched_priv)
#define TTXEN_VCPU(_vcpu) \
    ((struct ttxen_vcpu *) (_vcpu)->sched_priv)
#define TTXEN_DOM(_dom) \
    ((struct ttxen_dom *) (_dom)->sched_priv)
#define TTXEN_PERCPU(cpu) \
    (&per_cpu(ttxen_cputable, cpu))

/* Helper function to get a VCPU given a domain ID and a VCPU ID */
static inline struct ttxen_vcpu *
get_vcpu(struct ttxen_private *prv, int dom_id, int vcpu_id)
{
    struct ttxen_dom *domain;
    struct ttxen_vcpu *vcpu;

    list_for_each_entry(domain, &prv->domains, elem) {
        if (domain->dom->domain_id != dom_id)
            continue;
        list_for_each_entry(vcpu, &domain->vcpu_list, dom_elem) {
            if (vcpu->vcpu->vcpu_id == vcpu_id)
                return vcpu;
        }
    }

    return NULL;
}

/*
 * Table data structures. These mirror the packed structures that are
 * received from userspace.
 */

struct ttxen_vcpu_info {
    uint32_t dom_id;        /* Domain id */
    uint32_t vcpu_id;       /* VCPU id */
    uint64_t cpumask;       /* CPUs on which this VCPU has slots (128 max) */
    uint64_t flags;         /* Primarily whether this VCPU migrates or not */
    struct ttxen_vcpu *vcpu;/* Reserved for pointer to struct ttxen_vcpu */
} __attribute__((aligned(64)));

struct ttxen_slot {
    uint64_t offset;        /* Offset into vcpu_info list. Replaced with pointer in hypervisor */
    struct ttxen_vcpu *vcpu;/* Reserved for pointer to struct ttxen_vcpu */
    uint64_t length;        /* Length of slot in nsec */
    uint64_t start;         /* Starting offset of slot in nsec */
    uint64_t end;           /* Ending offset of slot in nsec */
} __attribute__((aligned(64)));

struct ttxen_l2_slot {
    uint64_t start;         /* Starting offset of slot in nsec */
    uint64_t end;           /* Ending offset of slot in nsec */
    uint64_t length;        /* Length of slot in nsec */
    uint64_t restricts;     /* Restricted set of vCPUs at this point in time */
} __attribute__((aligned(64)));

struct ttxen_slice {                                                                
    uint64_t start;         /* Start time of slice */                         
    uint64_t end;           /* End time of slice */                           
                                                                              
    /* The left, right and idle_middle fields need to be adjusted by the hypervisor */      
    struct ttxen_slot *left;          /* Offset into slot list (or > len(slots) if none) */
    struct ttxen_slot *idle_middle;   /* Idle slot in between two slots if any (or > len(slots)) */
    struct ttxen_slot *right;         /* Offset into slot list (or > len(slots) if none) */
                                                                              
    uint64_t boundary;    /* Offset (for idle_middle) in nsec, if any (0 otherwise) */
} __attribute__((aligned(64)));

/* The per-CPU table */
struct ttxen_percpu_head {
    uint64_t nslots;        /* No. of slots */
    uint64_t slot_list_off; /* Offset of slot list */
    uint64_t nslices;       /* No. of slices */
    uint64_t slice_list_off;/* Offset of slice list */
    uint64_t slice_length;  /* Length of slicing */
    uint64_t table_length;  /* Length of table (added here for locality) */
    uint64_t nvcpus;           /* No. of tier-1 vCPUs */
    uint64_t vcpu_list_off;    /* Offset of vCPU info list */
} __attribute__((aligned(64)));

/* The global table */
struct ttxen_global_head {
    uint64_t num_vcpus;         /* Number of VCPUs is VCPU list */
    uint64_t vcpu_list_off;     /* Offset of VCPU list */
    uint64_t num_cpus;          /* Number of CPUs in Per-CPU data list */
    uint64_t percpu_off[NR_CPUS];  /* Per-CPU data offsets */
    uint64_t length;
} __attribute__((aligned(4096)));


/* Table-related utility functions */

/* Get the per-CPU structure given the global header */
static inline struct ttxen_percpu_head *
ttxen_percpu_head(struct ttxen_global_head *head, int cpu)
{
    return (struct ttxen_percpu_head *)((char *)head + head->percpu_off[cpu]);
}

/* Get the VCPU info list given the global header */
static inline struct ttxen_vcpu_info *
ttxen_get_vcpu_info(struct ttxen_global_head *head)
{
    return (struct ttxen_vcpu_info *)((char *)head + head->vcpu_list_off);
}

/* Get the per-CPU VCPU info list given the percpu header */
static inline struct ttxen_vcpu_info *
ttxen_get_percpu_vcpu_info(struct ttxen_percpu_head *phead)
{
    return (struct ttxen_vcpu_info *)((char *)phead + phead->vcpu_list_off);
}

/* Get the slice info list given the percpu header */
static inline struct ttxen_slice *
ttxen_get_slices(struct ttxen_percpu_head *head)
{
    return (struct ttxen_slice *)((char *)head + head->slice_list_off);
}

/* Get the slot info list given the percpu header */
static inline struct ttxen_slot *
ttxen_get_slots(struct ttxen_percpu_head *head)
{
    return (struct ttxen_slot *)((char *)head + head->slot_list_off);
}

/* Get the ttxen_vcpu struct given a domain and a VCPU id */
static inline struct ttxen_vcpu *
ttxen_get_dom_vcpu(struct domain *dom, int vcpu_id)
{
    struct ttxen_vcpu *svc;
    list_for_each_entry(svc, &TTXEN_DOM(dom)->vcpu_list, dom_elem)
        if (svc->vcpu->vcpu_id == vcpu_id)
            return svc;
    return NULL;
}

/*
 * Given a slice and a current time, figure out which part of the slice
 * should be currently scheduled (right, middle, or left).;
 */
static inline struct ttxen_slot *ttxen_slice_to_slot(struct ttxen_percpu *pt,
    struct ttxen_slice *slice, s_time_t now)
{
    /* If now is out-of-bounds for this slice, return NULL */
    if (now < pt->table_start + (s_time_t)slice->start ||
        now >= pt->table_start + (s_time_t)slice->end)
        return NULL;

    /* Check (in order) right, middle, and left slots */
    if (slice->left && now < pt->table_start + (s_time_t)slice->left->end)
        return slice->left;

    if (slice->idle_middle &&
        now >= pt->table_start + (s_time_t)slice->idle_middle->start &&
        now < pt->table_start + (s_time_t)slice->idle_middle->end)
        return slice->idle_middle;

    if (slice->right && now >= pt->table_start + (s_time_t)slice->right->start)
        return slice->right;

    /* Slices should be "fully covered" by slots. This should never happen */
    BUG();
}

/* Get the slot for a given time */
static inline struct ttxen_slot *
ttxen_get_slot(struct ttxen_percpu *pt,
    s_time_t now)
{
    int off;
    struct ttxen_slice *slices;

    off = (now - pt->table_start) / pt->curr_table->slice_length;
    slices = ttxen_get_slices(pt->curr_table);

    return ttxen_slice_to_slot(pt, &slices[off], now);
}

static inline struct ttxen_global_head *
make_table(uint64_t num_vcpus, uint64_t num_cpus, int percpu_pages)
{
    unsigned long i;
    struct ttxen_global_head *head;

    /*
     * For the initial table, the breakdown looks as follows:
     * Global header: 1 page
     * VCPU list: 1 page
     * Percpu-inf: 3 pages/core (or user-specified)
     *    header: 1 page
     *    slots: 1 page
     *    slices: 1 page
     *
     * Need to allocate: (2 + num_cpus * 3) pages
     */

    /*
     * struct ttxen_global_head is 1 page long. Due to the implementation of
     * xzalloc_array (which uses the underlying _xzalloc), the resulting mem
     * is aligned using gcc's __alignof__ to the size of the type being passed.
     * This ensures that we get a page-aligned piece of memory.
     */
    head = xzalloc_array(struct ttxen_global_head, 2 + num_cpus * percpu_pages);
    BUG_ON(!head);

    head->num_vcpus = num_vcpus; 
    head->vcpu_list_off = 4096;
    head->num_cpus = num_cpus;
    for (i = 0; i < num_cpus; i++)
        head->percpu_off[i] = 8192 + i * percpu_pages * 4096; // 3 pages per CPU
    head->length = percpu_pages * 4096;

    return head;
}

static inline void make_percpu_head(struct ttxen_percpu_head *phead,
    uint64_t nslots, uint64_t nslices, uint64_t slen, uint64_t tlen)
{
    phead->nslots = nslots;
    phead->nslices = nslices;
    phead->slot_list_off = 4096;
    phead->slice_list_off = 8192;
    phead->slice_length = slen;
    phead->table_length = tlen;
}

static inline void make_vinfo_entry(struct ttxen_vcpu_info *vinfo, int i,
        uint64_t dom_id, uint64_t vcpu_id, uint64_t cpumask, uint64_t flags)
{
    vinfo[i].dom_id = dom_id;
    vinfo[i].vcpu_id = vcpu_id;
    vinfo[i].cpumask = cpumask;
    vinfo[i].flags = flags;
    vinfo[i].vcpu = NULL;
}

/* Build a slot at a specified address. Used during initial table generation */
static inline void make_slot(struct ttxen_slot *slots, int i, uint64_t offset,
    uint64_t vinfo_offset, uint64_t length)
{
    struct ttxen_slot *slot;

    slot = &slots[i];
    slot->offset = offset;
    slot->vcpu = (struct ttxen_vcpu *)vinfo_offset;
    slot->length = length;
    slot->start = offset;
    slot->end = offset + length;
}

/* Build a slice at a specified address. Used during initial table generation */
static inline void make_slice(struct ttxen_slice *slices, int i, uint64_t start,
    uint64_t end, int slot_index)
{
    struct ttxen_slice *slice;

    slice = &slices[i];
    slice->start = start;
    slice->end = end;
    slice->left = (struct ttxen_slot *)((unsigned long long)slot_index);
    slice->idle_middle = NULL;
    slice->right = NULL;
    slice->boundary = 0;
}

/* Scheduler functions */

static void garbage_collect_callback(void *_table)
{
    int cpu = smp_processor_id();
    struct ttxen_private *priv = TTXEN_PRIV(per_cpu(scheduler, cpu));

    /* We should simply free up the old table data */
    xfree((char *)_table);
    printk("garbage collected old table\n");
    priv->switch_in_progress = 0;
}

/* This callback is invoked when a new table needs to be installed  */
static void update_table_callback(void *_table)
{
    unsigned long i;
    int cpu = smp_processor_id();
    struct ttxen_global_head *header;
    struct ttxen_percpu_head *table;
    struct ttxen_percpu *percpu;
    struct ttxen_private *priv = TTXEN_PRIV(per_cpu(scheduler, cpu));

    header = (struct ttxen_global_head *)_table;

    /* Simply set each per-cpu next-table pointer */
    for (i = 0; i < priv->num_pcpus; i++) {
        table = ttxen_percpu_head(header, i);
        percpu = TTXEN_PERCPU(i);
        percpu->next_table = table;
        percpu->next_table_global = header;
    }
    printk("CPU%d: set next_table for all cores\n", cpu);
}

/*
 * The update_table() function updates the next table pointer safely. The
 * technique employed is quite simple: setup a timer that fires at a time
 * that we are certain a table-switch would be safe. The timer callback
 * (see update_table_callback() above) sets the next-table pointer for
 * all CPUs. TODO: this cannot be called concurrently. For now, the code
 * assumes that there are no concurrent update_table() calls.
 */
int update_table(struct ttxen_global_head *gtable)
{
    s_time_t t_gc;
    s_time_t t_switch;
    s_time_t tstart;
    struct ttxen_percpu_head *ctable;
    struct ttxen_percpu_head *ntable;
    struct ttxen_global_head *ctable_global;
    int cpu = smp_processor_id();
    struct ttxen_percpu *pt = TTXEN_PERCPU(cpu);

    ctable = pt->curr_table; /* We are certain this will not change */
    ctable_global = pt->curr_table_global; /* We are certain this will not change */
    ntable = ttxen_percpu_head(gtable, cpu);
    tstart = pt->table_start;  /* store this out in case it changes */

    /*
     * We now calculate two times in the future where we can (i) switch the
     * table of all CPUs safely, and (ii) garbage collect the old table once
     * the new one has been picked up.
     *
     * Switch when CPUs are 50% into the second round after the current one
     * The reason for using 50% is arbitrary and using two rounds is based on
     * minimizing the risk that the 50% point of the next round is reached
     * while in this operation (extremely unlikely unless we are blocked for a
     * nice long while for some reason, but again, it's arbitrary).
     *
     * Garbage collect at least one round after the switch.
     */
    t_gc = tstart + ctable->table_length + 2 * ntable->table_length + ntable->table_length / 3;
    t_switch = tstart + 2 * ctable->table_length + ctable->table_length / 3;

    /* Initialize and setup our two timers */
    init_timer(&gc_timer, garbage_collect_callback, (void *)ctable_global, cpu);
    init_timer(&switch_timer, update_table_callback, (void *)gtable, cpu);
    set_timer(&gc_timer, t_gc);
    set_timer(&switch_timer, t_switch);

    return 0;
}

void ttxen_table_dump(struct ttxen_global_head *head);

/*
 * When tables are passed from userspace, they need some fixups before they
 * are suitable for scheduling. Specifically, this involves fixing the VCPU
 * pointers to point to the actual structs in the hypervsisor. This function
 * performs this as well as other minor fixes.
 */
static int
ttxen_table_weave(struct ttxen_private *prv, struct ttxen_global_head *head)
{
    unsigned long i, j;
    struct ttxen_vcpu_info *vinfo;
    struct ttxen_vcpu_info *pvinfo;
    struct ttxen_percpu_head *phead;
    struct ttxen_slot *slots;
    struct ttxen_slice *slices;

    trace();

    vinfo = ttxen_get_vcpu_info(head);
    debug("%llu global vcpus found\n", (unsigned long long)head->num_vcpus);
    for (i = 0; i < head->num_vcpus; i++) {
        vinfo[i].vcpu = get_vcpu(prv, vinfo[i].dom_id, vinfo[i].vcpu_id);
        debug("%d.%d = %p\n", (int)vinfo[i].dom_id, (int)vinfo[i].vcpu_id, vinfo[i].vcpu);
        if (!vinfo[i].vcpu)
            return -EINVAL;
    }


    //for (i = 0; i < prv->num_pcpus; i++) {
    //    struct ttxen_vcpu *idle = TTXEN_VCPU(idle_vcpu[i]);
    //    debug("%d.%d = %p\n", (int)idle->vcpu->domain->domain_id, (int)idle->vcpu->vcpu_id, idle);
    //}

    debug("%llu cpus found\n", (unsigned long long)head->num_cpus);
    for (i = 0; i < head->num_cpus; i++) {
        phead = ttxen_percpu_head(head, i);
        slots = ttxen_get_slots(phead);
        slices = ttxen_get_slices(phead);

        /* Table length and slice length should not be zero */
        if (phead->table_length == 0 || phead->slice_length == 0)
            return -EINVAL;
        if (phead->nslots == 0 || phead->nslices == 0)
            return -EINVAL;

        //debug("%llu slots found\n", (unsigned long long)phead->nslots);
        for (j = 0; j < phead->nslots; j++) {
            if ((unsigned long long)slots[j].vcpu >= head->num_vcpus)
                slots[j].vcpu = TTXEN_VCPU(idle_vcpu[i]);
            else
                slots[j].vcpu = vinfo[(unsigned long long)slots[j].vcpu].vcpu;
        }

        phead = ttxen_percpu_head(head, i);
        pvinfo = ttxen_get_percpu_vcpu_info(phead);
        printk("%llu percore vcpus found on core %lu\n", (unsigned long long)phead->nvcpus, i);
        for (j = 0; j < phead->nvcpus; j++) {
            pvinfo[j].vcpu = get_vcpu(prv, pvinfo[j].dom_id, pvinfo[j].vcpu_id);
            printk("%d.%d = %p\n", (int)pvinfo[j].dom_id, (int)pvinfo[j].vcpu_id, pvinfo[j].vcpu);
            if (!pvinfo[j].vcpu)
                return -EINVAL;
        }

        //debug("%llu slices found\n", (unsigned long long)phead->nslices);
        for (j = 0; j < phead->nslices; j++) {
            // TODO: error checks needed for missing slots

            /* left is mandatory for a slice. The others may be > nslots */
            if (!((unsigned long long)slices[j].left < phead->nslots))
                return -EINVAL;
            slices[j].left = &slots[(unsigned long long)slices[j].left];

            /* For others, if it's an idle VCPU, the slot offset > nslots */
            if ((unsigned long long)slices[j].idle_middle &&
                (unsigned long long)slices[j].idle_middle < phead->nslots)
                slices[j].idle_middle = &slots[(unsigned long long)slices[j].idle_middle];
            else
                slices[j].idle_middle = NULL;

            if ((unsigned long long)slices[j].right &&
                (unsigned long long)slices[j].right < phead->nslots)
                slices[j].right = &slots[(unsigned long long)slices[j].right];
            else
                slices[j].right = NULL;
        }
    }
    //debug("done\n");
    //ttxen_table_dump(head);

    return 0;
}

#define TTXEN_OP_PUSH_TABLE         0
#define TTXEN_OP_READ_TABLE         1
#define TTXEN_OP_READ_TABLE_LENGTH  2
#define TTXEN_OP_READ_STATS         3
#define TTXEN_OP_ADD_VCPU           4
#define TTXEN_OP_REMOVE_VCPU        5
#define TTXEN_OP_TOGGLE_TYPE        6
#define TTXEN_OP_VCPU_CORE          7
#define TTXEN_OP_READ_NUM_CPUS      8
#define TTXEN_OP_MOVE_VCPU          9

/*
 * This hypercall is the simplest implementation I could think of for passing
 * the table from Dom0 to the hypervisor. Dom0 generates a binary string that
 * holds all the data we need and pushes it. We simply copy it over and use
 * the table as-is (since we never need to modify tables at runtime).
 * TODO: support for concurrent calls to push_table.
 */
long do_tableau_op(unsigned long op, unsigned long length,
    XEN_GUEST_HANDLE_PARAM(void) arg)
{
    int ret = 0;
    char *table_raw = 0;
    struct ttxen_global_head *table;
    int cpu = smp_processor_id();
    struct ttxen_private *prv = TTXEN_PRIV(per_cpu(scheduler, cpu));
    struct ttxen_op_vcpu top;
    struct ttxen_percpu *pt = TTXEN_PERCPU(cpu);
    struct ttxen_vcpu *svc;
    struct ttxen_pcpu *spc;
    unsigned long flags;

    printk("do_tablau_op: called (op=%lu, length=%lu)\n", op, length);

    switch(op) {
        case TTXEN_OP_PUSH_TABLE:
            printk("received scheduling table of length: %lu bytes\n", length);

            if (prv->switch_in_progress)
                return -EAGAIN;

            /* Allocate a buffer to hold all the table data */
            table_raw = xzalloc_array(char, length);
            if (!table_raw)
                return -ENOMEM;

            /* Copy the table from userspace */
            ret = copy_from_guest(table_raw, arg, length);
            if (ret) {
                xfree(table_raw);
                return -EFAULT;
            }

            /* The global header is always at offset 0 in the pushed data */
            table = (struct ttxen_global_head *)table_raw;
            table->length = length;

            /*
             * We've copied the table but still need to set up all the pointers so
             * that we can associate them with hypervisor-level data structures
             * (specifically, VCPUs and slot pointers in slices). This call does this.
             */
            ret = ttxen_table_weave(prv, table);
            if (ret < 0) {
                xfree(table_raw);
                return -EINVAL;
            }

            /* Now just update the table and we're done (unless it times out) */
            prv->switch_in_progress = 1;
            if (update_table(table) < 0) {
                xfree(table_raw);
                return -EAGAIN;
            }
            break;
        case TTXEN_OP_READ_TABLE_LENGTH:
            length = pt->curr_table_global->length;

            if (prv->switch_in_progress) {
                printk("tableau_op: read_table_length: error: table switch in progress\n");
                return -EAGAIN;
            }

            ret = copy_to_guest(arg, &length, 1);
            if (ret) {
                printk("tableau_op: read_table_length: error: failed to copy to guest\n");
                return -EFAULT;
            }

            printk("tableau_op: read_table_length: current table length: %lu\n", length);

            break;
        case TTXEN_OP_READ_TABLE:
            if (prv->switch_in_progress) {
                printk("tableau_op: read_table: error: table switch in progress\n");
                return -EAGAIN;
            }

            ret = copy_to_guest(arg, (char *)pt->curr_table_global,
                pt->curr_table_global->length);
            if (ret) {
                printk("tableau_op: read_table: failed to copy table to guest\n");
                return ret;
            }

            printk("tableau_op: read_table: successfully copied table to guest\n");

            break;
        case TTXEN_OP_READ_NUM_CPUS:
            ret = copy_to_guest(arg, &prv->num_pcpus, 1);
            if (ret) {
                printk("tableau_op: read_num_cpus: error: table switch in progress\n");
                return -EFAULT;
            }

            printk("tableau_op: read_num_cpus: found %lu cpus\n", prv->num_pcpus);

            break;
        case TTXEN_OP_READ_STATS:
            /* Ensure bounds on arg buffer size */
            ret = copy_to_guest(arg, prv->stats, prv->num_pcpus);
            if (ret) {
                printk("tableau_op: read_stats: error: failed to copy stats to guest\n");
                return -EFAULT;
            }

            printk("tableau_op: read_stats: successfully copied stats to guest\n");

            break;
        case TTXEN_OP_ADD_VCPU:
            /* Copy the table from userspace */
            ret = copy_from_guest(&top, arg, 1);
            if (ret)
                return -EFAULT;

            /* Check for magic value to ensure correct copying of structs */
            if (top.magic != TTXEN_OP_MAGIC)
                return -EFAULT;

            /* Basic sanity checks on the vcpu and CPU number */
            svc = get_vcpu(prv, top.dom_id, top.vcpu_id);
            if (!svc || top.cpu >= (long)prv->num_pcpus)
                return -EINVAL;

            /* Add to VCPU list. Grab the lock to avoid list corruption. */
            spc = TTXEN_PCPU(top.cpu);
            spin_lock_irqsave(&spc->t2_lock, flags);
            svc->t2_cpu = top.cpu;
            /* These ops specifically apply only to Tier-2 VCPUs */
            svc->type = VCPU_TYPE_TIER2;
            list_add_tail(&svc->t2_elem, &spc->t2_runq);
            spin_unlock_irqrestore(&spc->t2_lock, flags);
            break;
        case TTXEN_OP_REMOVE_VCPU:
            /* Copy the table from userspace */
            ret = copy_from_guest(&top, arg, 1);
            if (ret)
                return -EFAULT;

            /* Check for magic value to ensure correct copying of structs */
            if (top.magic != TTXEN_OP_MAGIC)
                return -EFAULT;

            /* Basic sanity checks on the vcpu and CPU number */
            svc = get_vcpu(prv, top.dom_id, top.vcpu_id);
            if (!svc)
                return -EINVAL;

            /* Make sure this is not a tier 1 VCPU */
            if (svc->t2_cpu < 0 || svc->type != VCPU_TYPE_TIER2)
                return -EINVAL;

            spc = TTXEN_PCPU(svc->t2_cpu);
            spin_lock_irqsave(&spc->t2_lock, flags);
            list_del(&svc->t2_elem);
            svc->t2_cpu = -1;
            spin_unlock_irqrestore(&spc->t2_lock, flags);
            break;
        case TTXEN_OP_MOVE_VCPU:
            /* Copy the table from userspace */
            ret = copy_from_guest(&top, arg, 1);
            if (ret)
                return -EFAULT;

            /* Check for magic value to ensure correct copying of structs */
            if (top.magic != TTXEN_OP_MAGIC)
                return -EFAULT;

            /* Basic sanity checks on the vcpu and CPU number */
            svc = get_vcpu(prv, top.dom_id, top.vcpu_id);
            if (!svc)
                return -EINVAL;

            /* Make sure this is not a tier 1 VCPU */
            if (svc->t2_cpu < 0 || svc->type != VCPU_TYPE_TIER2)
                return -EINVAL;

            /* If we're asking to move to the same core, return */
            if (svc->t2_cpu == top.cpu)
                return 0;

            spc = TTXEN_PCPU(svc->t2_cpu);
            spin_lock_irqsave(&spc->t2_lock, flags);
            list_del(&svc->t2_elem);
            svc->t2_cpu = -1;
            spin_unlock_irqrestore(&spc->t2_lock, flags);

            /* Add to VCPU list. Grab the lock to avoid list corruption. */
            spc = TTXEN_PCPU(top.cpu);
            spin_lock_irqsave(&spc->t2_lock, flags);
            svc->t2_cpu = top.cpu;
            /* These ops specifically apply only to Tier-2 VCPUs */
            svc->type = VCPU_TYPE_TIER2;
            list_add_tail(&svc->t2_elem, &spc->t2_runq);
            spin_unlock_irqrestore(&spc->t2_lock, flags);
            break;

        case TTXEN_OP_TOGGLE_TYPE:
            /* Copy the table from userspace */
            ret = copy_from_guest(&top, arg, 1);
            if (ret)
                return -EFAULT;

            /* Check for magic value to ensure correct copying of structs */
            if (top.magic != TTXEN_OP_MAGIC)
                return -EFAULT;

            /* Basic sanity checks on the vcpu and CPU number */
            svc = get_vcpu(prv, top.dom_id, top.vcpu_id);
            if (!svc)
                return -EINVAL;

            /* Cannot toggle a Tier-2 VCPU that is in some queue */
            if (svc->type == VCPU_TYPE_TIER2 && svc->t2_cpu >= 0)
                return -EINVAL;

            if (is_idle_vcpu(svc->vcpu))
                return -EINVAL;

            svc->type = !svc->type;
            break;
        case TTXEN_OP_VCPU_CORE:
            ret = copy_from_guest(&top, arg, 1);
            if (ret)
                return -EFAULT;

            /* Check for magic value to ensure correct copying of structs */
            if (top.magic != TTXEN_OP_MAGIC)
                return -EFAULT;

            /* Basic sanity checks on the vcpu and CPU number */
            svc = get_vcpu(prv, top.dom_id, top.vcpu_id);
            if (!svc)
                return -EINVAL;

            top.cpu = ((svc->type & 0xffff) << 16) | (svc->t2_cpu & 0xffff);
            ret = copy_to_guest(arg, &top, 1);
            if (ret)
                return -EFAULT;
            break;
        default:
            break;
    }

    return ret;
}

/*
 * Generate an initial schedule where each VCPU for dom0 is sequentially
 * assigned a dedicated processor in the system. Note that this assumes
 * that there are fewer VCPUs assigned to dom0 than there are CPUs.
 */
static struct ttxen_global_head *
ttxen_init_table_generate_fixed(struct domain *dom0)
{
    unsigned long i;
    struct ttxen_global_head *head;
    struct ttxen_percpu_head *phead;
    struct ttxen_vcpu_info *vinfo;
    int cpu = smp_processor_id();
    struct ttxen_private *priv = TTXEN_PRIV(per_cpu(scheduler, cpu));
    struct ttxen_slice *slices;
    struct ttxen_slot *slots;

    head = make_table(dom0->max_vcpus, priv->num_pcpus, 3);
    BUG_ON(!head);

    vinfo = ttxen_get_vcpu_info(head);
    for (i = 0; i < dom0->max_vcpus; i++)
        make_vinfo_entry(vinfo, i,
            0,      /* domain id */
            i,      /* vcpu id */
            1 << i, /* cpumask */
            0);     /* flags (migrating=false) */

    for (i = 0; i < priv->num_pcpus; i++) {
        phead = ttxen_percpu_head(head, i);
        /* Every CPU has a single slot (either idle or normal VCPU) */
        make_percpu_head(phead, 1, 1, CONFIG_INITTABLE_LEN, CONFIG_INITTABLE_LEN);

        slots = ttxen_get_slots(phead);
        make_slot(slots,
            0,              /* index to modify */
            0,              /* offset */
            i,              /* index in vcpu_info list (weave will use this) */
                            /* setting this > len(vinfo) is == idle vcpu */
            CONFIG_INITTABLE_LEN);    /* length */

        slices = ttxen_get_slices(phead);
        make_slice(slices,  /* slice list */
            0,              /* index to modify */
            0,              /* start time */
            CONFIG_INITTABLE_LEN,     /* end time */
            0);             /* slot index (weave will fix this up) */
    }
    return head;
}

/*
 * Generate an initial schedule where each VCPU migrates across cores in
 * the system. For n VCPUs, there are n slots created on each CPU with
 * VCPUs migrating sequentially across processors. Note again that this
 * assumes that there are fewer VCPUs assigned to dom0 than there are CPUs.
 * This is useful for stress-testing the scheduler and ensuring no crashes
 * occur.
 */
struct ttxen_global_head *
ttxen_init_table_generate_migrate(struct domain *dom0)
{
    unsigned long i;
    unsigned long j;
    struct ttxen_global_head *head;
    struct ttxen_percpu_head *phead;
    struct ttxen_vcpu_info *vinfo;
    int cpu = smp_processor_id();
    struct ttxen_private *priv = TTXEN_PRIV(per_cpu(scheduler, cpu));
    struct ttxen_slot *slots;
    struct ttxen_slice *slices;

    head = make_table(dom0->max_vcpus, priv->num_pcpus, 3);
    BUG_ON(!head);

    vinfo = ttxen_get_vcpu_info(head);
    for (i = 0; i < dom0->max_vcpus; i++)
        make_vinfo_entry(vinfo, i,
            0,      /* domain id */
            i,      /* vcpu id */
            1 << i, /* cpumask */
            1);     /* flags (migrating=true) */

    for (i = 0; i < priv->num_pcpus; i++) {
        phead = ttxen_percpu_head(head, i);
        /* Just 1 idle slot if > max_vcpus */
        if (i >= dom0->max_vcpus) {
            make_percpu_head(phead,
                1,  /* Just 1 slot */
                1,  /* And 1 slice */
                MILLISECS(500) * dom0->max_vcpus,   /* slice_len == table_len */
                MILLISECS(500) * dom0->max_vcpus);  /* This is our table len */
        /* Otherwise, as many slots/slices as VCPUs */
        } else {
            make_percpu_head(phead,
                dom0->max_vcpus,    /* n slots */
                dom0->max_vcpus,    /* n slices */
                MILLISECS(500),     /* slice length */
                MILLISECS(500) * dom0->max_vcpus);  /* total table length */
        }

        slots = ttxen_get_slots(phead);
        /* If we're past max number of vcpus, just 1 idle slot */
        if (i >= dom0->max_vcpus) {
            make_slot(slots,
                0,              /* index to modify */
                0,              /* offset */
                i,              /* index in vcpu_info list (weave will use this) */
                                /* setting this > len(vinfo) is == idle vcpu */
                MILLISECS(500) * dom0->max_vcpus);    /* length */
        /* Otherwise, we should linearly schedule all VCPUs */
        } else {
            for (j = 0; j < dom0->max_vcpus; j++)
                make_slot(slots,
                    j,          /* index to modify */
                    MILLISECS(500) * j, /* offset */
                    (i + j) % dom0->max_vcpus,
                    MILLISECS(500));
        }

        slices = ttxen_get_slices(phead);
        /* If we're past max number of vcpus, just 1 slice with idle VCPU */
        if (i >= dom0->max_vcpus) {
            make_slice(slices,  /* slice list */
                0,              /* index to modify */
                0,              /* start time */
                MILLISECS(500) * dom0->max_vcpus,     /* end time */
                0);             /* slot index (weave will fix this up) */
        /* Otherwise, we should linearly schedule all VCPUs */
        } else {
            for (j = 0; j < dom0->max_vcpus; j++)
                make_slice(slices,  /* slice list */
                    j,              /* index to modify */
                    MILLISECS(500) * j, /* start time */
                    MILLISECS(500) * (j + 1),   /* end time */
                    j);             /* slot index (weave will fix this up) */
        }
    }

    return head;
}

static void ttxen_dump_global_head(struct ttxen_global_head *head)
{
    unsigned long i;

    printk("global header (@%p):\n", head);
    printk("  num_vcpus=%llu\n", (unsigned long long)head->num_vcpus); 
    printk("  vcpu_list_offset=%llu\n", (unsigned long long)head->vcpu_list_off);
    printk("  num_cpus=%llu\n", (unsigned long long)head->num_cpus);
    for (i = 0; i < head->num_cpus; i++)
        printk("  cpu%lu_offset=%llu\n", i, (unsigned long long)head->percpu_off[i]);

}

static void ttxen_dump_vinfo(struct ttxen_global_head *head)
{
    unsigned long i;
    struct ttxen_vcpu_info *vinfo;

    vinfo = ttxen_get_vcpu_info(head);
    printk("vcpu info (@%p):\n", vinfo);
    for (i = 0; i < head->num_vcpus; i++) {
        printk("  vcpu_%lu\n", i);
        printk("    dom_id=%lu\n", (unsigned long)vinfo[i].dom_id);
        printk("    vcpu_id=%lu\n", (unsigned long)vinfo[i].vcpu_id);
        printk("    cpumask=%llu\n", (unsigned long long)vinfo[i].cpumask);
        printk("    flags=%llu\n", (unsigned long long)vinfo[i].flags);
        printk("    vcpu_ptr=%p\n", vinfo[i].vcpu);
    }
}

static void ttxen_dump_percpu_head(struct ttxen_global_head *head, int cpu)
{
    struct ttxen_percpu_head *phead;

    phead = ttxen_percpu_head(head, cpu);
    printk("  cpu_%d (@%p):\n", cpu, phead);
    printk("    nslots=%llu\n", (unsigned long long)phead->nslots);
    printk("    nslices=%llu\n", (unsigned long long)phead->nslices);
    printk("    slot_list_off=%llu\n", (unsigned long long)phead->slot_list_off);
    printk("    slice_list_off=%llu\n", (unsigned long long)phead->slice_list_off);
    printk("    slice_length=%llu\n", (unsigned long long)phead->slice_length);    /* in nsec */
    printk("    table_length=%llu\n", (unsigned long long)phead->table_length);    /* in nsec */
    printk("    nvcpus=%llu\n", (unsigned long long)phead->nvcpus);    /* in nsec */
    printk("    vcpu_list_off=%llu\n", (unsigned long long)phead->vcpu_list_off);    /* in nsec */
}

static void ttxen_dump_slot(struct ttxen_slot *slot, int j)
{
    printk("    slot_%d (@%p):\n", j, slot);
    printk("      offset=%llu\n", (unsigned long long)slot->offset);
    printk("      vcpu=%p\n", slot->vcpu);
    printk("      length=%llu\n", (unsigned long long)slot->length);        /* in nsec */
    printk("      start=%llu\n", (unsigned long long)slot->start);
    printk("      end=%llu\n", (unsigned long long)slot->end);
}

static void ttxen_dump_slots(struct ttxen_global_head *head, int cpu)
{
    unsigned long j;
    struct ttxen_slot *slots;
    struct ttxen_percpu_head *phead;

    phead = ttxen_percpu_head(head, cpu);
    slots = ttxen_get_slots(phead);
    printk("  cpu_%d (@%p):\n", cpu, slots);
    for (j = 0; j < phead->nslots; j++)
        ttxen_dump_slot(&slots[j], j);
}

static void ttxen_dump_slice(struct ttxen_slice *slice, int j)
{
    printk("    slice_%d (@%p):\n", j, slice);
    printk("      start=%llu\n", (unsigned long long)slice->start);
    printk("      end=%llu\n", (unsigned long long)slice->end);
    printk("      left=%p\n", slice->left);
    printk("      middle=%p\n", slice->idle_middle);
    printk("      right=%p\n", slice->right);
    printk("      boundary=%llu\n", (unsigned long long)slice->boundary);
}

static void ttxen_dump_slices(struct ttxen_global_head *head, int cpu)
{
    unsigned long j;
    struct ttxen_slice *slices;
    struct ttxen_percpu_head *phead;

    phead = ttxen_percpu_head(head, cpu);
    slices = ttxen_get_slices(phead);
    printk("  cpu_%d (@%p):\n", cpu, slices);
    for (j = 0; j < phead->nslices; j++)
        ttxen_dump_slice(&slices[j], j);
}

/* Dump a table to serial console */
void ttxen_table_dump(struct ttxen_global_head *head)
{
    unsigned long i;

    ttxen_dump_global_head(head);
    ttxen_dump_vinfo(head);

    printk("percpu info:\n");
    for (i = 0; i < head->num_cpus; i++)
        ttxen_dump_percpu_head(head, i);

    printk("slot info:\n");
    for (i = 0; i < head->num_cpus; i++)
        ttxen_dump_slots(head, i);

    printk("slice info:\n");
    for (i = 0; i < head->num_cpus; i++)
        ttxen_dump_slices(head, i);

    return;
}

/*
 * Setup an initial table on boot. Basically it assumes dom0 has fewer VCPUs
 * than physical cores and assigns them one by one to dedicated cores.
 */
static void set_initial_table(struct domain *dom0)
{
    unsigned long i;
    struct ttxen_global_head *init_table;
    int cpu = smp_processor_id();
    struct ttxen_private *prv = TTXEN_PRIV(per_cpu(scheduler, cpu));
    s_time_t now = NOW();
    struct ttxen_vcpu *tmp;

    /* The boot table assumes fewer vCPUs than physical CPUs */
    BUG_ON(dom0->max_vcpus > prv->num_pcpus);

    init_table = ttxen_init_table_generate_fixed(dom0);
    BUG_ON(!init_table);
    ttxen_table_weave(prv, init_table);
    ttxen_table_dump(init_table);

    for (i = 0; i < prv->num_pcpus; i++) {
        TTXEN_PERCPU(i)->curr_table = ttxen_percpu_head(init_table, i);
        TTXEN_PERCPU(i)->curr_table_global = init_table;
        TTXEN_PERCPU(i)->next_table = NULL;
        TTXEN_PERCPU(i)->next_table_global = NULL;
        TTXEN_PERCPU(i)->table_start = now + SECONDS(1);
    }

    /*
     * We need to do some additional work now: we need to setup VCPU 
     * ownership correctly here since the normal route to getting ownership
     * (i.e. by someone pushing it to us) doesn't apply the first time.
     * We also state that the VCPU has a current slot so that a wakeup will
     * actually result in an IPI being sent to the owner.
     */
    i = 0;
    list_for_each_entry(tmp, &TTXEN_DOM(dom0)->vcpu_list, dom_elem) {
        tmp->vcpu->processor = i;
        tmp->slot_on_cpu = i;
        i++;
        printk("tableau: set slot for VCPU [%d.%d] to CPU%d\n",
            tmp->vcpu->domain->domain_id,
            tmp->vcpu->vcpu_id,
            tmp->slot_on_cpu);
    }
}

/*
 * The check_and_switch_table() function checks for a new table that may
 * have been inserted. If it finds one, it switches to it.
 */
static int check_and_switch_table(void)
{
    int ret = 0;
    unsigned long long table_end;
    int cpu = smp_processor_id();
    struct ttxen_percpu *pt = TTXEN_PERCPU(cpu);

    /* If a new table was set, pick it! */
    if (pt->next_table) {
        ret = 1;

        pt->curr_table = pt->next_table;
        pt->curr_table_global = pt->next_table_global;

        pt->next_table = NULL;
        pt->next_table_global = NULL;

        table_end = (unsigned long long)(pt->table_start + pt->curr_table->table_length);

        printk("CPU%d: switching to new table, table_start:%llu, now:%llu, table_end:%llu (length=%llu)\n",
            cpu, (unsigned long long)pt->table_start,
            (unsigned long long)NOW(), table_end,
            (unsigned long long)pt->curr_table->table_length);
    }

    return ret;
}

/*
 * Handles the logic for wrapping around a table and checking for switches.
 * NOTE: This also forwards the start time appropriately. This should thus
 * only be called when a wraparound occurs.
 */
static int do_wrap(s_time_t now)
{
    int cpu = smp_processor_id();
    struct ttxen_percpu *pt = TTXEN_PERCPU(cpu);
    struct ttxen_private *prv = TTXEN_PRIV(per_cpu(scheduler, cpu));
    unsigned long counter = prv->stats[cpu].cslot;

    trace();

    /* These will change regardless of whether a switch occurred or not. */
    do {
        pt->table_start += pt->curr_table->table_length;
    } while (now >= pt->table_start + (s_time_t)pt->curr_table->table_length);

    /* Set the end time of current slot and increment stats counter */
    prv->stats[cpu].slots[counter].end = now;
    prv->stats[cpu].cslot = (counter + 1) % CONFIG_MAX_STATS;
    prv->stats[cpu].slots[prv->stats[cpu].cslot].start = now;
    prv->stats[cpu].slots[prv->stats[cpu].cslot].end = 0;
    prv->stats[cpu].slots[prv->stats[cpu].cslot].total_idle_time = 0;

    return check_and_switch_table();
}

/* Physical CPU related callbacks */

/*
 * This is where we allocate and initialize any per-CPU data that we want
 * @ops: the ttxen operations structure
 * @cpu: the physical CPU number that is being 'alloced'
 *
 * @return: Xen requires that this be non-NULL
 */
static void *ttxen_alloc_pdata(const struct scheduler *ops, int cpu)
{
    unsigned long flags;
    struct ttxen_pcpu *spc;
    struct ttxen_private *prv = TTXEN_PRIV(ops);

    trace();

    /* Allocate per-PCPU info */
    spc = xzalloc(struct ttxen_pcpu);
    if (!spc) {
        printk("tableau: error: failed to allocated PCPU: %d\n", cpu);
        return NULL;
    }

    INIT_LIST_HEAD(&spc->t2_runq);
    spin_lock_init(&spc->t2_lock);

    /* We store this structure in a per-cpu variable called sched_priv */
    if (per_cpu(schedule_data, cpu).sched_priv == NULL)
        per_cpu(schedule_data, cpu).sched_priv = spc;

    /* Update system-wide state */
    spin_lock_irqsave(&prv->lock, flags);

    prv->num_pcpus++;
    cpumask_set_cpu(cpu, prv->pcpu_mask);
    BUG_ON(!is_idle_vcpu(curr_on_cpu(cpu))); /* We should start as idle */

    spin_unlock_irqrestore(&prv->lock, flags);

    printk("tableau: allocated PCPU: %d\n", cpu);

    return spc;
}

static void ttxen_free_pdata(const struct scheduler *ops, void *pcpu, int cpu)
{
    unsigned long flags;
    struct ttxen_pcpu *spc = pcpu;
    struct ttxen_private *prv = TTXEN_PRIV(ops);

    trace();

    if (!spc) {
        printk("tableau: error: NULL PCPU provided: %d\n", cpu);
        return;
    }

    /* Update system-wide state */
    spin_lock_irqsave(&prv->lock, flags);
    prv->num_pcpus--;
    cpumask_clear_cpu(cpu, prv->pcpu_mask);
    spin_unlock_irqrestore(&prv->lock, flags);

    xfree(spc);

    printk("tableau: destroyed PCPU: %d\n", cpu);

}

/* Virtual CPU allocation and initialization routines */

/*
 * This is where we allocate and initialize any per-VCPU data that we want
 * @ops: the ttxen operations structure
 * @vc: the undelying Xen VCPU structure
 * @dd: our ttxen_domain structure that this VCPU belongs to
 *
 * @return: Xen requires that this be non-NULL
 */
static void *ttxen_alloc_vdata(const struct scheduler *ops, struct vcpu *vc, void *dd)
{
    struct ttxen_vcpu *svc;

    trace();

    /* Allocate per-VCPU structure */
    svc = xzalloc(struct ttxen_vcpu);
    if (!svc) {
        printk("tableau: error: failed to allocate data for VCPU: [%d.%d]\n",
            svc->vcpu->domain->domain_id,
            svc->vcpu->vcpu_id);
        return NULL;
    }

    svc->sdom = dd;
    svc->vcpu = vc;
    svc->needs_wakeup = CPU_NONE;
    svc->running_on_cpu = CPU_NONE;
    svc->slot_on_cpu = CPU_NONE;
    spin_lock_init(&svc->lock);

    /* Note: the domain is still NULL at this point. can't add info here */

    printk("tableau: allocated VCPU: [%d.%d]\n", svc->vcpu->domain->domain_id,
        svc->vcpu->vcpu_id);

    return svc;
}

static void ttxen_free_vdata(const struct scheduler *ops, void *priv)
{
    struct ttxen_vcpu *svc = priv;

    trace();

    if (!svc) {
        printk("tableau: error: NULL VCPU provided\n");
        return;
    }

    /* Remove from the list of VCPU's in domain and free */
    if (!is_idle_vcpu(svc->vcpu)) {
        list_del_init(&svc->dom_elem);
    }

    if (svc->t2_cpu) {
        struct ttxen_pcpu *spc = TTXEN_PCPU(svc->t2_cpu);
        spin_lock(&spc->t2_lock);
        list_del_init(&svc->t2_elem);
        spin_unlock(&spc->t2_lock);
    }

    printk("tableau: destroyed VCPU: [%d.%d]\n", svc->vcpu->domain->domain_id,
        svc->vcpu->vcpu_id);

    xfree(svc);
}

/*
 * Normally, here we should return a valid CPU (by checking affinity) on
 * which the VCPU can run. However, since we are entirely table-driven,
 * just return the linked CPU at any given time.
 */
static int ttxen_cpu_pick(const struct scheduler *ops, struct vcpu *vc)
{
    int slot;

    trace();
    /*
     * If cpu_pick is called on a VCPU just return core 0 or Xen's migrate
     * function politely complains by crashing the entire hypervisor
     */
    slot = TTXEN_VCPU(vc)->slot_on_cpu;

    return slot == CPU_NONE ? 0 : slot;
}

/*
 * We use a new TABLEAU_SOFTIRQ signal for doing this. The basic idea is
 * to have a rendevous point in memory where each VCPU spins.
 * Everytime core 0 writes its TSC value, the other core immediately
 * provides its own TSC value. In the end, the average phase difference
 * is stored and used to synchronize .
 */
static void __attribute__((unused)) ttxen_rendevous_tsc(struct ttxen_private *prv)
{
    unsigned long i;
    cpumask_t mask;

    trace();

    memset(&prv->rendevous, 0, sizeof(struct rendevous) * NR_CPUS);

    /* Raise the TABLEAU_SOFTIRQ on all cores */
    cpumask_setall(&mask);
    cpumask_clear_cpu(0, &mask);
    printk("Raising TABLEAU_SOFTIRQ on all cores\n");
    cpumask_raise_softirq(&mask, TABLEAU_SOFTIRQ);

    /* Rendevous with each core one by one and calculate the mean offset */
    for (i = 1; i < prv->num_pcpus; i++) {
        struct rendevous *r = &prv->rendevous[i];
        int64_t avg = 0;
        for (int j = 0; j < CONFIG_RENDEVOUS_LOOPS; j++) {
            r->rendevous = NOW();
            while(!r->response);
            avg += ((int64_t)r->response - (int64_t)r->rendevous);
            /* Discard first samples (possibly L3 cache miss overheads) */
            if (j == CONFIG_RENDEVOUS_DISCARD_SAMPLES)
                avg = 0;
            r->response = 0;
        }
        avg /= CONFIG_RENDEVOUS_LOOPS;
        /* Store in ttxen_private for use by scheduler functions */
        prv->tsc_off[i] = avg;
    }

    /* Dump info on the console */
    printk("TSC rendevous complete (used %d loops)\n",
            CONFIG_RENDEVOUS_LOOPS);
    for (i = 1; i < prv->num_pcpus; i++)
        printk("CPU%lu has offset: %lld\n", i, (long long)prv->tsc_off[i]);
}

/*
 * The 'insert_vcpu' callback is called immediately after alloc_vdata.
 * At this point, we should add the VCPU into a runqueue somewhere. We
 * don't use a runqueue so don't bother. Note that in schedule.c, our
 * alloced vdata structure is automatically set to vc->sched_priv and we
 * can retrieve it from there. The macro TTXEN_VCPU does exactly this.
 *
 * @ops: the ttxen scheduler ops structure
 * @vc: the VCPU that we need to insert
 */
static void ttxen_vcpu_insert(const struct scheduler *ops, struct vcpu *vc)
{
    cpumask_t mask;
    struct ttxen_vcpu *svc = TTXEN_VCPU(vc);
    struct ttxen_vcpu *vcurr;
    struct ttxen_dom *sdom = TTXEN_DOM(svc->vcpu->domain);
    //struct ttxen_private *prv = TTXEN_PRIV(ops);
    struct ttxen_pcpu *spc;
    unsigned long flags;

    trace();

    if (!is_idle_domain(svc->vcpu->domain))
        list_add_tail(&svc->dom_elem, &sdom->vcpu_list);

    if (svc->vcpu->domain->domain_id == 0) {
        svc->type = VCPU_TYPE_TIER1;
        svc->t2_cpu = -1;
    } else if (!is_idle_vcpu(svc->vcpu)) {
        /* Idle VCPU's don't count */
        svc->type = VCPU_TYPE_TIER2;

        /* Any other VCPU should go onto the Tier-2 runqueue when inserted */

        /*
         * Insert into the list of whatever CPU vcpu_insert was called on.
         * TODO: Perhaps a better approach would be to randomly pick a CPU to
         * push this onto so the distribution is more even.
         */
        svc->t2_cpu = smp_processor_id();
        spc = TTXEN_PCPU(smp_processor_id());

        /* Make sure to grab the lock to avoid list corruption */
        spin_lock_irqsave(&spc->t2_lock, flags);
        list_add_tail(&svc->t2_elem, &spc->t2_runq);
        spin_unlock_irqrestore(&spc->t2_lock, flags);
    }

    /* We treat idle vCPUs as tier-2 vcpus under Tableau */
    if (is_idle_vcpu(svc->vcpu)) {
        svc->type = VCPU_TYPE_TIER2;
        svc->t2_cpu = svc->vcpu->vcpu_id;
    }

    /*
     * If we just inserted the last VCPU for dom0, generate initial schedule.
     * Note that this has to be after all VCPUs have been inserted so that the
     * table-generation is correct (it looks at the VCPU list for dom0 to
     * generate the initial schedule).
     *
     * One caveat: since Xen tends to wakeup inserted VCPUs regardless of
     * whether all the VCPUs associated with a particular domain have been
     * created, putting this here means we might have the case where we get a
     * schedule() call with no table set. This needs to be (and is) handled
     * correctly.
     */
    if (svc->vcpu->domain->domain_id == 0 &&
        (unsigned long)svc->vcpu->vcpu_id == svc->vcpu->domain->max_vcpus - 1) {
        struct domain *dom0 = svc->vcpu->domain;
        /*
         * Generate our initial table for dom0. This simply generates a table
         * where the first VCPU of dom0 is scheduled on core 0 (table length
         * is 100ms). No locks acquired here as no other VCPU exists yet.
         */
        set_initial_table(dom0);

        /* Now that the table is present, wake all VCPUs */
        cpumask_setall(&mask);
        cpumask_raise_softirq(&mask, SCHEDULE_SOFTIRQ);

        /*
         * This is a good time to calculate all offsets in the TSC for all =
         * cores in the system as we can be sure that all pCPUs exist.
         */
        //ttxen_rendevous_tsc(prv);
    }

    if (svc->type == VCPU_TYPE_TIER2) {
        printk("tableau: inserted tier-2 vcpu [%d.%d] on core %d\n",
            svc->vcpu->domain->domain_id, svc->vcpu->vcpu_id, svc->t2_cpu);
    } else {
        printk("tableau: inserted tier-1 vcpu [%d.%d]\n",
            svc->vcpu->domain->domain_id, svc->vcpu->vcpu_id);
    }

    if (svc->type == VCPU_TYPE_TIER2) {
        vcurr = TTXEN_VCPU(curr_on_cpu(svc->t2_cpu));
        printk("tableau: added tier-2 vcpu to core %d (current=[%d:%d])\n",
            (int)svc->t2_cpu,
            vcurr->vcpu->domain->domain_id,
            vcurr->vcpu->vcpu_id);

        //if (vcurr->type != VCPU_TYPE_TIER1) {
            printk("tableau: raising softirq on core %d\n", svc->t2_cpu);
            cpu_raise_softirq(svc->t2_cpu, SCHEDULE_SOFTIRQ);
        //}
    }
}

/*
 * This function is called just before free_vdata. Do all the cleanup stuff
 * here but don't do the deallocation of data structures here.
 */
static void ttxen_vcpu_remove(const struct scheduler *ops, struct vcpu *vc)
{
    struct ttxen_vcpu * const svc = TTXEN_VCPU(vc);
    struct ttxen_dom * const sdom = svc->sdom;

    trace();

    BUG_ON(sdom == NULL);

    printk("tableau: processed removal request for VCPU: [%d.%d]\n",
        svc->vcpu->domain->domain_id,
        svc->vcpu->vcpu_id);
}

/*
 * This function should allocate the per-domain data
 * @ops: the scheduling ops
 * @dom: the underlying Xen domain structure
 *
 * @return: should be non-NULL
 */
static void *ttxen_alloc_domdata(const struct scheduler *ops, struct domain *dom)
{
    struct ttxen_dom *sdom;

    trace();

    sdom = xzalloc(struct ttxen_dom);
    if (!sdom) {
        printk("tableau: error: failed to allocate domdata for domain %d\n", dom->domain_id);
        return NULL;
    }

    INIT_LIST_HEAD(&sdom->vcpu_list);
    sdom->dom = dom;

    INIT_LIST_HEAD(&sdom->elem);

    printk("tableau: allocated domdata for domain %d\n", dom->domain_id);

    return (void *)sdom;
}

static void ttxen_free_domdata(const struct scheduler *ops, void *data)
{
    struct ttxen_dom *sdom = data;

    trace();

    BUG_ON(!list_empty(&sdom->vcpu_list));
    printk("tableau: freed domdata for domain %d\n", sdom->dom->domain_id);
    xfree(data);
}

static int ttxen_dom_init(const struct scheduler *ops, struct domain *dom)
{
    unsigned long flags;
    struct ttxen_dom *sdom;
    struct ttxen_private *prv = TTXEN_PRIV(ops);

    trace();

    /* Apparently this can happen according to sched_credit.c */
    if (is_idle_domain(dom)) {
        printk("tableau: dom_init() called on idle domain (ignoring)\n");
        return 0;
    }

    /* Allocate our domain */
    sdom = ttxen_alloc_domdata(ops, dom);
    if (!sdom) {
        printk("tableau: failed to allocate domain: %d\n", dom->domain_id);
        return -ENOMEM;
    }

    /* set the sched_priv info so we can access our struct later */
    dom->sched_priv = sdom;

    /* We track all domains in the system in priv->domains */
    spin_lock_irqsave(&prv->lock, flags);
    list_add_tail(&sdom->elem, &prv->domains);
    spin_unlock_irqrestore(&prv->lock, flags);

    printk("tableau: added new domain: %d\n", dom->domain_id);

    return 0;
}

static void ttxen_dom_destroy(const struct scheduler *ops, struct domain *dom)
{
    unsigned long flags;
    struct ttxen_dom *sdom = TTXEN_DOM(dom);
    struct ttxen_private *prv = TTXEN_PRIV(ops);

    trace();

    /* Clear up the global state and free */
    if (!list_empty(&sdom->elem)) {
        printk("tableau: removed domain %d from global domain list\n", dom->domain_id);
        spin_lock_irqsave(&prv->lock, flags);
        list_del(&sdom->elem);
        spin_unlock_irqrestore(&prv->lock, flags);
    }

    printk("tableau: removed domain: %d\n", dom->domain_id);
    ttxen_free_domdata(ops, sdom);
}

/* Scheduler-related functions */

/*
 * Called whenever a VCPU is woken up. Note that this function may be
 * called multiple times so all checks to ensure correct behaviour in
 * these situations should be made.
 */
static void ttxen_vcpu_wake(const struct scheduler *ops, struct vcpu *vc)
{
    int wake_cpu;
    unsigned long flags;
    struct ttxen_vcpu *v = TTXEN_VCPU(vc);
    struct ttxen_vcpu *vcurr;

    trace();

    if (v->type == VCPU_TYPE_TIER1) {
        spin_lock_irqsave(&v->lock, flags);
        wake_cpu = v->slot_on_cpu;
        spin_unlock_irqrestore(&v->lock, flags);
    } else {
        if (v->t2_cpu < 0)
            wake_cpu = CPU_NONE;
        else {
            wake_cpu = CPU_NONE;
            vcurr = TTXEN_VCPU(curr_on_cpu(v->t2_cpu));
            if (vcurr->type != VCPU_TYPE_TIER1)
                wake_cpu = v->t2_cpu;
        }
        //wake_cpu = vc->processor;
    }

    /* Send IPI after spin_unlock() barrier */
    if (wake_cpu != CPU_NONE)
        cpu_raise_softirq(wake_cpu, SCHEDULE_SOFTIRQ);
}

static struct ttxen_slot *get_current_slot(s_time_t now)
{
    int cpu = smp_processor_id();
    struct ttxen_percpu *pt = TTXEN_PERCPU(cpu);
    struct ttxen_slot *slot;
    int switch_occurred = 0;

    trace();

    /* If current table is not scheduled yet */
    if (pt->table_start > now || !pt->curr_table)
        return NULL;

    /* Check for switches and wraparound */
    if (now >= pt->table_start + (s_time_t)pt->curr_table->table_length)
        switch_occurred = do_wrap(now);

    BUG_ON(now >= pt->table_start + (s_time_t)pt->curr_table->table_length);
    BUG_ON(now < pt->table_start);
    /* We should never have no slots in a table (at least 1 idle slot) */
    BUG_ON(pt->curr_table->nslots == 0);

    /* Figure out the slot based on current time (should not be NULL) */
    slot = ttxen_get_slot(pt, now);
    BUG_ON(!slot);

    return slot;
}

static int replenish_compare(void *priv, struct list_head *pa, struct list_head *pb)
{
    struct ttxen_vcpu *a = list_entry(pa, struct ttxen_vcpu, t2_elem);
    struct ttxen_vcpu *b = list_entry(pb, struct ttxen_vcpu, t2_elem);

    if (a->last_replenish < b->last_replenish)
        return -1;
    else if (b->last_replenish < a->last_replenish)
        return 1;
    else
        return 0;
}

void ttxen_tier2_preschedule(s_time_t now, struct ttxen_vcpu *prev)
{
    int cpu = smp_processor_id();
    struct ttxen_private *prv = TTXEN_PRIV(per_cpu(scheduler, cpu));
    struct ttxen_percpu *pt = TTXEN_PERCPU(cpu);
    struct ttxen_pcpu *spc = TTXEN_PCPU(cpu);
    unsigned long flags;

    /* A tier-2 CPU just finished, add time to current stats slot */
    prv->stats[cpu].slots[prv->stats[cpu].cslot].total_idle_time +=
        now - pt->last_t2_start;

    /* If we just finished with an idle vcpu, just return at this point */
    if (is_idle_vcpu(prev->vcpu))
        return;

    /* All tier-2 state changes are protected by the owning CPU's spinlock */
    spin_lock_irqsave(&spc->t2_lock, flags);
    /* Update budget based on runtime of VM */
    prev->budget -= (long long)(now - pt->last_t2_start);
    /* Replenish budget if needed */
    if (prev->budget <= 0) {
        prev->budget = CONFIG_TIER2_TIMESLICE;
        prev->last_replenish = now;
    }
    /* Re-sort list based on replenish time (oldest first) */
    list_sort(NULL, &spc->t2_runq, replenish_compare);
    spin_unlock_irqrestore(&spc->t2_lock, flags);
}

void ttxen_tier2_schedule(s_time_t now, struct task_slice *ret)
{
    int cpu = smp_processor_id();
    struct ttxen_percpu *pt = TTXEN_PERCPU(cpu);
    struct ttxen_pcpu *spc = TTXEN_PCPU(cpu);
    //unsigned long flags;
    struct ttxen_vcpu *v;

    //spin_lock_irqsave(&spc->t2_lock, flags);
    spin_lock(&spc->t2_lock);
    /* Pick first from queue or until runnable */
    list_for_each_entry(v, &spc->t2_runq, t2_elem) {
        if (vcpu_runnable(v->vcpu)) {
            ret->task = v->vcpu;
            break;
        }
    }

    /* Schedule for budget time (invariant: budget <= timeslice) */
    if (!is_idle_vcpu(ret->task)) {
        //printk("T2 --> ");
        /* If v->budget is past the next wake, don't change */
        if (v->budget < ret->time)
            ret->time = v->budget;
        if (ret->task->processor != cpu) {
            ret->task->processor = cpu;
            ret->migrated = 1;
        }
    }

    //spin_unlock_irqrestore(&spc->t2_lock, flags);
    spin_unlock(&spc->t2_lock);

    /* Whether we pick a background VM or idle, it counts as tier-2 time */
    pt->last_t2_start = now;
}

void ttxen_level2_preschedule(s_time_t now, struct ttxen_vcpu *prev)
{
    int cpu = smp_processor_id();
    struct ttxen_private *prv = TTXEN_PRIV(per_cpu(scheduler, cpu));
    struct ttxen_percpu *pt = TTXEN_PERCPU(cpu);

    /* A level-2 CPU just finished, add time to current stats slot */
    prv->stats[cpu].slots[prv->stats[cpu].cslot].total_idle_time +=
        now - pt->last_l2_start;

    /* If we just finished with an idle vcpu, just return at this point */
    if (is_idle_vcpu(prev->vcpu))
        return;

    /* Update budget based on runtime of VM */
    prev->budget -= (long long)(now - pt->last_l2_start);
    prev->scheduled_by_l2 = 0;
}

static void replenish_budgets(s_time_t now)
{
    int i;
    struct ttxen_vcpu *v;
    struct ttxen_vcpu_info *pvinfo;
    int cpu = smp_processor_id();
    struct ttxen_percpu *pt = TTXEN_PERCPU(cpu);
    int replenish = 0;
    int all_runnable_depleted = 1;

    /* If we crossed an epoch, just push all budgets to full */
    if (now - pt->last_l2_epoch > CONFIG_LEVEL2_EPOCH) {
        pt->last_l2_epoch = now;
        replenish = 1;
    }

    /* Replenish if all runnable vCPUs have no budget */
    pvinfo = ttxen_get_percpu_vcpu_info(pt->curr_table);
    for (i = 0; i < pt->curr_table->nvcpus; i++) {
        v = pvinfo[i].vcpu;
        if (!pvinfo[i].flags &&                 // VM is not semi-partitioned
            vcpu_runnable(v->vcpu) && v->budget > 0) {
            all_runnable_depleted = 0;
            break;
        }
    }
    if (all_runnable_depleted)
        replenish = 1;

    if (!replenish)
        return;

    pvinfo = ttxen_get_percpu_vcpu_info(pt->curr_table);
    for (i = 0; i < pt->curr_table->nvcpus; i++) {
        v = pvinfo[i].vcpu;
        /* Don't bother with semi-partitioned vCPUs */
        if (!pvinfo[i].flags)
            v->budget = CONFIG_LEVEL2_EPOCH / pt->curr_table->nvcpus;
    }
}

void ttxen_level2_schedule(s_time_t now, struct task_slice *ret)
{
    int i;
    int cpu = smp_processor_id();
    struct ttxen_percpu *pt = TTXEN_PERCPU(cpu);
    struct ttxen_vcpu_info *pvinfo;
    struct ttxen_vcpu *v;
    struct ttxen_vcpu *picked = NULL;
    long long highest_budget = -1;

    if (!pt->curr_table)
        return;

    /* Replenish budgets if necessary */
    replenish_budgets(now);

    /* Pick from percore VCPU list (highest-budget first) or until runnable */
    pvinfo = ttxen_get_percpu_vcpu_info(pt->curr_table);
    for (i = 0; i < pt->curr_table->nvcpus; i++) {
        v = pvinfo[i].vcpu;
        /* First condition ensures we're not picking a semi-paritioned vCPU */
        if (!pvinfo[i].flags &&                 // VM is not semi-partitioned
            v->budget > 0 &&                    // VM has budget remaining
            v->vcpu != pt->slot->vcpu->vcpu &&  // VM is not on current slot
            vcpu_runnable(v->vcpu)) {           // VM is runnable
            if (v->budget >= highest_budget) {
                highest_budget = v->budget;
                picked = v;
            }
            // Don't break here. We want to go through all vCPUs.
        }
    }

    if (picked) {
        picked->scheduled_by_l2 = 1;
        ret->task = picked->vcpu;
    }

    /* Decise how long to schedule for */
    if (!is_idle_vcpu(ret->task)) {
        /* If v->budget is past the next wake, don't change */
        ret->time = MIN(ret->time, picked->budget);
        /* If v->budget is more than the level2 timeslice, lower it */
        ret->time = MIN(ret->time, CONFIG_LEVEL2_TIMESLICE);

        if (ret->task->processor != cpu) {
            ret->task->processor = cpu;
            ret->migrated = 1;
        }
    }

    /* Whether we pick a background VM or idle, it counts as level-2 time */
    pt->last_l2_start = now;
}

/* These per-CPU variables are used to match traces in schedule() */
DEFINE_PER_CPU(s_time_t, last_now);

#define SCHED_DECISION_T1_L1 0
#define SCHED_DECISION_T1_L2 1
#define SCHED_DECISION_T2    2

static struct task_slice ttxen_schedule(const struct scheduler *ops,
    s_time_t now, bool_t tasklet)
{
    unsigned long flags;
    struct ttxen_vcpu *next;
    int sched_decision = SCHED_DECISION_T1_L1;
    int cpu = smp_processor_id();
    struct task_slice ret;
    struct ttxen_percpu *pt = TTXEN_PERCPU(cpu);
    struct ttxen_vcpu *prev = TTXEN_VCPU(current);

    trace();

    /* Make sure table allocation was successful */
    BUG_ON(pt->curr_table && pt->curr_table->table_length == 0);

    /* Xen apparently doesn't ensure monotonicity of 'now'. Fix it ourselves */
    if (now < per_cpu(last_now, cpu))
        now = per_cpu(last_now, cpu);
    *(&per_cpu(last_now, cpu)) = now;

    TRACE_5D(TRC_TTXEN_SCHED_START,
            (per_cpu(ttxen_sched_iteration, cpu) & 0xffffffff),
            ((per_cpu(ttxen_sched_iteration, cpu) >> 32) & 0xffffffff),
            prev->vcpu->domain->domain_id,
            prev->vcpu->vcpu_id,
            tasklet);

    /* This is needed to ensure that the default migrated flag is 0 */
    memset(&ret, 0, sizeof(struct task_slice));

    /*
     * If anything needs to be done with prev (eg. add it back to runqueue),
     * this is performed here.
     */
    if (prev->scheduled_by_l2)
        ttxen_level2_preschedule(now, prev);
    else if (prev->type == VCPU_TYPE_TIER2)
        ttxen_tier2_preschedule(now, prev);

    /*
     * If we got here, no tasklet work was scheduled. Call a magic function
     * that retrieves the next VCPU by looking at the current time and the
     * table. The returned 'next' pointer will unequivocally point to the
     * VCPU that we should be scheduling right now, regardless of whether
     * it is runnable.
     */
    pt->slot = get_current_slot(now);
    if (!pt->slot) {
        ret.task = idle_vcpu[cpu];
        /* The only time we have a NULL slot is if table is in future */
        //BUG_ON(!(pt->table_start > now));
        ret.time = pt->table_start - now;
        goto done;
    }

    next = pt->slot->vcpu;

    /*
     * Unset the slot_on_cpu field in vCPU if the slot changed, in order to
     * to avoid unnecessary wakeups.
     */
    if (next != prev)
        prev->slot_on_cpu = CPU_NONE;

    /* Idle slot: just schedule it immediately until end-of-slot. */
    if (is_idle_vcpu(next->vcpu)) {
        ret.task = idle_vcpu[cpu];
        ret.time = pt->table_start + pt->slot->end - now;
        goto done;
    }

    /*
     * If this is being scheduled elsewhere, scheduling it will corrupt the
     * stack and result in a crash. Figure out if its safe and setup an IPI
     * otherwise.
     */
    spin_lock_irqsave(&next->lock, flags);
    if (next->running_on_cpu != CPU_NONE && next->running_on_cpu != cpu) {
        next->needs_wakeup = cpu;
        spin_unlock_irqrestore(&next->lock, flags);
        /*
         * Don't bother invoking the L2 scheduler here. The only time we
         * end up here is if there is clock skew across cores, resulting
         * in one core waiting a short amount of time for an IPI telling
         * it that it's safe to continue.
         */
        ret.task = idle_vcpu[cpu];
        ret.time = pt->table_start + pt->slot->end - now;
        goto done;
    }

    /*
     * Set the slot_on_cpu field to indicate that this VCPU currently has a
     * slot somewhere. This is needed due to the structure of tables we
     * use: a pushing CPU can assign a VCPU to us if it sees that we have a
     * slot _at some point_ in the future (not necessarily immediately).
     * In such a case, wake() should ignore sending an IPI as we'll anyway
     * wake up at some point and notice that the VCPU is runnable. This
     * flag tells wake(): "this VCPU has a slot here _right now_ so
     * please send wakeup IPIs if you receive them."
     */
    next->slot_on_cpu = cpu;

    /*
     * We should check if the VCPU is runnable. If not, we idle since we can
     * be sure to receive a wakeup IPI if the VCPU becomes runnable again (we
     * set the slot_on_cpu field. Note that this must be done after setting
     * the slot_on_cpu field otherwise we won't receive the IPI. Also, we do
     * this with the lock held so that setting slot_on_cpu and running_on_cpu
     * is atomic.
     */
    if (!vcpu_runnable(next->vcpu)) {
        spin_unlock_irqrestore(&next->lock, flags);
        ret.task = idle_vcpu[cpu];
        ret.time = pt->table_start + pt->slot->end - now;
        goto done;
    }

    next->running_on_cpu = cpu;
    spin_unlock_irqrestore(&next->lock, flags);

    /* Finally, everything is fine: schedule the VCPU */
    ret.task = next->vcpu;
    ret.time = pt->table_start + pt->slot->end - now;
    if (!is_idle_vcpu(next->vcpu) && next->vcpu->processor != cpu) {
        next->vcpu->processor = cpu;
        ret.migrated = 1;
    }

done:
    /* If we picked idle, switch to level-2 scheduler */
    if (is_idle_vcpu(ret.task)) {
        sched_decision = SCHED_DECISION_T1_L2;
        ttxen_level2_schedule(now, &ret);
    }

    /* If we still picked idle, switch to tier-2 scheduler */
    if (is_idle_vcpu(ret.task)) {
        sched_decision = SCHED_DECISION_T2;
        ttxen_tier2_schedule(now, &ret);
    }

    TRACE_5D(TRC_TTXEN_SCHED_END,
            (per_cpu(ttxen_sched_iteration, cpu) & 0xffffffff),
            ((per_cpu(ttxen_sched_iteration, cpu) >> 32) & 0xffffffff),
            ret.task->domain->domain_id,
            ret.task->vcpu_id,
            sched_decision);
    *(&per_cpu(ttxen_sched_iteration, cpu)) += 1;
    return ret;
}

/* This function is called after the context-switch */
static void ttxen_context_saved(const struct scheduler *ops, struct vcpu *vc)
{
    unsigned long flags;
    int cpu = smp_processor_id();
    struct ttxen_vcpu *prev = TTXEN_VCPU(vc);
    spinlock_t *lock;
    int needs_wakeup = CPU_NONE;

    /* We don't need to bother about ownership issues with idle-domain VCPUs */
    if (is_idle_vcpu(prev->vcpu))
        return;

    /*
     * Acquire core-lock before anything to prevent issues with concurrent
     * wakeups on other cores.
     */
    lock = pcpu_schedule_lock_irq(cpu);
    /* Release the VCPU from this processor to NONE */
    spin_lock_irqsave(&prev->lock, flags);
    prev->running_on_cpu = CPU_NONE;
    spin_unlock_irqrestore(&prev->lock, flags);

    /* Figure out if another core requested a wakeup on us releasing */
    if (prev->needs_wakeup != CPU_NONE) {
        needs_wakeup = prev->needs_wakeup;
        prev->needs_wakeup = CPU_NONE;
    }
    pcpu_schedule_unlock_irq(lock, cpu);

    /* Send IPI to core after spinlock barrier */
    if (needs_wakeup != CPU_NONE)
        cpu_raise_softirq(needs_wakeup, SCHEDULE_SOFTIRQ);
}

/* The softirq handler for tsc rendevous used for offset calculation */
static void ttxen_softirq_handler(void)
{
    int i;
    int cpu = smp_processor_id();
    struct ttxen_private *priv = TTXEN_PRIV(per_cpu(scheduler, cpu));
    struct rendevous *r = &priv->rendevous[cpu];
    s_time_t val;
    s_time_t expect = 0;

    for (i = 0; i < CONFIG_RENDEVOUS_LOOPS; i++) {
        while ((val = r->rendevous) == expect);
        r->response = NOW();
        expect = val;
    }
}

static int ttxen_init(struct scheduler *ops)
{
    struct ttxen_private *prv;

    trace();

    prv = xzalloc(struct ttxen_private);
    if (!prv)
        goto err_alloc;

    if (!zalloc_cpumask_var(&prv->pcpu_mask))
        goto err_cpus;

    ops->sched_data = prv;
    spin_lock_init(&prv->lock);
    INIT_LIST_HEAD(&prv->domains);
    prv->switch_in_progress = 0;
    memset(prv->stats, 0, sizeof(struct ttxen_stats) * NR_CPUS);

    open_softirq(TABLEAU_SOFTIRQ, ttxen_softirq_handler);

    return 0;

err_cpus:
    xfree(prv);
err_alloc:
    return -ENOMEM;
}

static void ttxen_deinit(struct scheduler *ops)
{
    struct ttxen_private *prv;

    trace();

    prv = TTXEN_PRIV(ops);
    if (!prv)
        return;

    free_cpumask_var(prv->pcpu_mask);
    xfree(prv);
}

static struct ttxen_private _ttxen_priv;

const struct scheduler sched_ttxen_def = {
    .name           = "SMP Table-Driven Scheduler",
    .opt_name       = "tableau",
    .sched_id       = XEN_SCHEDULER_TABLEAU,
    .sched_data     = &_ttxen_priv,

    /* Scheduler initialization and cleanup functions */
    .init           = ttxen_init,
    .deinit         = ttxen_deinit,

    /* Domain initialization and cleanup functions */
    .init_domain    = ttxen_dom_init,
    .destroy_domain = ttxen_dom_destroy,

    /* VCPU insertion and removal functions */
    .insert_vcpu    = ttxen_vcpu_insert,
    .remove_vcpu    = ttxen_vcpu_remove,

    /* Basic scheduler operations */
    .wake           = ttxen_vcpu_wake,
    .do_schedule    = ttxen_schedule,

    /* Allocation and deallocation functions */
    .alloc_vdata    = ttxen_alloc_vdata,
    .free_vdata     = ttxen_free_vdata,
    .alloc_pdata    = ttxen_alloc_pdata,
    .free_pdata     = ttxen_free_pdata,
    .alloc_domdata  = ttxen_alloc_domdata,
    .free_domdata   = ttxen_free_domdata,

    .pick_cpu       = ttxen_cpu_pick,
    .context_saved  = ttxen_context_saved,
};

REGISTER_SCHEDULER(sched_ttxen_def);
