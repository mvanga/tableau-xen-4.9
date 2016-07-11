#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>

#include <xenctrl.h>
#include <xenguest.h>
#include <xc_private.h>

#define TTXEN_OP_MAGIC  0xdeadbeef

struct ttxen_op_vcpu {
    unsigned long magic;
    unsigned long dom_id;
    unsigned long vcpu_id;
    long cpu;
};

struct idle_stats_single {
    uint64_t start;
    uint64_t end;
    uint64_t total_time;
};

#define CONFIG_MAX_STATS    10

struct idle_stats {
    unsigned long cslot;
    struct idle_stats_single slots[CONFIG_MAX_STATS];
};

void usage(void)
{
    printf("usage: ttxentool <cmd> <opts>\n");
    printf("push_table\n");
    printf("get_table_length\n");
    printf("add_vcpu\n");
    printf("remove_vcpu\n");
    printf("toggle_vcpu\n");
    printf("get_table\n");
    printf("get_vcpu_info\n");
    printf("get_num_pcpus\n");
    printf("read_stats\n");
    printf("move_vcpu\n");
}

void usage_push_table(void)
{
    printf("usage: ttxentool push_table <schedgen_generated_folder>\n");
}

void usage_add_vcpu(void)
{
    printf("usage: ttxentool add_vcpu <dom_id> <vcpu_id> <cpu>\n");
}

void usage_move_vcpu(void)
{
    printf("usage: ttxentool move_vcpu <dom_id> <vcpu_id> <cpu>\n");
}

void usage_rem_vcpu(void)
{
    printf("usage: ttxentool remove_vcpu <dom_id> <vcpu_id>\n");
}
void usage_toggle_vcpu(void)
{
    printf("usage: ttxentool toggle_vcpu <dom_id> <vcpu_id>\n");
}

void usage_get_table(void)
{
    printf("usage: ttxentool get_table <length> <filename>\n");
}

void usage_get_vcpu_info(void)
{
    printf("usage: ttxentool get_vcpu_info <dom_id> <vcpu_id>\n");
}

int ttxen_op(unsigned long op, unsigned long len, char *arg)
{
    int ret = 0;
    xc_interface *xch;

    xch = xc_interface_open(0, 0, 0);
    if (!xch) {
        printf("fatal: failed to open control interface");
        return -EFAULT;
    }

    ret = do_tableau_op(xch, op, len, arg);
    if (ret) {
        printf("ttxen_op failed: %d\n", ret);
        return ret;
    }

    xc_interface_close(xch);

    return ret;
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


#define TYPE_TIER2  0
#define TYPE_TIER1  1

int main(int argc, char *argv[])
{
    int i, j;

    if (argc < 2) {
        usage();
        exit(1);
    }

    if (strcmp(argv[1], "push_table") == 0) {
        size_t size;
        FILE *fp;
        char *buffer;
        char path[1024];

        if (argc != 3) {
            usage_push_table();
            exit(1);
        }

        strcpy(path, argv[2]);
        strcat(path, "/raw");
        printf("pushing table: %s\n", path);

        /* Open the passed data file */
        fp = fopen(path, "rb");
        if (fp == NULL) {
            printf("error: failed to open file: %s \n", path);           
            exit(1);
        }

        /* Figure out the size of the passed file */
        fseek(fp, 0, SEEK_END); 
        size = ftell(fp);         /*calc the size needed*/
        fseek(fp, 0, SEEK_SET); 
        printf("file size: %d bytes\n", (int)size);

        /* Allocate our buffer and read the file into it */
        buffer = (char *)malloc(size);
        assert(buffer);
        printf("%p %d %d\n", buffer, (int)sizeof(*buffer), (int)size);
        if (fread(buffer, sizeof(*buffer), size, fp) != size){ 
            printf("error: There was an error reading the file %s \n", path);           
            exit(1);
        }
        fclose(fp);
        assert(ttxen_op(TTXEN_OP_PUSH_TABLE, size, buffer) == 0);
        free(buffer);
    } else if (strcmp(argv[1], "get_table_length") == 0) {
        unsigned long long tlen;
        assert(ttxen_op(TTXEN_OP_READ_TABLE_LENGTH, sizeof(unsigned long long), (char *)&tlen) == 0);
        printf("table_length=%llu\n", tlen);
    } else if (strcmp(argv[1], "add_vcpu") == 0) {
        struct ttxen_op_vcpu top;
        if (argc != 5) {
            usage_add_vcpu();
            exit(1);
        }
        top.magic = TTXEN_OP_MAGIC;
        top.dom_id = atoi(argv[2]);
        top.vcpu_id = atoi(argv[3]);
        top.cpu = atoi(argv[4]);
        assert(ttxen_op(TTXEN_OP_ADD_VCPU, sizeof(struct ttxen_op_vcpu), (char *)&top) == 0);
        printf("adding vcpu [%lu.%lu] to CPU%lu\n", top.dom_id, top.vcpu_id, top.cpu);
    } else if (strcmp(argv[1], "move_vcpu") == 0) {
        struct ttxen_op_vcpu top;
        if (argc != 5) {
            usage_add_vcpu();
            exit(1);
        }
        top.magic = TTXEN_OP_MAGIC;
        top.dom_id = atoi(argv[2]);
        top.vcpu_id = atoi(argv[3]);
        top.cpu = atoi(argv[4]);
        assert(ttxen_op(TTXEN_OP_MOVE_VCPU, sizeof(struct ttxen_op_vcpu), (char *)&top) == 0);
        printf("moving vcpu [%lu.%lu] to CPU%lu\n", top.dom_id, top.vcpu_id, top.cpu);
    } else if (strcmp(argv[1], "remove_vcpu") == 0) {
        struct ttxen_op_vcpu top;
        if (argc != 4) {
            usage_rem_vcpu();
            exit(1);
        }
        top.magic = TTXEN_OP_MAGIC;
        top.dom_id = atoi(argv[2]);
        top.vcpu_id = atoi(argv[3]);
        assert(ttxen_op(TTXEN_OP_REMOVE_VCPU, sizeof(struct ttxen_op_vcpu), (char *)&top) == 0);
        printf("removing vcpu [%lu.%lu] from queues\n", top.dom_id, top.vcpu_id);
    } else if (strcmp(argv[1], "toggle_vcpu") == 0) {
        struct ttxen_op_vcpu top;
        if (argc != 4) {
            usage_toggle_vcpu();
            exit(1);
        }
        top.magic = TTXEN_OP_MAGIC;
        top.dom_id = atoi(argv[2]);
        top.vcpu_id = atoi(argv[3]);
        assert(ttxen_op(TTXEN_OP_TOGGLE_TYPE, sizeof(struct ttxen_op_vcpu), (char *)&top) == 0);
        printf("toggling vcpu [%lu.%lu]\n", top.dom_id, top.vcpu_id);
    } else if (strcmp(argv[1], "get_table") == 0) {
        unsigned long long tlen;
        char *buf;
        FILE *f;

        if (argc != 4) {
            usage_get_table();
            exit(1);
        }
        tlen = strtoull(argv[2], NULL, 10);
        buf = malloc(tlen);
        if (!buf) {
            printf("failed to allocate buffer for table\n");
            exit(1);
        }
        // Do stuff here
        assert(ttxen_op(TTXEN_OP_READ_TABLE, tlen, buf) == 0);
        f = fopen(argv[3], "wb");
        if (!f) {
            printf("failed to open file\n");
            exit(1);
        }
        fwrite(buf, 1, tlen, f);
        fclose(f);
        free(buf);
    } else if (strcmp(argv[1], "get_vcpu_info") == 0) {
        struct ttxen_op_vcpu top;
        if (argc != 4) {
            usage_get_vcpu_info();
            exit(1);
        }
        top.magic = TTXEN_OP_MAGIC;
        top.dom_id = atoi(argv[2]);
        top.vcpu_id = atoi(argv[3]);
        assert(ttxen_op(TTXEN_OP_VCPU_CORE, sizeof(struct ttxen_op_vcpu), (char *)&top) == 0);
        printf("%s %ld\n",
            (top.cpu >> 16) == TYPE_TIER2 ? "Tier-2" : "Tier-1",
            (top.cpu & 0xffff));
    } else if (strcmp(argv[1], "read_stats") == 0) {
        struct idle_stats *buf;
        int ncpus;
        if (argc != 3) {
            printf("usage: ttxentool read_stats <number of cpus>\n");
            exit(1);
        }
        ncpus = atoi(argv[2]);
        buf = malloc(sizeof(struct idle_stats) * ncpus);
        
        if (!buf) {
            printf("failed to allocate buffer for stats\n");
            exit(1);
        }
        assert(ttxen_op(TTXEN_OP_READ_STATS, sizeof(struct idle_stats) * ncpus, (char *)buf) == 0);
        for (i = 0 ; i < ncpus; i++) {
            for (j = 0; j < CONFIG_MAX_STATS; j++) {
                /* incomplete slots have end time = 0 */
                if (buf[i].slots[j].end == 0)
                    continue;
                printf("%llu:%llu ",
                    (unsigned long long)(buf[i].slots[j].end - buf[i].slots[j].start),
                    (unsigned long long)buf[i].slots[j].total_time);
            }
            printf("\n");
        }
    } else if (strcmp(argv[1], "get_num_pcpus") == 0) {
        unsigned long cpus;
        assert(ttxen_op(TTXEN_OP_READ_NUM_CPUS, sizeof(unsigned long), (char *)&cpus) == 0);
        printf("%lu\n", cpus);
    }

    return 0;
}
