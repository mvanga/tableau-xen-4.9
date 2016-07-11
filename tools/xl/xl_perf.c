/*
 * Author Cosmin Marin <cosmin@mpi-sws.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 3.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#include <inttypes.h>
#include <stdlib.h>

#include <libxl.h>
#include <libxl_json.h>
#include <libxl_utils.h>
#include <libxlutil.h>

#include "xl.h"
#include "xl_utils.h"
#include "xl_parse.h"

#define OUTPUT_FMT_INTERVAL_SEPARATOR       '-'
#define OUTPUT_FMT_ENUMERATION_SEPARATOR    ','

#define DOMID_ALL   (-1)
#define MAX_VCPUS   libxl_perf_get_dom_max_vcpus()

static bool init_done = false;
static int num_counters = -1;
static uint32_t perf_events_tbl_size = 0;
static struct pme_info *perf_events_tbl = NULL;

static int perf_build_report_header(char* header, uint16_t len, uint64_t rmask)
{
    int i = 0;
    int rc = -1;
    int hdrlen = 0;
    int bytes = 0;
    char hdr[256] = { 0 };
    char *phdr = hdr;

    if (!header) {
        printf("err: invalid pointer\n");
        goto out;
    }
    memset(header, 0, len);

#define PERF_REPORT_FIXED_HEADER_FMT    "%-16s %-3s %-4s "

    bytes += sprintf(phdr + bytes, PERF_REPORT_FIXED_HEADER_FMT, "Name", "ID", "VCPU");
    for (i = 0; i < num_counters; i++) {
        if (!(rmask & (1 << i)))
            continue;
        char cntx[32] = { 0 };
        sprintf(cntx, "PMC%-16d", i);
        bytes += sprintf(phdr + bytes, "%-20s", cntx);
    }
    bytes += sprintf(phdr + bytes, "%s", "CLKTics");

    hdrlen = strlen(hdr);
    if (len <= hdrlen) {
        printf("err: header buffer's size is too small\n");
        goto out;
    }

    memcpy(header, hdr, hdrlen);

    rc = 0;
out:
    return rc;
}

static void print_perf_stats_in_user_fmt(void* buffer, uint32_t has_header,
                uint32_t domain_id, uint32_t vcpu_id, uint64_t rmask)
{
    char header[256] = { 0 };
    uint8_t* ptr8;
    uint16_t* ptr16;
    uint64_t* ptr64;
    uint16_t num_domains_k = 0;
    uint16_t num_vcpus = 0;
    uint16_t domid;

    if (has_header) {
        if (!header[0])
            if (perf_build_report_header(header, 256, rmask)) {
                fprintf(stderr, "err: failed to build report header\n");
                return;
            }

        printf("%s\n", header);
    }

    ptr16 = (uint16_t*) (buffer);
    num_domains_k = *ptr16;
    ptr16++;

    // parse buffer according to expected format
    for (int i = 0; i < num_domains_k; i++) {
        char entry[256] = { 0 };
        char* pentry = entry;
        int offset = 0;

        domid = *ptr16;
        ptr16++;
        num_vcpus = *ptr16;
        ptr16++;

        offset += sprintf(pentry + offset, "%-16s %-3d ",
                    libxl_domid_to_name(ctx, domid), domid);

        for (int j = 0; j < num_vcpus; j++) {
            ptr8 = (uint8_t*)ptr16;
            uint8_t num_events = *ptr8;

            ptr8++;
            ptr16 = (uint16_t*)ptr8;
            offset += sprintf(pentry + offset, "%-4d ", j);
            for (int k = 0; k < num_events; k++) {
                uint16_t event = *ptr16;
                ptr16++;
                ptr64 = (uint64_t*)ptr16;
                uint64_t pmc = *ptr64;
                ptr64++;
                ptr16 = (uint16_t*)ptr64;

                //print only user selected event counters
                if (!(rmask & (1 << k)))
                    continue;

                if (!event && !pmc)
                    offset += sprintf(pentry + offset, "%-20s", "N/A");
                else {
                    int l;
                    for (l = 0; l < perf_events_tbl_size; l++) {
                        uint16_t key = perf_events_tbl[l].id;
                        if (key == event)
                            break;
                    }
                    if (l < perf_events_tbl_size)
                        offset += sprintf(pentry + offset, "%-4s:%-15lu",
                                perf_events_tbl[l].mnemonic, pmc);
                    else
                        offset += sprintf(pentry + offset,
                                "%-4x:%-15lu", event, pmc);
                }
            }

            ptr64 = (uint64_t*)ptr16;
            uint64_t tscs = *ptr64;
            ptr64++;
            ptr16 = (uint16_t*)ptr64;

            offset += sprintf(pentry + offset, "%lu", tscs);

            // filter printing based on domain or vcpu id it user
            // asked for that
            if ((domain_id == domid || domain_id == DOMID_ALL) &&
                    (vcpu_id == j || vcpu_id == MAX_VCPUS + 1))
                printf("%s\n", entry);
            memset(entry, 0, 256);
            offset = sprintf(pentry, "%-21s", "");
        }
    }
}

static void print_perf_stats_in_parser_fmt(void* buffer,
        uint32_t domain_id, uint32_t vcpu_id, uint64_t rmask)
{
    uint8_t* ptr8;
    uint16_t* ptr16;
    uint64_t* ptr64;
    uint16_t num_domains_k = 0;
    uint16_t num_vcpus = 0;
    uint16_t domid;

    ptr16 = (uint16_t*) (buffer);
    num_domains_k = *ptr16;
    ptr16++;

    // parse buffer according to expected format
    for (int i = 0; i < num_domains_k; i++) {
        char entry[256] = { 0 };
        char* pentry = entry;

        domid = *ptr16;
        ptr16++;
        num_vcpus = *ptr16;
        ptr16++;

        for (int j = 0; j < num_vcpus; j++) {
            uint16_t offset = 0;

            ptr8 = (uint8_t*)ptr16;
            uint8_t num_events = *ptr8;

            ptr8++;
            ptr16 = (uint16_t*)ptr8;

            offset += sprintf(pentry + offset,
                    "%-3d %-2d %-2d ", domid, j, num_events);
            for (int k = 0; k < num_events; k++) {
                uint16_t event = *ptr16;
                ptr16++;
                ptr64 = (uint64_t*)ptr16;
                uint64_t pmc = *ptr64;
                ptr64++;
                ptr16 = (uint16_t*)ptr64;

                //print only user selected event counters
                if (!(rmask & (1 << k)))
                    continue;

                offset += sprintf(pentry + offset,
                        "0x%04x:%-16lu ", event, pmc);
            }

            ptr64 = (uint64_t*)ptr16;
            offset += sprintf(pentry + offset,
                    "%16lu\n", *ptr64);
            ptr64++;
            ptr16 = (uint16_t*)ptr64;

            // filter printing based on domain or vcpu id it user
            // asked for that
            if ((domain_id == domid || domain_id == DOMID_ALL) &&
                    (vcpu_id == j || vcpu_id == MAX_VCPUS + 1))
                printf("%s", entry);
            memset(entry, 0, 256);
        }
    }
}

#define CHOOSE_REPORT_FMT( fmt,                                             \
        buf, has_header, domain_id, vcpu_id, register_mask)                 \
    do {                                                                    \
        switch((fmt)) {                                                     \
            case 'h':                                                       \
                print_perf_stats_in_user_fmt((buf), (has_header),           \
                    (domain_id), (vcpu_id), (register_mask));               \
                break;                                                      \
                                                                            \
            case 'm':                                                       \
                print_perf_stats_in_parser_fmt((buf), (domain_id),          \
                    (vcpu_id), (register_mask));                            \
                break;                                                      \
                                                                            \
            default:                                                        \
                fprintf(stderr, "err: unknown report format\n");            \
                goto out;                                                   \
                break;                                                      \
        }                                                                   \
    } while(0);

static int perf_dump_stats(char fmt,
        libxl_domid_list* domidlist, uint32_t vcpu_id, uint64_t rmask)
{
    int rc = EXIT_FAILURE;
    libxl_pmcs pmcs;
    uint16_t num_domains_u = 0;
    uint16_t num_vcpus = 0;
    libxl_dominfo *info_list = 0;
    libxl_dominfo *info_list_iter = 0;
    libxl_dominfo info_buf;

    /*
     * format of expected buffer
     *  num_domains                     - 16b
     *      domain0_id                  - 16b
     *          num_vcpus               - 16b
     *              vcpu0_num_events    - 8b
     *                  vcpu0_event0    - 16b
     *                  vcpu0_pmc0      - 64b
     *                  vcpu0_event1    - 16b
     *                  vcpu0_pmc1      - 64b
     *              vcpu0_tsc           - 64b
     *              vcpu1_num_events    - 8b
     *                  vcpu1_event0    - 16b
     *                  vcpu1_pmc0      - 64b
     *              vcpu1_tsc           - 64b
     *  .......................................
     *      domainN_id                  - 16b
     *          num_vcpus               - 16b
     *              vcpu0_num_events    - 8b
     *                  vcpu0_event0    - 64b
     *                  vcpu0_pmc0      - 64b
     *              vcpu0_tsc           - 64b
     *  .......................................
     *
     *      event_pmc_block = size(vcpu_event + vcpu_pmc) = 16b + 64b = 80b
     *      vcpu_block = size(num_events) + num_events  * event_pmc_block + size(tsc) =
     *              8b + num_events * 80b + 64b = 72b + num_events * 80b
     *      domain_block = size(domain_id) + size(num_vcpus) + num_vcpus * vcpu_events_block =
     *              16b + 16b + num_vcpus * (72b + num_events * 80b)
     *      buffer_size = size(num_domains) + domain0_block + ... + domainN_block =
     *              16b + domain0_block + ... domainN_block
     *
     *      => formula:
     *      buffer_size = 16b + 32b * num_domains +  num_vcpus * (72b + num_events * 80b)
     *
     *  example:
     *      num_domains = 2
     *          domain1: num_vcpus = 2
     *          domain2: num_vcpus = 1
     *      num_events = 8(total number of counters available on platform)
     *
     *      buffer_size = 16b + 32b * 2 + 3 * (72b + 8 * 80b)  = 2216b => 277B
     *
     */

    // get number of domains in the system
    info_list = libxl_list_domain(ctx, (int*)&num_domains_u);
    if (!info_list) {
        fprintf(stderr, "libxl_list_domain failed.\n");
        goto out;
    }
    info_list_iter = info_list;

    // get each domain number of vcpus
    for (int i = 0; i < num_domains_u; i++) {
        memset(&info_buf, 0, sizeof(libxl_dominfo));
        if (!libxl_domain_info(ctx, &info_buf, info_list_iter->domid))
            num_vcpus += info_buf.vcpu_max_id + 1;
        info_list_iter++;
    }

    // compute the necessary amount of memory
    pmcs.size = sizeof(uint16_t) +
        2 * sizeof(uint16_t) * num_domains_u +
        (sizeof(uint8_t) + sizeof(uint64_t) + num_counters * (sizeof(uint16_t) + sizeof(uint64_t))) * num_vcpus;
    pmcs.size = pmcs.size << 1;
    // to be on the safe side double the actual needed
    // size - theoretically, at least
    pmcs.buffer = calloc(pmcs.size, sizeof(uint8_t));
    if (!pmcs.buffer) {
        fprintf(stderr,"xl: Unable to alloc to %lu bytes.\n",
                      (unsigned long)pmcs.size);
        exit(-ERROR_FAIL);
    }

    // in the end get perf monitoring counter from kernel space
    if (libxl_perf_stats(ctx, (void*)pmcs.buffer)) {
        fprintf(stderr, "err: retrieving PMCs failed");
        goto out;
    }
    printf("stats retrieved\n");
    if (domidlist->num) {
        // filter stats dumping by list of domains we're interested in
        for (int i = 0; i < domidlist->num; i++) {
            CHOOSE_REPORT_FMT(fmt,
                (void*)pmcs.buffer, !i, domidlist->domids[i], vcpu_id, rmask);
        }
    } else {
        // dump stats for all domains, per convension use DOMID_ALL(=-1)
        // to signal a query for all domains
        CHOOSE_REPORT_FMT(fmt,
            (void*)pmcs.buffer, 1, DOMID_ALL, vcpu_id, rmask);
    }

    rc = EXIT_SUCCESS;

out:
    // release allocated memory
    if (info_list)
        libxl_dominfo_list_free(info_list, num_domains_u);
    if (pmcs.buffer)
        libxl_pmcs_dispose(&pmcs);
    return rc;
}

static int parse_friendly_fmt(const char* events, libxl_perf_cfg* pcfg)
{
    int i = 0, j = 0;
    int r = -1;
    const char* token = NULL;
    libxl_pme_list* eventslist = NULL;
    libxl_string_list evl;

    if (!events || !pcfg) {
        fprintf(stderr,
            "err: null argument\n");
        goto out;
    }

    eventslist = &pcfg->eventslist;
    split_string_into_string_list(events, ",", &evl);
    eventslist->num = libxl_string_list_length(&evl);
    if (eventslist->num >= num_counters) {
        fprintf(stderr,
                "err: too many arguments, only %d counter available\n",
                num_counters);
        goto out;
    }

    for (i = 0; i < eventslist->num; i++) {
        printf("event: %s ", evl[i]);
        for (j = 0; j < perf_events_tbl_size; j++)
            if (!strcmp(evl[i], perf_events_tbl[j].mnemonic) ||
                        !strcmp(evl[i], perf_events_tbl[j].name))
                break;
        if (j == perf_events_tbl_size) {
            fprintf(stderr, "Unknown event: %s\n", token);
            goto out;
        }
        eventslist->pmes[i].id = perf_events_tbl[j].id;
        printf("id: %#8x\n", eventslist->pmes[i].id);
    }

    r = 0;
out:
    libxl_string_list_dispose(&evl);
    return r;
}

static int parse_raw_fmt(const char* events, libxl_perf_cfg* pcfg)
{
    int r = -1;
    libxl_pme_list* eventslist = NULL;
    libxl_string_list evl;

    if (!events || !pcfg) {
        fprintf(stderr,
            "err: null argument\n");
        goto out;
    }

    eventslist = &pcfg->eventslist;
    split_string_into_string_list(events, ",", &evl);
    eventslist->num = libxl_string_list_length(&evl);
    if (eventslist->num >= num_counters) {
        fprintf(stderr,
                "err: too many arguments, only %d counter available\n",
                num_counters);
        goto out;
    }

    for (int i = 0; i < eventslist->num; i++)
        eventslist->pmes[i].id = parse_integer_number(evl[i], 16);

    r = 0;
out:
    libxl_string_list_dispose(&evl);
    return r;
}

static int xl_perf_config(const char* events, libxl_perf_cfg* pcfg)
{
    int rc = -1;

    if (!pcfg) {
        fprintf(stderr,
            "err: null argument\n");
        goto out;
    }

    // extract the events to be monitored
    switch(*events) {
        case 'f':
            if (parse_friendly_fmt(++events, pcfg))
                goto out;
            break;

        case 'r':
            if (parse_raw_fmt(++events, pcfg))
                goto out;
            break;

        default:
            fprintf(stderr,
                "err: unknown event format\n");
            goto out;
            break;
    }

    if (libxl_perf_config(ctx, pcfg)) {
        fprintf(stderr,
            "err: libxl perf config failure\n");
        goto out;
    }

    rc = 0;

out:
    return rc;
}

static void xl_dump_info(void)
{
    int i = 0;

    printf("\n");
    printf("  %-20s %-10s %-20s\n", "EVENT", "MNEMONIC", "DESCRIPTION");

    for (i = 0; i < perf_events_tbl_size; i++)
        printf("  %-20s %-10s %-100s\n", perf_events_tbl[i].name,
                perf_events_tbl[i].mnemonic, perf_events_tbl[i].description);
    printf("\n");

    printf("Notes: performance event identification varies across   "
            "different hardware platforms. Hence user is expected to "
            "provide counter identification parameter in platform    "
            "specific format. See below supported platform formats\n");
    printf("x86: single 16bit number in hex format\n"
            "     MSB contains event mask\n"
            "     LSB contains event number\n");
    printf("arm: single 16bit event identifier\n");
}

static void xl_perf_init(void)
{
    libxl_physinfo info;

    if (libxl_get_physinfo(ctx, &info) != 0) {
        fprintf(stderr, "libxl_physinfo failed.\n");
        exit(EXIT_FAILURE);
    }
    num_counters = info.pmuinfo.gp_cnt_num;

    perf_events_tbl_size = libxl_perf_get_arch_pme_info_tbl(
            &perf_events_tbl);

    init_done = true;
}

/*
 *  Get/set PMU parameter per domain, vcpu or system wide
 *  [-i] | [[[-c -e <f><MNEMONIC1:...>|<r><ID1,MASK1:...>] [-a <start|stop> [-k]] | -s] [[-d <Domain>] | [-v <VCPUID>]]]
 *  -i, --information                        List of platform supported events and number of counters
 *  -c, --configure                          Configure performance monitoring session
 *  -e <f><MNEMONIC1:...>|<r><ID1,MASK1:...> List of events to be monitored. The list can be specified either in a
 *                                             friendly manner using the predefined events mnemonics or in a raw
 *                                             manner by specifying the event ID and MASK. IDs are separated from
 *                                             MASKs by a \",\". List elements use \":\" as separator for both formats
 *  -s, --stats                              Dump monitored session statistics
 *  -k, --keep                               Keep current counters/timestamps values
 *  -d Domain, --domain=DOMAIN               For which domain performance monitoring session will be enabled
 *  -v VCPUID, --vcpuid=VCPUID,              For which VCPU performance monitoring session will be enabled\
 *  -a <start|stop>, --action=<start|stop>   Start/stop a monitoring session\n"
 */
int main_perf(int argc, char** argv)
{
    int r;
    int opt = 0;
    bool opt_a;
    bool opt_s;
    bool opt_e;
    bool opt_i;
    bool opt_c;
    bool opt_k;
    bool opt_r;
    int vcpuid = MAX_VCPUS + 1; //by default all VCPUs
    uint64_t rmask = 0;
    char fmt = 'h';
    const char* dom = NULL;
    char events[256];
    static libxl_perf_cfg pcfg = { 0 };
    libxl_perf_action_type action = LIBXL_PERF_ACTION_TYPE_STOP;
    static struct option opts[] = {
        {"action",    1, 0, 'a'},
        {"keep",      0, 0, 'k'},
        {"configure", 0, 0,  1 },
        {"domain",    1, 0, 'd'},
        {"events",    1, 0, 'e'},
        {"info",      0, 0,  1 },
        {"stats",     0, 0,  1 },
        {"vcpuid",    1, 0, 'v'},
        {"register",  1, 0, 'r'},
        COMMON_LONG_OPTS
    };

    r = EXIT_FAILURE;

    if (!init_done)
        xl_perf_init();

    pcfg.eventslist.pmes = xcalloc(num_counters, sizeof(libxl_pme));
    if (!pcfg.eventslist.pmes) {
        fprintf(stderr,
                "err: memory allocation for \"perf\" config failed!\n");
        goto out;
    }

    opt_a = opt_s = opt_e = opt_i = opt_c = opt_k = opt_r = false;
    SWITCH_FOREACH_OPT(opt, "cikd:v:e:a:r:s::", opts, "perf", 0) {
        case 'i':           //info
            opt_i = true;
            break;

        case 'c':           //configure
            opt_c = true;
            break;

        case 's':           //get stats
            opt_s = true;
            if (optarg)
                fmt = *optarg;
            break;

        case 'k':           //keep
            opt_k = true;
            break;

        case 'd':           //domain ID
            dom = optarg;
            break;

        case 'v':           //vcpu ID
            {
                char* err = NULL;

                vcpuid = strtol(optarg, &err, 10);
                if (err != NULL && *err != '\0') {
                    fprintf(stderr,
                        "err: wrong parameter type, number expected\n");
                    goto out;
                }

                if (vcpuid > MAX_VCPUS) {
                    fprintf(stderr,
                        "err: current Xen version supports maximum: %d\n",
                        MAX_VCPUS);
                    goto out;
                }
            }
            break;

        case 'e':           //events to be monitored
            opt_e = true;
            memcpy(events, optarg, 256);
            break;

        case 'a':           //action
            opt_a = true;
            if (!strncmp(optarg, "start", 5)) {
                action = LIBXL_PERF_ACTION_TYPE_START;
            } else if (strncmp(optarg, "stop", 4)) {
                fprintf(stderr,
                    "err: unknown requested action\n");
                goto out;
            }
            break;

        case 'r':
            opt_r = true;
            if (optarg) {
                char* separator = NULL;
                libxl_uintnum_constraints constr = { 0 };

                constr.min = 0;
                constr.max = num_counters - 1;

                if ((separator = strchr(optarg,
                                OUTPUT_FMT_INTERVAL_SEPARATOR))) {
                    long ledge = 0, redge = 0;

                    if (parse_interval(optarg, separator,
                            &constr, &ledge, &redge)) {
                        goto out;
                    }

                    for (int i = ledge; i <= redge; i++)
                        rmask |= (uint64_t)(1 << i);
                } else if ((separator = strchr(optarg,
                                OUTPUT_FMT_ENUMERATION_SEPARATOR))) {
                    uint32_t i = 0;
                    uint32_t size = 0;
                    long* array;

                    if (parse_num_enumeration(optarg, ",",
                                &constr,  &array, &size)) {
                        goto out;
                    }
                    for (i = 0; i < size; i++)
                        rmask |= (uint64_t)(1 << array[i]);
                } else {
                    long val;

                    if (parse_constrained_number(optarg, 16, &constr, &val))
                        goto out;
                    rmask |= (uint64_t)(1 << val);
                }
            }
            break;
    }

    if (dom) {
        uint32_t i = 0;
        uint32_t domid = DOMID_ALL;
        libxl_string_list domlist;

        split_string_into_string_list(dom, ",", &domlist);
        pcfg.domidlist.num = libxl_string_list_length(&domlist);
        pcfg.domidlist.domids = xmalloc(sizeof(uint32_t) * pcfg.domidlist.num);
        if (!pcfg.domidlist.domids) {
            fprintf(stderr, "err: domain list allocation\n");
            goto out;
        }
        for (i = 0; i < pcfg.domidlist.num; i++) {
            if (ERROR_INVAL == libxl_name_to_domid(ctx, domlist[i], &domid)) {
                fprintf(stderr,
                    "err: domain %s not found\n", dom);
                goto out;
            }
            pcfg.domidlist.domids[i] = domid;
            printf("domain %d - %s/%u\n", i, domlist[i], domid);
        }

        libxl_string_list_dispose(&domlist);
    }

    if (opt_i) {
        xl_dump_info();
    } else if (opt_c) {
        //validate rest of arguments
        if (!opt_e) {
            fprintf(stderr,
                    "err: event(s) to be monitored missing\n");
            goto out;
        }

        pcfg.vcpuid = vcpuid;
        pcfg.action = action;
        // when a new configuration is applied counters are cleared
        // anyway, such that opt_k here has no effect
        pcfg.keep = opt_k;
        pcfg.eventslist.num = 0;

        memset(pcfg.eventslist.pmes, 0, num_counters * sizeof(libxl_pme));
        if (xl_perf_config(events, &pcfg)) {
            fprintf(stderr,
                    "err: configuring performance monitoring session failed\n");
            goto out;
        }
    } else if (opt_s) {
        r = perf_dump_stats(fmt, &pcfg.domidlist, vcpuid,
                (opt_r) ? rmask : ~rmask);
    } else if (opt_a) {
        libxl_pme* save_eventslist = pcfg.eventslist.pmes;

        pcfg.vcpuid = vcpuid;
        pcfg.action = action;
        pcfg.keep = opt_k;
        pcfg.eventslist.num = 0;
        pcfg.eventslist.pmes = NULL;

        if (libxl_perf_config(ctx, &pcfg)) {
            fprintf(stderr,
                "err: libxl perf config failure\n");
            goto out;
        }

        pcfg.eventslist.pmes = save_eventslist;
    } else {
        fprintf(stdout,
                "err: unknown option\n");
        goto out;
    }

    r = EXIT_SUCCESS;

out:
    if (pcfg.eventslist.pmes) {
        free(pcfg.eventslist.pmes);
        pcfg.eventslist.pmes = NULL;
    }
    return r;
}
