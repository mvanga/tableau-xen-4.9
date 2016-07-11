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

#include "libxl_osdeps.h"

#include "libxl_internal.h"
#include "libxl_arch.h"

int libxl_perf_stats(libxl_ctx *ctx, void* stats)
{
    int rc = 0;

    GC_INIT(ctx);

    if (xc_perf_stats(ctx->xch, stats)) {
        LOG(ERROR, "perf get stats failure");
        rc = ERROR_FAIL;
    }

    GC_FREE;

    return rc;
}

int libxl_perf_config(libxl_ctx *ctx, libxl_perf_cfg* pcfg)
{
    int rc = 0;
    xc_perf_t xc_perf;

    GC_INIT(ctx);

    xc_perf.cmd = XEN_PERF_config;
    xc_perf.u.config.action = pcfg->action;
    xc_perf.u.config.keep = pcfg->keep;
    xc_perf.u.config.domids.num = pcfg->domidlist.num;
    xc_perf.u.config.domids.idslist = pcfg->domidlist.domids;
    xc_perf.u.config.vcpu = pcfg->vcpuid;
    xc_perf.u.config.pmes_config.num = pcfg->eventslist.num;
    xc_perf.u.config.pmes_config.pmes = (xc_perf_pme_t*)pcfg->eventslist.pmes;

    if (xc_perf_config(ctx->xch, &xc_perf)) {
        LOG(ERROR, "Failed to configure perf monitoring");
        rc = ERROR_FAIL;
    }

    GC_FREE;

    return rc;
}

int libxl_perf_get_dom_max_vcpus(void)
{
    return libxl__arch_perf_get_dom_max_vcpus();
}

int libxl_perf_get_arch_pme_info_tbl(struct pme_info **tbl)
{
    int size = 0;
    struct arch_pme_info* arch_tbl = NULL;

    size = libxl__perf_get_arch_pme_info_tbl(&arch_tbl);
    *tbl = (struct pme_info*)arch_tbl;

    return size;
}
