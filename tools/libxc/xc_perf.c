/****************************************************************************
 *
 *        File: xc_perf.c
 *      Author: Cosmin Marin
 *
 * Description: XC Interface to the per VCPU performance monitoring counters
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
 */

#include "xc_private.h"

int
xc_perf_stats(xc_interface *xch,
        void* buffer)
{
    DECLARE_SYSCTL;

    sysctl.cmd = XEN_SYSCTL_perf_op;
    sysctl.u.perf_op.cmd = XEN_PERF_stats;
    sysctl.u.perf_op.u.stats.buffer = buffer; /* OUT */

    printf("xc do perf stats\n");
    if ( do_sysctl(xch, &sysctl) )
        return -1;

    return 0;
}

int
xc_perf_config(xc_interface* xch,
    xc_perf_t* config)
{
    DECLARE_SYSCTL;

    sysctl.cmd = XEN_SYSCTL_perf_op;
    memcpy(&sysctl.u.perf_op, config, sizeof(xc_perf_t));

    if ( do_sysctl(xch, &sysctl) )
        return -1;

    return 0;
}
