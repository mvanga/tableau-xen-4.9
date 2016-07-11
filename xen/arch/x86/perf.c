/****************************************************************************
 *        File: perf.c
 *      Author: Cosmin Marin
 *
 * Description: x86 interface to the per VCPU performance monitoring counters
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

#include <asm/msr.h>
#include <asm/perf.h>

void perf_set_event(u8 counter_id, u64 event_id, u8 flags)
{
    u32 eax = 0;
    u32 edx = 0;
    u32 id = 0;
    u32 msk = 0;

    // in current PMU version event is encoded using two bytes
    // byte0: event identifier
    // byte1: event mask
    id = event_id & 0xFF;
    msk = event_id >> 8;

    eax |= (1 << EN_OFFSET);
    eax |= (id << EVTNUM_OFFSET);
    eax |= (msk << EVTMSK_OFFSET);

    // for events for which execution context matters
    if (flags & USER_CTXT)
            eax |= (1 << USR_OFFSET);
    if (flags & KERN_CTXT)
            eax |= (1 << OS_OFFSET);

    //edx must remain 0
    wrmsr(MSR_P6_EVNTSEL(counter_id), eax, edx);
}

u64 perf_get_counter(u8 counter_id)
{
    u32 eax = 0;
    u32 edx = 0;
    u64 val = 0;

    rdmsr(MSR_P6_PERFCTR(counter_id), eax, edx);

    val = eax | ((u64)edx << 32);

    return val;
}

u64 perf_get_tsc(void)
{
    return rdtsc();
}
