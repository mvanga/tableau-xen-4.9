/****************************************************************************
 *        File: perf.c
 *      Author: Cosmin Marin
 *
 * Description: ARM interface to the per VCPU performance monitoring counters
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

#include <asm/perf.h>

void perf_set_event(u8 counter_id, u64 event_id, u8 flags)
{

    //TODO: to be implemented
    return;
}

u64 perf_get_counter(u8 counter_id)
{
    u64 val = 0;
    //TODO: to be implemented

    return val;
}

u64 perf_get_tsc(void)
{
    u64 tsc = 0;
    //TODO: to be implemented

    return tsc;
}
