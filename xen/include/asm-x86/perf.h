/****************************************************************************
 *        File: perf.h
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

#ifndef __XEN_PMU_H__
#define __XEN_PMU_H__

/* Event Selector Register format*/

// 31       24  23  22  21  20  19  18  17  16 15      8 7          0
//  -----------------------------------------------------------------
//  |        | I | E | A | I | P | E | O | U |          |           |
//  | CMASK  | N | N | N | N | C |   | S | S | UnitMask | Event Sel |
//  |        | V |   | Y | T |   |   |   | R |          |           |
//  -----------------------------------------------------------------

#define EVTNUM_OFFSET   0
#define EVTMSK_OFFSET   8
#define USR_OFFSET      16
#define OS_OFFSET       17
#define E_OFFSET        18
#define PC_OFFSET       19
#define INT_OFFSET      20
#define ANY_OFFSET      21
#define EN_OFFSET       22
#define INV_OFFSET      23

#define     USER_CTXT   0x1
#define     KERN_CTXT   0x2

void perf_set_event(u8 counter_id, u64 event_id, u8 flags);

u64 perf_get_counter(u8 counter_id);

u64 perf_get_tsc(void);
#endif
