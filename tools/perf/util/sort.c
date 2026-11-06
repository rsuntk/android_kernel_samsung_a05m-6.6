// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <inttypes.h>
#include <regex.h>
#include <stdlib.h>
#include <linux/mman.h>
#include <linux/time64.h>
#include "debug.h"
#include "dso.h"
#include "sort.h"
#include "hist.h"
#include "cacheline.h"
#include "comm.h"
#include "map.h"
#include "maps.h"
#include "symbol.h"
#include "map_symbol.h"
#include "branch.h"
#include "thread.h"
#include "evsel.h"
#include "evlist.h"
#include "srcline.h"
#include "strlist.h"
#include "strbuf.h"
#include "mem-events.h"
#include "annotate.h"
#include "event.h"
#include "time-utils.h"
#include "cgroup.h"
#include "machine.h"
#include "trace-event.h"
#include <linux/kernel.h>
#include <linux/string.h>

#ifdef HAVE_LIBTRACEEVENT
#include <traceevent/event-parse.h>
#endif

regex_t		parent_regex;
const char	default_parent_pattern[] = "^sys_|^do_page_fault";
const char	*parent_pattern = default_parent_pattern;
const char	*default_sort_order = "comm,dso,symbol";
const char	default_branch_sort_order[] = "comm,dso_from,symbol_from,symbol_to,cycles";
const char	default_mem_sort_order[] = "local_weight,mem,sym,dso,symbol_daddr,dso_daddr,snoop,tlb,locked,blocked,local_ins_lat,local_p_stage_cyc";
const char	default_top_sort_order[] = "dso,symbol";
const char	default_diff_sort_order[] = "dso,symbol";
const char	default_tracepoint_sort_order[] = "trace";
const char	*sort_order;
const char	*field_order;
regex_t		ignore_callees_regex;
int		have_ignore_callees = 0;
enum sort_mode	sort__mode = SORT_MODE__NORMAL;
static const char *const dynamic_headers[] = {"local_ins_lat", "ins_lat", "local_p_stage_cyc", "p_stage_cyc"};
static const char *const arch_specific_sort_keys[] = {"local_p_stage_cyc", "p_stage_cyc"};

/*
 * Some architectures have Adjacent Cacheline Prefetch feature, which
 * behaves like the cacheline size is doubled. Enable this flag to
 * check things in double cacheline granularity.
 */
bool chk_double_cl;

/*
 * Replaces all occurrences of a char used with the:
 *
 * -t, --field-separator
 *
 * option, that uses a special separator character and don't pad with spaces,
 * replacing all occurrences of this separator in symbol names (and other
 * output) with a '.' character, that thus it's the only non valid separator.
*/
static int repsep_snprintf(char *bf, size_t size, const char *fmt, ...)
{
	int n;
	va_list ap;

	va_start(ap, fmt);
	n = vsnprintf(bf, size, fmt, ap);
	if (symbol_conf.field_sep && n > 0) {
		char *sep = bf;

		while (1) {
			sep = strchr(sep, *symbol_conf.field_sep);
			if (sep == NULL)
				break;
			*sep = '.';
		}
	}
	va_end(ap);

	if (n >= (int)size)
		return size - 1;
	return n;
}

static int64_t cmp_null(const void *l, const void *r)
{
	if (!l && !r)
		return 0;
	else if (!l)
		return -1;
	else
		return 1;
}

/* --sort pid */

static int64_t
sort__thread_cmp(struct hist_entry *left, struct hist_entry *right)
{
	return thread__tid(right->thread) - thread__tid(left->thread);
}

static int hist_entry__thread_snprintf(struct hist_entry *he, char *bf,
				       size_t size, unsigned int width)
{
	const char *comm = thread__comm_str(he->thread);

	width = max(7U, width) - 8;
	return repsep_snprintf(bf, size, "%7d:%-*.*s", thread__tid(he->thread),
			       width, width, comm ?: "");
}

static int hist_entry__thread_filter(struct hist_entry *he, int type, const void *arg)
{
	const struct thread *th = arg;

	if (type != HIST_FILTER__THREAD)
		return -1;

	return th && RC_CHK_ACCESS(he->thread) != RC_CHK_ACCESS(th);
}

struct sort_entry sort_thread = {
	.se_header	= "    Pid:Command",
	.se_cmp		= sort__thread_cmp,
	.se_snprintf	= hist_entry__thread_snprintf,
	.se_filter	= hist_entry__thread_filter,
	.se_width_idx	= HISTC_THREAD,
};

/* --sort simd */

static int64_t
sort__simd_cmp(struct hist_entry *left, struct hist_entry *right)
{
	if (left->simd_flags.arch != right->simd_flags.arch)
		return (int64_t) left->simd_flags.arch - right->simd_flags.arch;

	return (int64_t) left->simd_flags.pred - right->simd_flags.pred;
}

static const char *hist_entry__get_simd_name(struct simd_flags *simd_flags)
{
	u64 arch = simd_flags->arch;

	if (arch & SIMD_OP_FLAGS_ARCH_SVE)
		return "SVE";
	else
		return "n/a";
}

static int hist_entry__simd_snprintf(struct hist_entry *he, char *bf,
				     size_t size, unsigned int width __maybe_unused)
{
	const char *name;

	if (!he->simd_flags.arch)
		return repsep_snprintf(bf, size, "");

	name = hist_entry__get_simd_name(&he->simd_flags);

	if (he->simd_flags.pred & SIMD_OP_FLAGS_PRED_EMPTY)
		return repsep_snprintf(bf, size, "[e] %s", name);
	else if (he->simd_flags.pred & SIMD_OP_FLAGS_PRED_PARTIAL)
		return repsep_snprintf(bf, size, "[p] %s", name);

	return repsep_snprintf(bf, size, "[.] %s", name);
}

struct sort_entry sort_simd = {
	.se_header	= "Simd   ",
	.se_cmp		= sort__simd_cmp,
	.se_snprintf	= hist_entry__simd_snprintf,
	.se_width_idx	= HISTC_SIMD,
};

/* --sort comm */

/*
 * We can't use pointer comparison in functions below,
 * because it gives different results based on pointer
 * values, which could break some sorting assumptions.
 */
static int64_t
sort__comm_cmp(struct hist_entry *left, struct hist_entry *right)
{
	return strcmp(comm__str(right->comm), comm__str(left->comm));
}

static int64_t
sort__comm_collapse(struct hist_entry *left, struct hist_entry *right)
{
	return strcmp(comm__str(right->comm), comm__str(left->comm));
}

static int64_t
sort__comm_sort(struct hist_entry *left, struct hist_entry *right)
{
	return strcmp(comm__str(right->comm), comm__str(left->comm));
}

static int hist_entry__comm_snprintf(struct hist_entry *he, char *bf,
				     size_t size, unsigned int width)
{
	return repsep_snprintf(bf, size, "%-*.*s", width, width, comm__str(he->comm));
}

struct sort_entry sort_comm = {
	.se_header	= "Command",
	.se_cmp		= sort__comm_cmp,
	.se_collapse	= sort__comm_collapse,
	.se_sort	= sort__comm_sort,
	.se_snprintf	= hist_entry__comm_snprintf,
	.se_filter	= hist_entry__thread_filter,
	.se_width_idx	= HISTC_COMM,
};

/* --sort dso */

static int64_t _sort__dso_cmp(struct map *map_l, struct map *map_r)
{
	struct dso *dso_l = map_l ? map__dso(map_l) : NULL;
	struct dso *dso_r = map_r ? map__dso(map_r) : NULL;
	const char *dso_name_l, *dso_name_r;

	if (!dso_l || !dso_r)
		return cmp_null(dso_r, dso_l);

	if (verbose > 0) {
		dso_name_l = dso_l->long_name;
		dso_name_r = dso_r->long_name;
	} else {
		dso_name_l = dso_l->short_name;
		dso_name_r = dso_r->short_name;
	}

	return strcmp(dso_name_l, dso_name_r);
}

static int64_t
sort__dso_cmp(struct hist_entry *left, struct hist_entry *right)
{
	return _sort__dso_cmp(right->ms.map, left->ms.map);
}

static int _hist_entry__dso_snprintf(struct map *map, char *bf,
				     size_t size, unsigned int width)
{
	const struct dso *dso = map ? map__dso(map) : NULL;
	const char *dso_name = "[unknown]";

	if (dso)
		dso_name = verbose > 0 ? dso->long_name : dso->short_name;

	return repsep_snprintf(bf, size, "%-*.*s", width, width, dso_name);
}

static int hist_entry__dso_snprintf(struct hist_entry *he, char *bf,
				    size_t size, unsigned int width)
{
	return _hist_entry__dso_snprintf(he->ms.map, bf, size, width);
}

static int hist_entry__dso_filter(struct hist_entry *he, int type, const void *arg)
{
	const struct dso *dso = arg;

	if (type != HIST_FILTER__DSO)
		return -1;

	return dso && (!he->ms.map || map__dso(he->ms.map) != dso);
}

struct sort_entry sort_dso = {
	.se_header	= "Shared Object",
	.se_cmp		= sort__dso_cmp,
	.se_snprintf	= hist_entry__dso_snprintf,
	.se_filter	= hist_entry__dso_filter,
	.se_width_idx	= HISTC_DSO,
};

/* --sort symbol */

static int64_t _sort__addr_cmp(u64 left_ip, u64 right_ip)
{
	return (int64_t)(right_ip - left_ip);
}

int64_t _sort__sym_cmp(struct symbol *sym_l, struct symbol *sym_r)
{
	if (!sym_l || !sym_r)
		return cmp_null(sym_l, sym_r);

	if (sym_l == sym_r)
		return 0;

	if (sym_l->inlined || sym_r->inlined) {
		int ret = strcmp(sym_l->name, sym_r->name);

		if (ret)
			return ret;
		if ((sym_l->start <= sym_r->end) && (sym_l->end >= sym_r->start))
			return 0;
	}

	if (sym_l->start != sym_r->start)
		return (int64_t)(sym_r->start - sym_l->start);

	return (int64_t)(sym_r->end - sym_l->end);
}

static int64_t
sort__sym_cmp(struct hist_entry *left, struct hist_entry *right)
{
	int64_t ret;

	if (!left->ms.sym && !right->ms.sym)
		return _sort__addr_cmp(left->ip, right->ip);

	/*
	 * comparing symbol address alone is not enough since it's a
	 * relative address within a dso.
	 */
	if (!hists__has(left->hists, dso)) {
		ret = sort__dso_cmp(left, right);
		if (ret != 0)
			return ret;
	}

	return _sort__sym_cmp(left->ms.sym, right->ms.sym);
}

static int64_t
sort__sym_sort(struct hist_entry *left, struct hist_entry *right)
{
	if (!left->ms.sym || !right->ms.sym)
		return cmp_null(left->ms.sym, right->ms.sym);

	return strcmp(right->ms.sym->name, left->ms.sym->name);
}

static int _hist_entry__sym_snprintf(struct map_symbol *ms,
				     u64 ip, char level, char *bf, size_t size,
				     unsigned int width)
{
	struct symbol *sym = ms->sym;
	struct map *map = ms->map;
	size_t ret = 0;

	if (verbose > 0) {
		struct dso *dso = map ? map__dso(map) : NULL;
		char o = dso ? dso__symtab_origin(dso) : '!';
		u64 rip = ip;

		if (dso && dso->kernel && dso->adjust_symbols)
			rip = map__unmap_ip(map, ip);

		ret += repsep_snprintf(bf, size, "%-#*llx %c ",
				       BITS_PER_LONG / 4 + 2, rip, o);
	}

	ret += repsep_snprintf(bf + ret, size - ret, "[%c] ", level);
	if (sym && map) {
		if (sym->type == STT_OBJECT) {
			ret += repsep_snprintf(bf + ret, size - ret, "%s", sym->name);
			ret += repsep_snprintf(bf + ret, size - ret, "+0x%llx",
					ip - map__unmap_ip(map, sym->start));
		} else {
			ret += repsep_snprintf(bf + ret, size - ret, "%.*s",
					       width - ret,
					       sym->name);
			if (sym->inlined)
				ret += repsep_snprintf(bf + ret, size - ret,
						       " (inlined)");
		}
	} else {
		size_t len = BITS_PER_LONG / 4;
		ret += repsep_snprintf(bf + ret, size - ret, "%-#.*llx",
				       len, ip);
	}

	return ret;
}

int hist_entry__sym_snprintf(struct hist_entry *he, char *bf, size_t size, unsigned int width)
{
	return _hist_entry__sym_snprintf(&he->ms, he->ip,
					 he->level, bf, size, width);
}

static int hist_entry__sym_filter(struct hist_entry *he, int type, const void *arg)
{
	const char *sym = arg;

	if (type != HIST_FILTER__SYMBOL)
		return -1;

	return sym && (!he->ms.sym || !strstr(he->ms.sym->name, sym));
}

struct sort_entry sort_sym = {
	.se_header	= "Symbol",
	.se_cmp		= sort__sym_cmp,
	.se_sort	= sort__sym_sort,
	.se_snprintf	= hist_entry__sym_snprintf,
	.se_filter	= hist_entry__sym_filter,
	.se_width_idx	= HISTC_SYMBOL,
};

/* --sort srcline */

char *hist_entry__srcline(struct hist_entry *he)
{
	return map__srcline(he->ms.map, he->ip, he->ms.sym);
}

static int64_t
sort__srcline_cmp(struct hist_entry *left, struct hist_entry *right)
{
	int64_t ret;

	ret = _sort__addr_cmp(left->ip, right->ip);
	if (ret)
		return ret;

	return sort__dso_cmp(left, right);
}

static int64_t
sort__srcline_collapse(struct hist_entry *left, struct hist_entry *right)
{
	if (!left->srcline)
		left->srcline = hist_entry__srcline(left);
	if (!right->srcline)
		right->srcline = hist_entry__srcline(right);

	return strcmp(right->srcline, left->srcline);
}

static int64_t
sort__srcline_sort(struct hist_entry *left, struct hist_entry *right)
{
	return sort__srcline_collapse(left, right);
}

static void
sort__srcline_init(struct hist_entry *he)
{
	if (!he->srcline)
		he->srcline = hist_entry__srcline(he);
}

static int hist_entry__srcline_snprintf(struct hist_entry *he, char *bf,
					size_t size, unsigned int width)
{
	return repsep_snprintf(bf, size, "%-.*s", width, he->srcline);
}

struct sort_entry sort_srcline = {
	.se_header	= "Source:Line",
	.se_cmp		= sort__srcline_cmp,
	.se_collapse	= sort__srcline_collapse,
	.se_sort	= sort__srcline_sort,
	.se_init	= sort__srcline_init,
	.se_snprintf	= hist_entry__srcline_snprintf,
	.se_width_idx	= HISTC_SRCLINE,
};

/* --sort srcline_from */

static char *addr_map_symbol__srcline(struct addr_map_symbol *ams)
{
	return map__srcline(ams->ms.map, ams->al_addr, ams->ms.sym);
}

static int64_t
sort__srcline_from_cmp(struct hist_entry *left, struct hist_entry *right)
{
	return left->branch_info->from.addr - right->branch_info->from.addr;
}

static int64_t
sort__srcline_from_collapse(struct hist_entry *left, struct hist_entry *right)
{
	if (!left->branch_info->srcline_from)
		left->branch_info->srcline_from = addr_map_symbol__srcline(&left->branch_info->from);

	if (!right->branch_info->srcline_from)
		right->branch_info->srcline_from = addr_map_symbol__srcline(&right->branch_info->from);

	return strcmp(right->branch_info->srcline_from, left->branch_info->srcline_from);
}

static int64_t
sort__srcline_from_sort(struct hist_entry *left, struct hist_entry *right)
{
	return sort__srcline_from_collapse(left, right);
}

static void sort__srcline_from_init(struct hist_entry *he)
{
	if (!he->branch_info->srcline_from)
		he->branch_info->srcline_from = addr_map_symbol__srcline(&he->branch_info->from);
}

static int hist_entry__srcline_from_snprintf(struct hist_entry *he, char *bf,
					size_t size, unsigned int width)
{
	return repsep_snprintf(bf, size, "%-*.*s", width, width, he->branch_info->srcline_from);
}

struct sort_entry sort_srcline_from = {
	.se_header	= "From Source:Line",
	.se_cmp		= sort__srcline_from_cmp,
	.se_collapse	= sort__srcline_from_collapse,
	.se_sort	= sort__srcline_from_sort,
	.se_init	= sort__srcline_from_init,
	.se_snprintf	= hist_entry__srcline_from_snprintf,
	.se_width_idx	= HISTC_SRCLINE_FROM,
};

/* --sort srcline_to */

static int64_t
sort__srcline_to_cmp(struct hist_entry *left, struct hist_entry *right)
{
	return left->branch_info->to.addr - right->branch_info->to.addr;
}

static int64_t
sort__srcline_to_collapse(struct hist_entry *left, struct hist_entry *right)
{
	if (!left->branch_info->srcline_to)
		left->branch_info->srcline_to = addr_map_symbol__srcline(&left->branch_info->to);

	if (!right->branch_info->srcline_to)
		right->branch_info->srcline_to = addr_map_symbol__srcline(&right->branch_info->to);

	return strcmp(right->branch_info->srcline_to, left->branch_info->srcline_to);
}

static int64_t
sort__srcline_to_sort(struct hist_entry *left, struct hist_entry *right)
{
	return sort__srcline_to_collapse(left, right);
}

static void sort__srcline_to_init(struct hist_entry *he)
{
	if (!he->branch_info->srcline_to)
		he->branch_info->srcline_to = addr_map_symbol__srcline(&he->branch_info->to);
}

static int hist_entry__srcline_to_snprintf(struct hist_entry *he, char *bf,
					size_t size, unsigned int width)
{
	return repsep_snprintf(bf, size, "%-*.*s", width, width, he->branch_info->srcline_to);
}

struct sort_entry sort_srcline_to = {
	.se_header	= "To Source:Line",
	.se_cmp		= sort__srcline_to_cmp,
	.se_collapse	= sort__srcline_to_collapse,
	.se_sort	= sort__srcline_to_sort,
	.se_init	= sort__srcline_to_init,
	.se_snprintf	= hist_entry__srcline_to_snprintf,
	.se_width_idx	= HISTC_SRCLINE_TO,
};

static int hist_entry__sym_ipc_snprintf(struct hist_entry *he, char *bf,
					size_t size, unsigned int width)
{

	struct symbol *sym = he->ms.sym;
	struct annotated_branch *branch;
	double ipc = 0.0, coverage = 0.0;
	char tmp[64];

	if (!sym)
		return repsep_snprintf(bf, size, "%-*s", width, "-");

	branch = symbol__annotation(sym)->branch;

	if (branch && branch->hit_cycles)
		ipc = branch->hit_insn / ((double)branch->hit_cycles);

	if (branch && branch->total_insn) {
		coverage = branch->cover_insn * 100.0 /
			((double)branch->total_insn);
	}

	snprintf(tmp, sizeof(tmp), "%-5.2f [%5.1f%%]", ipc, coverage);
	return repsep_snprintf(bf, size, "%-*s", width, tmp);
}

struct sort_entry sort_sym_ipc = {
	.se_header	= "IPC   [IPC Coverage]",
	.se_cmp		= sort__sym_cmp,
	.se_snprintf	= hist_entry__sym_ipc_snprintf,
	.se_width_idx	= HISTC_SYMBOL_IPC,
};

static int hist_entry__sym_ipc_null_snprintf(struct hist_entry *he
					     __maybe_unused,
					     char *bf, size_t size,
					     unsigned int width)
{
	char tmp[64];

	snprintf(tmp, sizeof(tmp), "%-5s %2s", "-", "-");
	return repsep_snprintf(bf, size, "%-*s", width, tmp);
}

struct sort_entry sort_sym_ipc_null = {
	.se_header	= "IPC   [IPC Coverage]",
	.se_cmp		= sort__sym_cmp,
	.se_snprintf	= hist_entry__sym_ipc_null_snprintf,
	.se_width_idx	= HISTC_SYMBOL_IPC,
};

/* --sort srcfile */

static char no_srcfile[1];

static char *hist_entry__get_srcfile(struct hist_entry *e)
{
	char *sf, *p;
	struct map *map = e->ms.map;

	if (!map)
		return no_srcfile;

	sf = __get_srcline(map__dso(map), map__rip_2objdump(map, e->ip),
			 e->ms.sym, false, true, true, e->ip);
	if (sf == SRCLINE_UNKNOWN)
		return no_srcfile;
	p = strchr(sf, ':');
	if (p && *sf) {
		*p = 0;
		return sf;
	}
	free(sf);
	return no_srcfile;
}

static int64_t
sort__srcfile_cmp(struct hist_entry *left, struct hist_entry *right)
{
	return sort__srcline_cmp(left, right);
}

static int64_t
sort__srcfile_collapse(struct hist_entry *left, struct hist_entry *right)
{
	if (!left->srcfile)
		left->srcfile = hist_entry__get_srcfile(left);
	if (!right->srcfile)
		right->srcfile = hist_entry__get_srcfile(right);

	return strcmp(right->srcfile, left->srcfile);
}

static int64_t
sort__srcfile_sort(struct hist_entry *left, struct hist_entry *right)
{
	return sort__srcfile_collapse(left, right);
}

static void sort__srcfile_init(struct hist_entry *he)
{
	if (!he->srcfile)
		he->srcfile = hist_entry__get_srcfile(he);
}

static int hist_entry__srcfile_snprintf(struct hist_entry *he, char *bf,
					size_t size, unsigned int width)
{
	return repsep_snprintf(bf, size, "%-.*s", width, he->srcfile);
}

struct sort_entry sort_srcfile = {
	.se_header	= "Source File",
	.se_cmp		= sort__srcfile_cmp,
	.se_collapse	= sort__srcfile_collapse,
	.se_sort	= sort__srcfile_sort,
	.se_init	= sort__srcfile_init,
	.se_snprintf	= hist_entry__srcfile_snprintf,
	.se_width_idx	= HISTC_SRCFILE,
};

/* --sort parent */

static int64_t
sort__parent_cmp(struct hist_entry *left, struct hist_entry *right)
{
	struct symbol *sym_l = left->parent;
	struct symbol *sym_r = right->parent;

	if (!sym_l || !sym_r)
		return cmp_null(sym_l, sym_r);

	return strcmp(sym_r->name, sym_l->name);
}

static int hist_entry__parent_snprintf(struct hist_entry *he, char *bf,
				       size_t size, unsigned int width)
{
	return repsep_snprintf(bf, size, "%-*.*s", width, width,
			      he->parent ? he->parent->name : "[other]");
}

struct sort_entry sort_parent = {
	.se_header	= "Parent symbol",
	.se_cmp		= sort__parent_cmp,
	.se_snprintf	= hist_entry__parent_snprintf,
	.se_width_idx	= HISTC_PARENT,
};

/* --sort cpu */

static int64_t
sort__cpu_cmp(struct hist_entry *left, struct hist_entry *right)
{
	return right->cpu - left->cpu;
}

static int hist_entry__cpu_snprintf(struct hist_entry *he, char *bf,
				    size_t size, unsigned int width)
{
	return repsep_snprintf(bf, size, "%*.*d", width, width, he->cpu);
}

struct sort_entry sort_cpu = {
	.se_header      = "CPU",
	.se_cmp	        = sort__cpu_cmp,
	.se_snprintf    = hist_entry__cpu_snprintf,
	.se_width_idx	= HISTC_CPU,
};

/* --sort cgroup_id */

static int64_t _sort__cgroup_dev_cmp(u64 left_dev, u64 right_dev)
{
	return (int64_t)(right_dev - left_dev);
}

static int64_t _sort__cgroup_inode_cmp(u64 left_ino, u64 right_ino)
{
	return (int64_t)(right_ino - left_ino);
}

static int64_t
sort__cgroup_id_cmp(struct hist_entry *left, struct hist_entry *right)
{
	int64_t ret;

	ret = _sort__cgroup_dev_cmp(right->cgroup_id.dev, left->cgroup_id.dev);
	if (ret != 0)
		return ret;

	return _sort__cgroup_inode_cmp(right->cgroup_id.ino,
				       left->cgroup_id.ino);
}

static int hist_entry__cgroup_id_snprintf(struct hist_entry *he,
					  char *bf, size_t size,
					  unsigned int width __maybe_unused)
{
	return repsep_snprintf(bf, size, "%lu/0x%lx", he->cgroup_id.dev,
			       he->cgroup_id.ino);
}

struct sort_entry sort_cgroup_id = {
	.se_header      = "cgroup id (dev/inode)",
	.se_cmp	        = sort__cgroup_id_cmp,
	.se_snprintf    = hist_entry__cgroup_id_snprintf,
	.se_width_idx	= HISTC_CGROUP_ID,
};

/* --sort cgroup */

static int64_t
sort__cgroup_cmp(struct hist_entry *left, struct hist_entry *right)
{
	return right->cgroup - left->cgroup;
}

static int hist_entry__cgroup_snprintf(struct hist_entry *he,
				       char *bf, size_t size,
				       unsigned int width __maybe_unused)
{
	const char *cgrp_name = "N/A";

	if (he->cgroup) {
		struct cgroup *cgrp = cgroup__find(maps__machine(he->ms.maps)->env,
						   he->cgroup);
		if (cgrp != NULL)
			cgrp_name = cgrp->name;
		else
			cgrp_name = "unknown";
	}

	return repsep_snprintf(bf, size, "%s", cgrp_name);
}

struct sort_entry sort_cgroup = {
	.se_header      = "Cgroup",
	.se_cmp	        = sort__cgroup_cmp,
	.se_snprintf    = hist_entry__cgroup_snprintf,
	.se_width_idx	= HISTC_CGROUP,
};

/* --sort socket */

static int64_t
sort__socket_cmp(struct hist_entry *left, struct hist_entry *right)
{
	return right->socket - left->socket;
}

static int hist_entry__socket_snprintf(struct hist_entry *he, char *bf,
				    size_t size, unsigned int width)
{
	return repsep_snprintf(bf, size, "%*.*d", width, width-3, he->socket);
}

static int hist_entry__socket_filter(struct hist_entry *he, int type, const void *arg)
{
	int sk = *(const int *)arg;

	if (type != HIST_FILTER__SOCKET)
		return -1;

	return sk >= 0 && he->socket != sk;
}

struct sort_entry sort_socket = {
	.se_header      = "Socket",
	.se_cmp	        = sort__socket_cmp,
	.se_snprintf    = hist_entry__socket_snprintf,
	.se_filter      = hist_entry__socket_filter,
	.se_width_idx	= HISTC_SOCKET,
};

/* --sort time */

static int64_t
sort__time_cmp(struct hist_entry *left, struct hist_entry *right)
{
	return right->time - left->time;
}

static int hist_entry__time_snprintf(struct hist_entry *he, char *bf,
				    size_t size, unsigned int width)
{
	char he_time[32];

	if (symbol_conf.nanosecs)
		timestamp__scnprintf_nsec(he->time, he_time,
					  sizeof(he_time));
	else
		timestamp__scnprintf_usec(he->time, he_time,
					  sizeof(he_time));

	return repsep_snprintf(bf, size, "%-.*s", width, he_time);
}

struct sort_entry sort_time = {
	.se_header      = "Time",
	.se_cmp	        = sort__time_cmp,
	.se_snprintf    = hist_entry__time_snprintf,
	.se_width_idx	= HISTC_TIME,
};

/* --sort trace */

#ifdef HAVE_LIBTRACEEVENT
static char *get_trace_output(struct hist_entry *he)
{
	struct trace_seq seq;
	struct evsel *evsel;
	struct tep_record rec = {
		.data = he->raw_data,
		.size = he->raw_size,
	};

	evsel = hists_to_evsel(he->hists);

	trace_seq_init(&seq);
	if (symbol_conf.raw_trace) {
		tep_print_fields(&seq, he->raw_data, he->raw_size,
				 evsel->tp_format);
	} else {
		tep_print_event(evsel->tp_format->tep,
				&seq, &rec, "%s", TEP_PRINT_INFO);
	}
	/*
	 * Trim the buffer, it starts at 4KB and we're not going to
	 * add anything more to this buffer.
	 */
	return realloc(seq.buffer, seq.len + 1);
}

static int64_t
sort__trace_cmp(struct hist_entry *left, struct hist_entry *right)
{
	struct evsel *evsel;

	evsel = hists_to_evsel(left->hists);
	if (evsel->core.attr.type != PERF_TYPE_TRACEPOINT)
		return 0;

	if (left->trace_output == NULL)
		left->trace_output = get_trace_output(left);
	if (right->trace_output == NULL)
		right->trace_output = get_trace_output(right);

	return strcmp(right->trace_output, left->trace_output);
}

static int hist_entry__trace_snprintf(struct hist_entry *he, char *bf,
				    size_t size, unsigned int width)
{
	struct evsel *evsel;

	evsel = hists_to_evsel(he->hists);
	if (evsel->core.attr.type != PERF_TYPE_TRACEPOINT)
		return scnprintf(bf, size, "%-.*s", width, "N/A");

	if (he->trace_output == NULL)
		he->trace_output = get_trace_output(he);
	return repsep_snprintf(bf, size, "%-.*s", width, he->trace_output);
}

struct sort_entry sort_trace = {
	.se_header      = "Trace output",
	.se_cmp	        = sort__trace_cmp,
	.se_snprintf    = hist_entry__trace_snprintf,
	.se_width_idx	= HISTC_TRACE,
};
#endif /* HAVE_LIBTRACEEVENT */

/* sort keys for branch stacks */

static int64_t
sort__dso_from_cmp(struct hist_entry *left, struct hist_entry *right)
{
	if (!left->branch_info || !right->branch_info)
		return cmp_null(left->branch_info, right->branch_info);

	return _sort__dso_cmp(left->branch_info->from.ms.map,
			      right->branch_info->from.ms.map);
}

static int hist_entry__dso_from_snprintf(struct hist_entry *he, char *bf,
				    size_t size, unsigned int width)
{
	if (he->branch_info)
		return _hist_entry__dso_snprintf(he->branch_info->from.ms.map,
						 bf, size, width);
	else
		return repsep_snprintf(bf, size, "%-*.*s", width, width, "N/A");
}

static int hist_entry__dso_from_filter(struct hist_entry *he, int type,
				       const void *arg)
{
	const struct dso *dso = arg;

	if (type != HIST_FILTER__DSO)
		return -1;

	return dso && (!he->branch_info || !he->branch_info->from.ms.map ||
		map__dso(he->branch_info->from.ms.map) != dso);
}

static int64_t
sort__dso_to_cmp(struct hist_entry *left, struct hist_entry *right)
{
	if (!left->branch_info || !right->branch_info)
		return cmp_null(left->branch_info, right->branch_info);

	return _sort__dso_cmp(left->branch_info->to.ms.map,
			      right->branch_info->to.ms.map);
}

static int hist_entry__dso_to_snprintf(struct hist_entry *he, char *bf,
				       size_t size, unsigned int width)
{
	if (he->branch_info)
		return _hist_entry__dso_snprintf(he->branch_info->to.ms.map,
						 bf, size, width);
	else
		return repsep_snprintf(bf, size, "%-*.*s", width, width, "N/A");
}

static int hist_entry__dso_to_filter(struct hist_entry *he, int type,
				     const void *arg)
{
	const struct dso *dso = arg;

	if (type != HIST_FILTER__DSO)
		return -1;

	return dso && (!he->branch_info || !he->branch_info->to.ms.map ||
		map__dso(he->branch_info->to.ms.map) != dso);
}

static int64_t
sort__sym_from_cmp(struct hist_entry *left, struct hist_entry *right)
{
	struct addr_map_symbol *from_l, *from_r;

	if (!left->branch_info || !right->branch_info)
		return cmp_null(left->branch_info, right->branch_info);

	from_l = &left->branch_info->from;
	from_r = &right->branch_info->from;

	if (!from_l->ms.sym && !from_r->ms.sym)
		return _sort__addr_cmp(from_l->addr, from_r->addr);

	return _sort__sym_cmp(from_l->ms.sym, from_r->ms.sym);
}

static int64_t
sort__sym_to_cmp(struct hist_entry *left, struct hist_entry *right)
{
	struct addr_map_symbol *to_l, *to_r;

	if (!left->branch_info || !right->branch_info)
		return cmp_null(left->branch_info, right->branch_info);

	to_l = &left->branch_info->to;
	to_r = &right->branch_info->to;

	if (!to_l->ms.sym && !to_r->ms.sym)
		return _sort__addr_cmp(to_l->addr, to_r->addr);

	return _sort__sym_cmp(to_l->ms.sym, to_r->ms.sym);
}

static int hist_entry__sym_from_snprintf(struct hist_entry *he, char *bf,
					 size_t size, unsigned int width)
{
	if (he->branch_info) {
		struct addr_map_symbol *from = &he->branch_info->from;

		return _hist_entry__sym_snprintf(&from->ms, from->al_addr,
						 from->al_level, bf, size, width);
	}

	return repsep_snprintf(bf, size, "%-*.*s", width, width, "N/A");
}

static int hist_entry__sym_to_snprintf(struct hist_entry *he, char *bf,
				       size_t size, unsigned int width)
{
	if (he->branch_info) {
		struct addr_map_symbol *to = &he->branch_info->to;

		return _hist_entry__sym_snprintf(&to->ms, to->al_addr,
						 to->al_level, bf, size, width);
	}

	return repsep_snprintf(bf, size, "%-*.*s", width, width, "N/A");
}

static int hist_entry__sym_from_filter(struct hist_entry *he, int type,
				       const void *arg)
{
	const char *sym = arg;

	if (type != HIST_FILTER__SYMBOL)
		return -1;

	return sym && !(he->branch_info && he->branch_info->from.ms.sym &&
			strstr(he->branch_info->from.ms.sym->name, sym));
}

static int hist_entry__sym_to_filter(struct hist_entry *he, int type,
				       const void *arg)
{
	const char *sym = arg;

	if (type != HIST_FILTER__SYMBOL)
		return -1;

	return sym && !(he->branch_info && he->branch_info->to.ms.sym &&
		        strstr(he->branch_info->to.ms.sym->name, sym));
}

struct sort_entry sort_dso_from = {
	.se_header	= "Source Shared Object",
	.se_cmp		= sort__dso_from_cmp,
	.se_snprintf	= hist_entry__dso_from_snprintf,
	.se_filter	= hist_entry__dso_from_filter,
	.se_width_idx	= HISTC_DSO_FROM,
};

struct sort_entry sort_dso_to = {
	.se_header	= "Target Shared Object",
	.se_cmp		= sort__dso_to_cmp,
	.se_snprintf	= hist_entry__dso_to_snprintf,
	.se_filter	= hist_entry__dso_to_filter,
	.se_width_idx	= HISTC_DSO_TO,
};

struct sort_entry sort_sym_from = {
	.se_header	= "Source Symbol",
	.se_cmp		= sort__sym_from_cmp,
	.se_snprintf	= hist_entry__sym_from_snprintf,
	.se_filter	= hist_entry__sym_from_filter,
	.se_width_idx	= HISTC_SYMBOL_FROM,
};

struct sort_entry sort_sym_to = {
	.se_header	= "Target Symbol",
	.se_cmp		= sort__sym_to_cmp,
	.se_snprintf	= hist_entry__sym_to_snprintf,
	.se_filter	= hist_entry__sym_to_filter,
	.se_width_idx	= HISTC_SYMBOL_TO,
};

static int _hist_entry__addr_snprintf(struct map_symbol *ms,
				     u64 ip, char level, char *bf, size_t size,
				     unsigned int width)
{
	struct symbol *sym = ms->sym;
	struct map *map = ms->map;
	size_t ret = 0, offs;

	ret += repsep_snprintf(bf + ret, size - ret, "[%c] ", level);
	if (sym && map) {
		if (sym->type == STT_OBJECT) {
			ret += repsep_snprintf(bf + ret, size - ret, "%s", sym->name);
			ret += repsep_snprintf(bf + ret, size - ret, "+0x%llx",
					ip - map__unmap_ip(map, sym->start));
		} else {
			ret += repsep_snprintf(bf + ret, size - ret, "%.*s",
					       width - ret,
					       sym->name);
			offs = ip - sym->start;
			if (offs)
				ret += repsep_snprintf(bf + ret, size - ret, "+0x%llx", offs);
		}
	} else {
		size_t len = BITS_PER_LONG / 4;
		ret += repsep_snprintf(bf + ret, size - ret, "%-#.*llx",
				       len, ip);
	}

	return ret;
}

static int hist_entry__addr_from_snprintf(struct hist_entry *he, char *bf,
					 size_t size, unsigned int width)
{
	if (he->branch_info) {
		struct addr_map_symbol *from = &he->branch_info->from;

		return _hist_entry__addr_snprintf(&from->ms, from->al_addr,
						 he->level, bf, size, width);
	}

	return repsep_snprintf(bf, size, "%-*.*s", width, width, "N/A");
}

static int hist_entry__addr_to_snprintf(struct hist_entry *he, char *bf,
				       size_t size, unsigned int width)
{
	if (he->branch_info) {
		struct addr_map_symbol *to = &he->branch_info->to;

		return _hist_entry__addr_snprintf(&to->ms, to->al_addr,
						 he->level, bf, size, width);
	}

	return repsep_snprintf(bf, size, "%-*.*s", width, width, "N/A");
}

static int64_t
sort__addr_from_cmp(struct hist_entry *left, struct hist_entry *right)
{
	struct addr_map_symbol *from_l;
	struct addr_map_symbol *from_r;
	int64_t ret;

	if (!left->branch_info || !right->branch_info)
		return cmp_null(left->branch_info, right->branch_info);

	from_l = &left->branch_info->from;
	from_r = &right->branch_info->from;

	/*
	 * comparing symbol address alone is not enough since it's a
	 * relative address within a dso.
	 */
	ret = _sort__dso_cmp(from_l->ms.map, from_r->ms.map);
	if (ret != 0)
		return ret;

	return _sort__addr_cmp(from_l->addr, from_r->addr);
}

static int64_t
sort__addr_to_cmp(struct hist_entry *left, struct hist_entry *right)
{
	struct addr_map_symbol *to_l;
	struct addr_map_symbol *to_r;
	int64_t ret;

	if (!left->branch_info || !right->branch_info)
		return cmp_null(left->branch_info, right->branch_info);

	to_l = &left->branch_info->to;
	to_r = &right->branch_info->to;

	/*
	 * comparing symbol address alone is not enough since it's a
	 * relative address within a dso.
	 */
	ret = _sort__dso_cmp(to_l->ms.map, to_r->ms.map);
	if (ret != 0)
		return ret;

	return _sort__addr_cmp(to_l->addr, to_r->addr);
}

struct sort_entry sort_addr_from = {
	.se_header	= "Source Address",
	.se_cmp		= sort__addr_from_cmp,
	.se_snprintf	= hist_entry__addr_from_snprintf,
	.se_filter	= hist_entry__sym_from_filter, /* shared with sym_from */
	.se_width_idx	= HISTC_ADDR_FROM,
};

struct sort_entry sort_addr_to = {
	.se_header	= "Target Address",
	.se_cmp		= sort__addr_to_cmp,
	.se_snprintf	= hist_entry__addr_to_snprintf,
	.se_filter	= hist_entry__sym_to_filter, /* shared with sym_to */
	.se_width_idx	= HISTC_ADDR_TO,
};


static int64_t
sort__mispredict_cmp(struct hist_entry *left, struct hist_entry *right)
{
	unsigned char mp, p;

	if (!left->branch_info || !right->branch_info)
		return cmp_null(left->branch_info, right->branch_info);

	mp = left->branch_info->flags.mispred != right->branch_info->flags.mispred;
	p  = left->branch_info->flags.predicted != right->branch_info->flags.predicted;
	return mp || p;
}

static int hist_entry__mispredict_snprintf(struct hist_entry *he, char *bf,
				    size_t size, unsigned int width){
	static const char *out = "N/A";

	if (he->branch_info) {
		if (he->branch_info->flags.predicted)
			out = "N";
		else if (he->branch_info->flags.mispred)
			out = "Y";
	}

	return repsep_snprintf(bf, size, "%-*.*s", width, width, out);
}

static int64_t
sort__cycles_cmp(struct hist_entry *left, struct hist_entry *right)
{
	if (!left->branch_info || !right->branch_info)
		return cmp_null(left->branch_info, right->branch_info);

	return left->branch_info->flags.cycles -
		right->branch_info->flags.cycles;
}

static int hist_entry__cycles_snprintf(struct hist_entry *he, char *bf,
				    size_t size, unsigned int width)
{
	if (!he->branch_info)
		return scnprintf(bf, size, "%-.*s", width, "N/A");
	if (he->branch_info->flags.cycles == 0)
		return repsep_snprintf(bf, size, "%-*s", width, "-");
	return repsep_snprintf(bf, size, "%-*hd", width,
			       he->branch_info->flags.cycles);
}

struct sort_entry sort_cycles = {
	.se_header	= "Basic Block Cycles",
	.se_cmp		= sort__cycles_cmp,
	.se_snprintf	= hist_entry__cycles_snprintf,
	.se_width_idx	= HISTC_CYCLES,
};

/* --sort daddr_sym */
int64_t
sort__daddr_cmp(struct hist_entry *left, struct hist_entry *right)
{
	uint64_t l = 0, r = 0;

	if (left->mem_info)
		l = left->mem_info->daddr.addr;
	if (right->mem_info)
		r = right->mem_info->daddr.addr;

	return (int64_t)(r - l);
}

static int hist_entry__daddr_snprintf(struct hist_entry *he, char *bf,
				    size_t size, unsigned int width)
{
	uint64_t addr = 0;
	struct map_symbol *ms = NULL;

	if (he->mem_info) {
		addr = he->mem_info->daddr.addr;
		ms = &he->mem_info->daddr.ms;
	}
	return _hist_entry__sym_snprintf(ms, addr, he->level, bf, size, width);
}

int64_t
sort__iaddr_cmp(struct hist_entry *left, struct hist_entry *right)
{
	uint64_t l = 0, r = 0;

	if (left->mem_info)
		l = left->mem_info->iaddr.addr;
	if (right->mem_info)
		r = right->mem_info->iaddr.addr;

	return (int64_t)(r - l);
}

static int hist_entry__iaddr_snprintf(struct hist_entry *he, char *bf,
				    size_t size, unsigned int width)
{
	uint64_t addr = 0;
	struct map_symbol *ms = NULL;

	if (he->mem_info) {
		addr = he->mem_info->iaddr.addr;
		ms   = &he->mem_info->iaddr.ms;
	}
	return _hist_entry__sym_snprintf(ms, addr, he->level, bf, size, width);
}

static int64_t
sort__dso_daddr_cmp(struct hist_entry *left, struct hist_entry *right)
{
	struct map *map_l = NULL;
	struct map *map_r = NULL;

	if (left->mem_info)
		map_l = left->mem_info->daddr.ms.map;
	if (right->mem_info)
		map_r = right->mem_info->daddr.ms.map;

	return _sort__dso_cmp(map_l, map_r);
}

static int hist_entry__dso_daddr_snprintf(struct hist_entry *he, char *bf,
				    size_t size, unsigned int width)
{
	struct map *map = NULL;

	if (he->mem_info)
		map = he->mem_info->daddr.ms.map;

	return _hist_entry__dso_snprintf(map, bf, size, width);
}

static int64_t
sort__locked_cmp(struct hist_entry *left, struct hist_entry *right)
{
	union perf_mem_data_src data_src_l;
	union perf_mem_data_src data_src_r;

	if (left->mem_info)
		data_src_l = left->mem_info->data_src;
	else
		data_src_l.mem_lock = PERF_MEM_LOCK_NA;

	if (right->mem_info)
		data_src_r = right->mem_info->data_src;
	else
		data_src_r.mem_lock = PERF_MEM_LOCK_NA;

	return (int64_t)(data_src_r.mem_lock - data_src_l.mem_lock);
}

static int hist_entry__locked_snprintf(struct hist_entry *he, char *bf,
				    size_t size, unsigned int width)
{
	char out[10];

	perf_mem__lck_scnprintf(out, sizeof(out), he->mem_info);
	return repsep_snprintf(bf, size, "%.*s", width, out);
}

static int64_t
sort__tlb_cmp(struct hist_entry *left, struct hist_entry *right)
{
	union perf_mem_data_src data_src_l;
	union perf_mem_data_src data_src_r;

	if (left->mem_info)
		data_src_l = left->mem_info->data_src;
	else
		data_src_l.mem_dtlb = PERF_MEM_TLB_NA;

	if (right->mem_info)
		data_src_r = right->mem_info->data_src;
	else
		data_src_r.mem_dtlb = PERF_MEM_TLB_NA;

	return (int64_t)(data_src_r.mem_dtlb - data_src_l.mem_dtlb);
}

static int hist_entry__tlb_snprintf(struct hist_entry *he, char *bf,
				    size_t size, unsigned int width)
{
	char out[64];

	perf_mem__tlb_scnprintf(out, sizeof(out), he->mem_info);
	return repsep_snprintf(bf, size, "%-*s", width, out);
}

static int64_t
sort__lvl_cmp(struct hist_entry *left, struct hist_entry *right)
{
	union perf_mem_data_src data_src_l;
	union perf_mem_data_src data_src_r;

	if (left->mem_info)
		data_src_l = left->mem_info->data_src;
	else
		data_src_l.mem_lvl = PERF_MEM_LVL_NA;

	if (right->mem_info)
		data_src_r = right->mem_info->data_src;
	else
		data_src_r.mem_lvl = PERF_MEM_LVL_NA;

	return (int64_t)(data_src_r.mem_lvl - data_src_l.mem_lvl);
}

static int hist_entry__lvl_snprintf(struct hist_entry *he, char *bf,
				    size_t size, unsigned int width)
{
	char out[64];

	perf_mem__lvl_scnprintf(out, sizeof(out), he->mem_info);
	return repsep_snprintf(bf, size, "%-*s", width, out);
}

static int64_t
sort__snoop_cmp(struct hist_entry *left, struct hist_entry *right)
{
	union perf_mem_data_src data_src_l;
	union perf_mem_data_src data_src_r;

	if (left->mem_info)
		data_src_l = left->mem_info->data_src;
	else
		data_src_l.mem_snoop = PERF_MEM_SNOOP_NA;

	if (right->mem_info)
		data_src_r = right->mem_info->data_src;
	else
		data_src_r.mem_snoop = PERF_MEM_SNOOP_NA;

	return (int64_t)(data_src_r.mem_snoop - data_src_l.mem_snoop);
}

static int hist_entry__snoop_snprintf(struct hist_entry *he, char *bf,
				    size_t size, unsigned int width)
{
	char out[64];

	perf_mem__snp_scnprintf(out, sizeof(out), he->mem_info);
	return repsep_snprintf(bf, size, "%-*s", width, out);
}

int64_t
sort__dcacheline_cmp(struct hist_entry *left, struct hist_entry *right)
{
	u64 l, r;
	struct map *l_map, *r_map;
	struct dso *l_dso, *r_dso;
	int rc;

	if (!left->mem_info)  return -1;
	if (!right->mem_info) return 1;

	/* group event types together */
	if (left->cpumode > right->cpumode) return -1;
	if (left->cpumode < right->cpumode) return 1;

	l_map = left->mem_info->daddr.ms.map;
	r_map = right->mem_info->daddr.ms.map;

	/* if both are NULL, jump to sort on al_addr instead */
	if (!l_map && !r_map)
		goto addr;

	if (!l_map) return -1;
	if (!r_map) return 1;

	l_dso = map__dso(l_map);
	r_dso = map__dso(r_map);
	rc = dso__cmp_id(l_dso, r_dso);
	if (rc)
		return rc;
	/*
	 * Addresses with no major/minor numbers are assumed to be
	 * anonymous in userspace.  Sort those on pid then address.
	 *
	 * The kernel and non-zero major/minor mapped areas are
	 * assumed to be unity mapped.  Sort those on address.
	 */

	if ((left->cpumode != PERF_RECORD_MISC_KERNEL) &&
	    (!(map__flags(l_map) & MAP_SHARED)) && !l_dso->id.maj && !l_dso->id.min &&
	    !l_dso->id.ino && !l_dso->id.ino_generation) {
		/* userspace anonymous */

		if (thread__pid(left->thread) > thread__pid(right->thread))
			return -1;
		if (thread__pid(left->thread) < thread__pid(right->thread))
			return 1;
	}

addr:
	/* al_addr does all the right addr - start + offset calculations */
	l = cl_address(left->mem_info->daddr.al_addr, chk_double_cl);
	r = cl_address(right->mem_info->daddr.al_addr, chk_double_cl);

	if (l > r) return -1;
	if (l < r) return 1;

	return 0;
}

static int hist_entry__dcacheline_snprintf(struct hist_entry *he, char *bf,
					  size_t size, unsigned int width)
{

	uint64_t addr = 0;
	struct map_symbol *ms = NULL;
	char level = he->level;

	if (he->mem_info) {
		struct map *map = he->mem_info->daddr.ms.map;
		struct dso *dso = map ? map__dso(map) : NULL;

		addr = cl_address(he->mem_info->daddr.al_addr, chk_double_cl);
		ms = &he->mem_info->daddr.ms;

		/* print [s] for shared data mmaps */
		if ((he->cpumode != PERF_RECORD_MISC_KERNEL) &&
		     map && !(map__prot(map) & PROT_EXEC) &&
		     (map__flags(map) & MAP_SHARED) &&
		    (dso->id.maj || dso->id.min || dso->id.ino || dso->id.ino_generation))
			level = 's';
		else if (!map)
			level = 'X';
	}
	return _hist_entry__sym_snprintf(ms, addr, level, bf, size, width);
}

struct sort_entry sort_mispredict = {
	.se_header	= "Branch Mispredicted",
	.se_cmp		= sort__mispredict_cmp,
	.se_snprintf	= hist_entry__mispredict_snprintf,
	.se_width_idx	= HISTC_MISPREDICT,
};

static int64_t
sort__weight_cmp(struct hist_entry *left, struct hist_entry *right)
{
	return left->weight - right->weight;
}

static int hist_entry__local_weight_snprintf(struct hist_entry *he, char *bf,
				    size_t size, unsigned int width)
{
	return repsep_snprintf(bf, size, "%-*llu", width, he->weight);
}

struct sort_entry sort_local_weight = {
	.se_header	= "Local Weight",
	.se_cmp		= sort__weight_cmp,
	.se_snprintf	= hist_entry__local_weight_snprintf,
	.se_width_idx	= HISTC_LOCAL_WEIGHT,
};

static int hist_entry__global_weight_snprintf(struct hist_entry *he, char *bf,
					      size_t size, unsigned int width)
{
	return repsep_snprintf(bf, size, "%-*llu", width,
			       he->weight * he->stat.nr_events);
}

struct sort_entry sort_global_weight = {
	.se_header	= "Weight",
	.se_cmp		= sort__weight_cmp,
	.se_snprintf	= hist_entry__global_weight_snprintf,
	.se_width_idx	= HISTC_GLOBAL_WEIGHT,
};

static int64_t
sort__ins_lat_cmp(struct hist_entry *left, struct hist_entry *right)
{
	return left->ins_lat - right->ins_lat;
}

static int hist_entry__local_ins_lat_snprintf(struct hist_entry *he, char *bf,
					      size_t size, unsigned int width)
{
	return repsep_snprintf(bf, size, "%-*u", width, he->ins_lat);
}

struct sort_entry sort_local_ins_lat = {
	.se_header	= "Local INSTR Latency",
	.se_cmp		= sort__ins_lat_cmp,
	.se_snprintf	= hist_entry__local_ins_lat_snprintf,
	.se_width_idx	= HISTC_LOCAL_INS_LAT,
};

static int hist_entry__global_ins_lat_snprintf(struct hist_entry *he, char *bf,
					       size_t size, unsigned int width)
{
	return repsep_snprintf(bf, size, "%-*u", width,
			       he->ins_lat * he->stat.nr_events);
}

struct sort_entry sort_global_ins_lat = {
	.se_header	= "INSTR Latency",
	.se_cmp		= sort__ins_lat_cmp,
	.se_snprintf	= hist_entry__global_ins_lat_snprintf,
	.se_width_idx	= HISTC_GLOBAL_INS_LAT,
};

static int64_t
sort__p_stage_cyc_cmp(struct hist_entry *left, struct hist_entry *right)
{
	return left->p_stage_cyc - right->p_stage_cyc;
}

static int hist_entry__global_p_stage_cyc_snprintf(struct hist_entry *he, char *bf,
					size_t size, unsigned int width)
{
	return repsep_snprintf(bf, size, "%-*u", width,
			he->p_stage_cyc * he->stat.nr_events);
}


static int hist_entry__p_stage_cyc_snprintf(struct hist_entry *he, char *bf,
					size_t size, unsigned int width)
{
	return repsep_snprintf(bf, size, "%-*u", width, he->p_stage_cyc);
}

struct sort_entry sort_local_p_stage_cyc = {
	.se_header      = "Local Pipeline Stage Cycle",
	.se_cmp         = sort__p_stage_cyc_cmp,
	.se_snprintf	= hist_entry__p_stage_cyc_snprintf,
	.se_width_idx	= HISTC_LOCAL_P_STAGE_CYC,
};

struct sort_entry sort_global_p_stage_cyc = {
	.se_header      = "Pipeline Stage Cycle",
	.se_cmp         = sort__p_stage_cyc_cmp,
	.se_snprintf    = hist_entry__global_p_stage_cyc_snprintf,
	.se_width_idx   = HISTC_GLOBAL_P_STAGE_CYC,
};

struct sort_entry sort_mem_daddr_sym = {
	.se_header	= "Data Symbol",
	.se_cmp		= sort__daddr_cmp,
	.se_snprintf	= hist_entry__daddr_snprintf,
	.se_width_idx	= HISTC_MEM_DADDR_SYMBOL,
};

struct sort_entry sort_mem_iaddr_sym = {
	.se_header	= "Code Symbol",
	.se_cmp		= sort__iaddr_cmp,
	.se_snprintf	= hist_entry__iaddr_snprintf,
	.se_width_idx	= HISTC_MEM_IADDR_SYMBOL,
};

struct sort_entry sort_mem_daddr_dso = {
	.se_header	= "Data Object",
	.se_cmp		= sort__dso_daddr_cmp,
	.se_snprintf	= hist_entry__dso_daddr_snprintf,
	.se_width_idx	= HISTC_MEM_DADDR_DSO,
};

struct sort_entry sort_mem_locked = {
	.se_header	= "Locked",
	.se_cmp		= sort__locked_cmp,
	.se_snprintf	= hist_entry__locked_snprintf,
	.se_width_idx	= HISTC_MEM_LOCKED,
};

struct sort_entry sort_mem_tlb = {
	.se_header	= "TLB access",
	.se_cmp		= sort__tlb_cmp,
	.se_snprintf	= hist_entry__tlb_snprintf,
	.se_width_idx	= HISTC_MEM_TLB,
};

struct sort_entry sort_mem_lvl = {
	.se_header	= "Memory access",
	.se_cmp		= sort__lvl_cmp,
	.se_snprintf	= hist_entry__lvl_snprintf,
	.se_width_idx	= HISTC_MEM_LVL,
};

struct sort_entry sort_mem_snoop = {
	.se_header	= "Snoop",
	.se_cmp		= sort__snoop_cmp,
	.se_snprintf	= hist_entry__snoop_snprintf,
	.se_width_idx	= HISTC_MEM_SNOOP,
};

struct sort_entry sort_mem_dcacheline = {
	.se_header	= "Data Cacheline",
	.se_cmp		= sort__dcacheline_cmp,
	.se_snprintf	= hist_entry__dcacheline_snprintf,
	.se_width_idx	= HISTC_MEM_DCACHELINE,
};

static int64_t
sort__blocked_cmp(struct hist_entry *left, struct hist_entry *right)
{
	union perf_mem_data_src data_src_l;
	union perf_mem_data_src data_src_r;

	if (left->mem_info)
		data_src_l = left->mem_info->data_src;
	else
		data_src_l.mem_blk = PERF_MEM_BLK_NA;

	if (right->mem_info)
		data_src_r = right->mem_info->data_src;
	else
		data_src_r.mem_blk = PERF_MEM_BLK_NA;

	return (int64_t)(data_src_r.mem_blk - data_src_l.mem_blk);
}

static int hist_entry__blocked_snprintf(struct hist_entry *he, char *bf,
					size_t size, unsigned int width)
{
	char out[16];

	perf_mem__blk_scnprintf(out, sizeof(out), he->mem_info);
	return repsep_snprintf(bf, size, "%.*s", width, out);
}

struct sort_entry sort_mem_blocked = {
	.se_header	= "Blocked",
	.se_cmp		= sort__blocked_cmp,
	.se_snprintf	= hist_entry__blocked_snprintf,
	.se_width_idx	= HISTC_MEM_BLOCKED,
};

static int64_t
sort__phys_daddr_cmp(struct hist_entry *left, struct hist_entry *right)
{
	uint64_t l = 0, r = 0;

	if (left->mem_info)
		l = left->mem_info->daddr.phys_addr;
	if (right->mem_info)
		r = right->mem_info->daddr.phys_addr;

	return (int64_t)(r - l);
}

static int hist_entry__phys_daddr_snprintf(struct hist_entry *he, char *bf,
					   size_t size, unsigned int width)
{
	uint64_t addr = 0;
	size_t ret = 0;
	size_t len = BITS_PER_LONG / 4;

	addr = he->mem_info->daddr.phys_addr;

	ret += repsep_snprintf(bf + ret, size - ret, "[%c] ", he->level);

	ret += repsep_snprintf(bf + ret, size - ret, "%-#.*llx", len, addr);

	ret += repsep_snprintf(bf + ret, size - ret, "%-*s", width - ret, "");

	if (ret > width)
		bf[width] = '\0';

	return width;
}

struct sort_entry sort_mem_phys_daddr = {
	.se_header	= "Data Physical Address",
	.se_cmp		= sort__phys_daddr_cmp,
	.se_snprintf	= hist_entry__phys_daddr_snprintf,
	.se_width_idx	= HISTC_MEM_PHYS_DADDR,
};

static int64_t
sort__data_page_size_cmp(struct hist_entry *left, struct hist_entry *right)
{
	uint64_t l = 0, r = 0;

	if (left->mem_info)
		l = left->mem_info->daddr.data_page_size;
	if (right->mem_info)
		r = right->mem_info->daddr.data_page_size;

	return (int64_t)(r - l);
}

static int hist_entry__data_page_size_snprintf(struct hist_entry *he, char *bf,
					  size_t size, unsigned int width)
{
	char str[PAGE_SIZE_NAME_LEN];

	return repsep_snprintf(bf, size, "%-*s", width,
			       get_page_size_name(he->mem_info->daddr.data_page_size, str));
}

struct sort_entry sort_mem_data_page_size = {
	.se_header	= "Data Page Size",
	.se_cmp		= sort__data_page_size_cmp,
	.se_snprintf	= hist_entry__data_page_size_snprintf,
	.se_width_idx	= HISTC_MEM_DATA_PAGE_SIZE,
};

static int64_t
sort__code_page_size_cmp(struct hist_entry *left, struct hist_entry *right)
{
	uint64_t l = left->code_page_size;
	uint64_t r = right->code_page_size;

	return (int64_t)(r - l);
}

static int hist_entry__code_page_size_snprintf(struct hist_entry *he, char *bf,
					  size_t size, unsigned int width)
{
	char str[PAGE_SIZE_NAME_LEN];

	return repsep_snprintf(bf, size, "%-*s", width,
			       get_page_size_name(he->code_page_size, str));
}

struct sort_entry sort_code_page_size = {
	.se_header	= "Code Page Size",
	.se_cmp		= sort__code_page_size_cmp,
	.se_snprintf	= hist_entry__code_page_size_snprintf,
	.se_width_idx	= HISTC_CODE_PAGE_SIZE,
};

static int64_t
sort__abort_cmp(struct hist_entry *left, struct hist_entry *right)
{
	if (!left->branch_info || !right->branch_info)
		return cmp_null(left->branch_info, right->branch_info);

	return left->branch_info->flags.abort !=
		right->branch_info->flags.abort;
}

static int hist_entry__abort_snprintf(struct hist_entry *he, char *bf,
				    size_t size, unsigned int width)
{
	static const char *out = "N/A";

	if (he->branch_info) {
		if (he->branch_info->flags.abort)
			out = "A";
		else
			out = ".";
	}

	return repsep_snprintf(bf, size, "%-*s", width, out);
}

struct sort_entry sort_abort = {
	.se_header	= "Transaction abort",
	.se_cmp		= sort__abort_cmp,
	.se_snprintf	= hist_entry__abort_snprintf,
	.se_width_idx	= HISTC_ABORT,
};

static int64_t
sort__in_tx_cmp(struct hist_entry *left, struct hist_entry *right)
{
	if (!left->branch_info || !right->branch_info)
		return cmp_null(left->branch_info, right->branch_info);

	return left->branch_info->flags.in_tx !=
		right->branch_info->flags.in_tx;
}

static int hist_entry__in_tx_snprintf(struct hist_entry *he, char *bf,
				    size_t size, unsigned int width)
{
	static const char *out = "N/A";

	if (he->branch_info) {
		if (he->branch_info->flags.in_tx)
			out = "T";
		else
			out = ".";
	}

	return repsep_snprintf(bf, size, "%-*s", width, out);
}

struct sort_entry sort_in_tx = {
	.se_header	= "Branch in transaction",
	.se_cmp		= sort__in_tx_cmp,
	.se_snprintf	= hist_entry__in_tx_snprintf,
	.se_width_idx	= HISTC_IN_TX,
};

static int64_t
sort__transaction_cmp(struct hist_entry *left, struct hist_entry *right)
{
	return left->transaction - right->transaction;
}

static inline char *add_str(char *p, const char *str)
{
	strcpy(p, str);
	return p + strlen(str);
}

static struct txbit {
	unsigned flag;
	const char *name;
	int skip_for_len;
} txbits[] = {
	{ PERF_TXN_ELISION,        "EL ",        0 },
	{ PERF_TXN_TRANSACTION,    "TX ",        1 },
	{ PERF_TXN_SYNC,           "SYNC ",      1 },
	{ PERF_TXN_ASYNC,          "ASYNC ",     0 },
	{ PERF_TXN_RETRY,          "RETRY ",     0 },
	{ PERF_TXN_CONFLICT,       "CON ",       0 },
	{ PERF_TXN_CAPACITY_WRITE, "CAP-WRITE ", 1 },
	{ PERF_TXN_CAPACITY_READ,  "CAP-READ ",  0 },
	{ 0, NULL, 0 }
};

int hist_entry__transaction_len(void)
{
	int i;
	int len = 0;

	for (i = 0; txbits[i].name; i++) {
		if (!txbits[i].skip_for_len)
			len += strlen(txbits[i].name);
	}
	len += 4; /* :XX<space> */
	return len;
}

static int hist_entry__transaction_snprintf(struct hist_entry *he, char *bf,
					    size_t size, unsigned int width)
{
	u64 t = he->transaction;
	char buf[128];
	char *p = buf;
	int i;

	buf[0] = 0;
	for (i = 0; txbits[i].name; i++)
		if (txbits[i].flag & t)
			p = add_str(p, txbits[i].name);
	if (t && !(t & (PERF_TXN_SYNC|PERF_TXN_ASYNC)))
		p = add_str(p, "NEITHER ");
	if (t & PERF_TXN_ABORT_MASK) {
		sprintf(p, ":%" PRIx64,
			(t & PERF_TXN_ABORT_MASK) >>
			PERF_TXN_ABORT_SHIFT);
		p += strlen(p);
	}

	return repsep_snprintf(bf, size, "%-*s", width, buf);
}

struct sort_entry sort_transaction = {
	.se_header	= "Transaction                ",
	.se_cmp		= sort__transaction_cmp,
	.se_snprintf	= hist_entry__transaction_snprintf,
	.se_width_idx	= HISTC_TRANSACTION,
};

/* --sort symbol_size */

static int64_t _sort__sym_size_cmp(struct symbol *sym_l, struct symbol *sym_r)
{
	int64_t size_l = sym_l != NULL ? symbol__size(sym_l) : 0;
	int64_t size_r = sym_r != NULL ? symbol__size(sym_r) : 0;

	return size_l < size_r ? -1 :
		size_l == size_r ? 0 : 1;
}

static int64_t
sort__sym_size_cmp(struct hist_entry *left, struct hist_entry *right)
{
	return _sort__sym_size_cmp(right->ms.sym, left->ms.sym);
}

static int _hist_entry__sym_size_snprintf(struct symbol *sym, char *bf,
					  size_t bf_size, unsigned int width)
{
	if (sym)
		return repsep_snprintf(bf, bf_size, "%*d", width, symbol__size(sym));

	return repsep_snprintf(bf, bf_size, "%*s", width, "unknown");
}

static int hist_entry__sym_size_snprintf(struct hist_entry *he, char *bf,
					 size_t size, unsigned int width)
{
	return _hist_entry__sym_size_snprintf(he->ms.sym, bf, size, width);
}

struct sort_entry sort_sym_size = {
	.se_header	= "Symbol size",
	.se_cmp		= sort__sym_size_cmp,
	.se_snprintf	= hist_entry__sym_size_snprintf,
	.se_width_idx	= HISTC_SYM_SIZE,
};

/* --sort dso_size */

static int64_t _sort__dso_size_cmp(struct map *map_l, struct map *map_r)
{
	int64_t size_l = map_l != NULL ? map__size(map_l) : 0;
	int64_t size_r = map_r != NULL ? map__size(map_r) : 0;

	return size_l < size_r ? -1 :
		size_l == size_r ? 0 : 1;
}

static int64_t
sort__dso_size_cmp(struct hist_entry *left, struct hist_entry *right)
{
	return _sort__dso_size_cmp(right->ms.map, left->ms.map);
}

static int _hist_entry__dso_size_snprintf(struct map *map, char *bf,
					  size_t bf_size, unsigned int width)
{
	if (map && map__dso(map))
		return repsep_snprintf(bf, bf_size, "%*d", width, map__size(map));

	return repsep_snprintf(bf, bf_size, "%*s", width, "unknown");
}

static int hist_entry__dso_size_snprintf(struct hist_entry *he, char *bf,
					 size_t size, unsigned int width)
{
	return _hist_entry__dso_size_snprintf(he->ms.map, bf, size, width);
}

struct sort_entry sort_dso_size = {
	.se_header	= "DSO size",
	.se_cmp		= sort__dso_size_cmp,
	.se_snprintf	= hist_entry__dso_size_snprintf,
	.se_width_idx	= HISTC_DSO_SIZE,
};

/* --sort dso_size */

static int64_t
sort__addr_cmp(struct hist_entry *left, struct hist_entry *right)
{
	u64 left_ip = left->ip;
	u64 right_ip = right->ip;
	struct map *left_map = left->ms.map;
	struct map *right_map = right->ms.map;

	if (left_map)
		left_ip = map__unmap_ip(left_map, left_ip);
	if (right_map)
		right_ip = map__unmap_ip(right_map, right_ip);

	return _sort__addr_cmp(left_ip, right_ip);
}

static int hist_entry__addr_snprintf(struct hist_entry *he, char *bf,
				     size_t size, unsigned int width)
{
	u64 ip = he->ip;
	struct map *map = he->ms.map;

	if (map)
		ip = map__unmap_ip(map, ip);

	return repsep_snprintf(bf, size, "%-#*llx", width, ip);
}

struct sort_entry sort_addr = {
	.se_header	= "Address",
	.se_cmp		= sort__addr_cmp,
	.se_snprintf	= hist_entry__addr_snprintf,
	.se_width_idx	= HISTC_ADDR,
};


struct sort_dimension {
	const char		*name;
	struct sort_entry	*entry;
	int			taken;
};

int __weak arch_support_sort_key(const char *sort_key __maybe_unused)
{
	return 0;
}

const char * __weak arch_perf_header_entry(const char *se_header)
{
	return se_header;
}

static void sort_dimension_add_dynamic_header(struct sort_dimension *sd)
{
	sd->entry->se_header = arch_perf_header_entry(sd->entry->se_header);
}

#define DIM(d, n, func) [d] = { .name = n, .entry = &(func) }

static struct sort_dimension common_sort_dimensions[] = {
	DIM(SORT_PID, "pid", sort_thread),
	DIM(SORT_COMM, "comm", sort_comm),
	DIM(SORT_DSO, "dso", sort_dso),
	DIM(SORT_SYM, "symbol", sort_sym),
	DIM(SORT_PARENT, "parent", sort_parent),
	DIM(SORT_CPU, "cpu", sort_cpu),
	DIM(SORT_SOCKET, "socket", sort_socket),
	DIM(SORT_SRCLINE, "srcline", sort_srcline),
	DIM(SORT_SRCFILE, "srcfile", sort_srcfile),
	DIM(SORT_LOCAL_WEIGHT, "local_weight", sort_local_weight),
	DIM(SORT_GLOBAL_WEIGHT, "weight", sort_global_weight),
	DIM(SORT_TRANSACTION, "transaction", sort_transaction),
#ifdef HAVE_LIBTRACEEVENT
	DIM(SORT_TRACE, "trace", sort_trace),
#endif
	DIM(SORT_SYM_SIZE, "symbol_size", sort_sym_size),
	DIM(SORT_DSO_SIZE, "dso_size", sort_dso_size),
	DIM(SORT_CGROUP, "cgroup", sort_cgroup),
	DIM(SORT_CGROUP_ID, "cgroup_id", sort_cgroup_id),
	DIM(SORT_SYM_IPC_NULL, "ipc_null", sort_sym_ipc_null),
	DIM(SORT_TIME, "time", sort_time),
	DIM(SORT_CODE_PAGE_SIZE, "code_page_size", sort_code_page_size),
	DIM(SORT_LOCAL_INS_LAT, "local_ins_lat", sort_local_ins_lat),
	DIM(SORT_GLOBAL_INS_LAT, "ins_lat", sort_global_ins_lat),
	DIM(SORT_LOCAL_PIPELINE_STAGE_CYC, "local_p_stage_cyc", sort_local_p_stage_cyc),
	DIM(SORT_GLOBAL_PIPELINE_STAGE_CYC, "p_stage_cyc", sort_global_p_stage_cyc),
	DIM(SORT_ADDR, "addr", sort_addr),
	DIM(SORT_LOCAL_RETIRE_LAT, "local_retire_lat", sort_local_p_stage_cyc),
	DIM(SORT_GLOBAL_RETIRE_LAT, "retire_lat", sort_global_p_stage_cyc),
	DIM(SORT_SIMD, "simd", sort_simd)
};

#undef DIM

#define DIM(d, n, func) [d - __SORT_BRANCH_STACK] = { .name = n, .entry = &(func) }

static struct sort_dimension bstack_sort_dimensions[] = {
	DIM(SORT_DSO_FROM, "dso_from", sort_dso_from),
	DIM(SORT_DSO_TO, "dso_to", sort_dso_to),
	DIM(SORT_SYM_FROM, "symbol_from", sort_sym_from),
	DIM(SORT_SYM_TO, "symbol_to", sort_sym_to),
	DIM(SORT_MISPREDICT, "mispredict", sort_mispredict),
	DIM(SORT_IN_TX, "in_tx", sort_in_tx),
	DIM(SORT_ABORT, "abort", sort_abort),
	DIM(SORT_CYCLES, "cycles", sort_cycles),
	