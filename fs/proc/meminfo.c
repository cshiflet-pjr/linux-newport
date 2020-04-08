// SPDX-License-Identifier: GPL-2.0
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/mman.h>
#include <linux/mmzone.h>
#include <linux/proc_fs.h>
#include <linux/quicklist.h>
#include <linux/seq_file.h>
#include <linux/swap.h>
#include <linux/vmstat.h>
#include <linux/atomic.h>
#include <linux/vmalloc.h>
#ifdef CONFIG_CMA
#include <linux/cma.h>
#endif
#include <asm/page.h>
#include <asm/pgtable.h>
#include "internal.h"
#ifdef CONFIG_POPCORN_REMOTE_INFO
#include <popcorn/remote_meminfo.h>
#endif

void __attribute__((weak)) arch_report_meminfo(struct seq_file *m)
{
}

static void show_val_kb(struct seq_file *m, const char *s, unsigned long num)
{
	char v[32];
	static const char blanks[7] = {' ', ' ', ' ', ' ',' ', ' ', ' '};
	int len;

	len = num_to_str(v, sizeof(v), num << (PAGE_SHIFT - 10));

	seq_write(m, s, 16);

	if (len > 0) {
		if (len < 8)
			seq_write(m, blanks, 8 - len);

		seq_write(m, v, len);
	}
	seq_write(m, " kB\n", 4);
}

static int meminfo_proc_show(struct seq_file *m, void *v)
{
	struct sysinfo i;
	unsigned long committed;
	long cached;
	long available;
	unsigned long pages[NR_LRU_LISTS];
	int lru;

#ifdef CONFIG_POPCORN_REMOTE_INFO
	remote_mem_info_response_t rem_mem;
#endif

	si_meminfo(&i);
	si_swapinfo(&i);
	committed = percpu_counter_read_positive(&vm_committed_as);

	cached = global_node_page_state(NR_FILE_PAGES) -
			total_swapcache_pages() - i.bufferram;
	if (cached < 0)
		cached = 0;

	for (lru = LRU_BASE; lru < NR_LRU_LISTS; lru++)
		pages[lru] = global_node_page_state(NR_LRU_BASE + lru);

	available = si_mem_available();


#ifdef CONFIG_HIGHMEM
	show_val_kb(m, "HighTotal:      ", i.totalhigh);
	show_val_kb(m, "HighFree:       ", i.freehigh);
	show_val_kb(m, "LowTotal:       ", i.totalram - i.totalhigh);
	show_val_kb(m, "LowFree:        ", i.freeram - i.freehigh);
#endif

#ifndef CONFIG_MMU
	show_val_kb(m, "MmapCopy:       ",
		    (unsigned long)atomic_long_read(&mmap_pages_allocated));
#endif
#ifndef CONFIG_POPCORN_REMOTE_INFO
	show_val_kb(m, "MemTotal:       ", i.totalram);
	show_val_kb(m, "MemFree:        ", i.freeram);
	show_val_kb(m, "MemAvailable:   ", available);
	show_val_kb(m, "Buffers:        ", i.bufferram);
	show_val_kb(m, "Cached:         ", cached);
	show_val_kb(m, "SwapCached:     ", total_swapcache_pages());
	show_val_kb(m, "Active:         ", pages[LRU_ACTIVE_ANON] +
					   pages[LRU_ACTIVE_FILE]);
	show_val_kb(m, "Inactive:       ", pages[LRU_INACTIVE_ANON] +
					   pages[LRU_INACTIVE_FILE]);
	show_val_kb(m, "Active(anon):   ", pages[LRU_ACTIVE_ANON]);
	show_val_kb(m, "Inactive(anon): ", pages[LRU_INACTIVE_ANON]);
	show_val_kb(m, "Active(file):   ", pages[LRU_ACTIVE_FILE]);
	show_val_kb(m, "Inactive(file): ", pages[LRU_INACTIVE_FILE]);
	show_val_kb(m, "Unevictable:    ", pages[LRU_UNEVICTABLE]);
	show_val_kb(m, "Mlocked:        ", global_zone_page_state(NR_MLOCK));

	show_val_kb(m, "SwapTotal:      ", i.totalswap);
	show_val_kb(m, "SwapFree:       ", i.freeswap);
	show_val_kb(m, "Dirty:          ",
		    global_node_page_state(NR_FILE_DIRTY));
	show_val_kb(m, "Writeback:      ",
		    global_node_page_state(NR_WRITEBACK));
	show_val_kb(m, "AnonPages:      ",
		    global_node_page_state(NR_ANON_MAPPED));
	show_val_kb(m, "Mapped:         ",
		    global_node_page_state(NR_FILE_MAPPED));
	show_val_kb(m, "Shmem:          ", i.sharedram);
	show_val_kb(m, "Slab:           ",
		    global_node_page_state(NR_SLAB_RECLAIMABLE) +
		    global_node_page_state(NR_SLAB_UNRECLAIMABLE));

	show_val_kb(m, "SReclaimable:   ",
		    global_node_page_state(NR_SLAB_RECLAIMABLE));
	show_val_kb(m, "SUnreclaim:     ",
		    global_node_page_state(NR_SLAB_UNRECLAIMABLE));
	seq_printf(m, "KernelStack:    %8lu kB\n",
		   global_zone_page_state(NR_KERNEL_STACK_KB));
	show_val_kb(m, "PageTables:     ",
		    global_zone_page_state(NR_PAGETABLE));
#ifdef CONFIG_QUICKLIST
	show_val_kb(m, "Quicklists:     ", quicklist_total_size());
#endif

	show_val_kb(m, "NFS_Unstable:   ",
		    global_node_page_state(NR_UNSTABLE_NFS));
	show_val_kb(m, "Bounce:         ",
		    global_zone_page_state(NR_BOUNCE));
	show_val_kb(m, "WritebackTmp:   ",
		    global_node_page_state(NR_WRITEBACK_TEMP));
	show_val_kb(m, "CommitLimit:    ", vm_commit_limit());
	show_val_kb(m, "Committed_AS:   ", committed);
	seq_printf(m, "VmallocTotal:   %8lu kB\n",
		   (unsigned long)VMALLOC_TOTAL >> 10);
	show_val_kb(m, "VmallocUsed:    ", 0ul);
	show_val_kb(m, "VmallocChunk:   ", 0ul);

#ifdef CONFIG_MEMORY_FAILURE
	seq_printf(m, "HardwareCorrupted: %5lu kB\n",
		   atomic_long_read(&num_poisoned_pages) << (PAGE_SHIFT - 10));
#endif

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	show_val_kb(m, "AnonHugePages:  ",
		    global_node_page_state(NR_ANON_THPS) * HPAGE_PMD_NR);
	show_val_kb(m, "ShmemHugePages: ",
		    global_node_page_state(NR_SHMEM_THPS) * HPAGE_PMD_NR);
	show_val_kb(m, "ShmemPmdMapped: ",
		    global_node_page_state(NR_SHMEM_PMDMAPPED) * HPAGE_PMD_NR);
#endif

#ifdef CONFIG_CMA
	show_val_kb(m, "CmaTotal:       ", totalcma_pages);
	show_val_kb(m, "CmaFree:        ",
		    global_zone_page_state(NR_FREE_CMA_PAGES));
#endif

#else // CONFIG_POPCORN_REMOTE_INFO
	remote_proc_mem_info(&rem_mem);

	seq_printf(m,
		"MemTotal:       %8lu kB\n"
		"MemFree:        %8lu kB\n"
		"MemAvailable:   %8lu kB\n"
		"Buffers:        %8lu kB\n"
		"Cached:         %8lu kB\n"
		"SwapCached:     %8lu kB\n"
		"Active:         %8lu kB\n"
		"Inactive:       %8lu kB\n"
		"Active(anon):   %8lu kB\n"
		"Inactive(anon): %8lu kB\n"
		"Active(file):   %8lu kB\n"
		"Inactive(file): %8lu kB\n"
		"Unevictable:    %8lu kB\n"
		"Mlocked:        %8lu kB\n"
#ifdef CONFIG_HIGHMEM
		"HighTotal:      %8lu kB\n"
		"HighFree:       %8lu kB\n"
		"LowTotal:       %8lu kB\n"
		"LowFree:        %8lu kB\n"
#endif
#ifndef CONFIG_MMU
		"MmapCopy:       %8lu kB\n"
#endif
		"SwapTotal:      %8lu kB\n"
		"SwapFree:       %8lu kB\n"
		"Dirty:          %8lu kB\n"
		"Writeback:      %8lu kB\n"
		"AnonPages:      %8lu kB\n"
		"Mapped:         %8lu kB\n"
		"Shmem:          %8lu kB\n"
		"Slab:           %8lu kB\n"
		"SReclaimable:   %8lu kB\n"
		"SUnreclaim:     %8lu kB\n"
		"KernelStack:    %8lu kB\n"
		"PageTables:     %8lu kB\n"
#ifdef CONFIG_QUICKLIST
		"Quicklists:     %8lu kB\n"
#endif
		"NFS_Unstable:   %8lu kB\n"
		"Bounce:         %8lu kB\n"
		"WritebackTmp:   %8lu kB\n"
		"CommitLimit:    %8lu kB\n"
		"Committed_AS:   %8lu kB\n"
		"VmallocTotal:   %8lu kB\n"
		"VmallocUsed:    %8lu kB\n"
		"VmallocChunk:   %8lu kB\n"
#ifdef CONFIG_MEMORY_FAILURE
		"HardwareCorrupted: %5lu kB\n"
#endif
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
		"AnonHugePages:  %8lu kB\n"
#endif
#ifdef CONFIG_CMA
		"CmaTotal:       %8lu kB\n"
		"CmaFree:        %8lu kB\n"
#endif
		,
		K(i.totalram) + rem_mem.MemTotal,
		K(i.freeram) + rem_mem.MemFree,
		K(available) + rem_mem.MemAvailable,
		K(i.bufferram) + rem_mem.Buffers,
		K(cached) + rem_mem.Cached,
		K(total_swapcache_pages()) + rem_mem.SwapCached,
		K(pages[LRU_ACTIVE_ANON]   + pages[LRU_ACTIVE_FILE]) + rem_mem.Active,
		K(pages[LRU_INACTIVE_ANON] + pages[LRU_INACTIVE_FILE]) + rem_mem.Inactive,
		K(pages[LRU_ACTIVE_ANON]) + rem_mem.Active_anon,
		K(pages[LRU_INACTIVE_ANON]) + rem_mem.Inactive_anon,
		K(pages[LRU_ACTIVE_FILE]) + rem_mem.Active_file,
		K(pages[LRU_INACTIVE_FILE]) + rem_mem.Inactive_file,
		K(pages[LRU_UNEVICTABLE]) + rem_mem.Unevictable,
		K(global_page_state(NR_MLOCK)) + rem_mem.Mlocked,
#ifdef CONFIG_HIGHMEM
		K(i.totalhigh) + rem_mem.HighTotal,
		K(i.freehigh) + rem_mem.HighFree,
		K(i.totalram-i.totalhigh) + rem_mem.LowTotal,
		K(i.freeram-i.freehigh) + rem_mem.LowFree,
#endif
#ifndef CONFIG_MMU
		K((unsigned long) atomic_long_read(&mmap_pages_allocated)) + rem_mem.MmapCopy,
#endif
		K(i.totalswap) + rem_mem.SwapTotal,
		K(i.freeswap) + rem_mem.SwapFree,
		K(global_page_state(NR_FILE_DIRTY)) + rem_mem.Dirty,
		K(global_page_state(NR_WRITEBACK)) + rem_mem.Writeback,
		K(global_page_state(NR_ANON_PAGES)) + rem_mem.AnonPages,
		K(global_page_state(NR_FILE_MAPPED)) + rem_mem.Mapped,
		K(i.sharedram) + rem_mem.Shmem,
		K(global_page_state(NR_SLAB_RECLAIMABLE) +
				global_page_state(NR_SLAB_UNRECLAIMABLE)) + rem_mem.Slab,
		K(global_page_state(NR_SLAB_RECLAIMABLE)) + rem_mem.SReclaimable,
		K(global_page_state(NR_SLAB_UNRECLAIMABLE)) + rem_mem.SUnreclaim,
		global_page_state(NR_KERNEL_STACK) * THREAD_SIZE / 1024 + rem_mem.KernelStack,
		K(global_page_state(NR_PAGETABLE)) + rem_mem.PageTables,
#ifdef CONFIG_QUICKLIST
		K(quicklist_total_size()) + rem_mem.Quicklists,
#endif
		K(global_page_state(NR_UNSTABLE_NFS)) + rem_mem.NFS_Unstable,
		K(global_page_state(NR_BOUNCE)) + rem_mem.Bounce,
		K(global_page_state(NR_WRITEBACK_TEMP)) + rem_mem.WritebackTmp,
		K(vm_commit_limit()) + rem_mem.CommitLimit,
		K(committed) + rem_mem.Committed_AS,
		((unsigned long)VMALLOC_TOTAL >> 10) + rem_mem.VmallocTotal,
		0ul, // used to be vmalloc 'used'
		0ul  // used to be vmalloc 'largest_chunk'
#ifdef CONFIG_MEMORY_FAILURE
		, (atomic_long_read(&num_poisoned_pages) << (PAGE_SHIFT - 10)) + rem_mem.HardwareCorrupted
#endif
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
		, K(global_page_state(NR_ANON_TRANSPARENT_HUGEPAGES) *
		   HPAGE_PMD_NR) + rem_mem.AnonHugePages
#endif
#ifdef CONFIG_CMA
		, K(totalcma_pages) + rem_mem.CmaTotal
		, K(global_page_state(NR_FREE_CMA_PAGES)) + rem_mem.CmaFree
#endif
		);
#endif

	hugetlb_report_meminfo(m);

	arch_report_meminfo(m);

	return 0;
}

static int meminfo_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, meminfo_proc_show, NULL);
}

static const struct file_operations meminfo_proc_fops = {
	.open		= meminfo_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int __init proc_meminfo_init(void)
{
	proc_create("meminfo", 0, NULL, &meminfo_proc_fops);
	return 0;
}
fs_initcall(proc_meminfo_init);
