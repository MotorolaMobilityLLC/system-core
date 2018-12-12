/*
 * Copyright (C) 2018 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include <meminfo/pageacct.h>
#include <meminfo/procmeminfo.h>
#include <meminfo/sysmeminfo.h>
#include <pagemap/pagemap.h>

#include <android-base/file.h>
#include <android-base/logging.h>

using namespace std;
using namespace android::meminfo;

pid_t pid = -1;

class ValidateProcMemInfo : public ::testing::Test {
  protected:
    void SetUp() override {
        ASSERT_EQ(0, pm_kernel_create(&ker));
        ASSERT_EQ(0, pm_process_create(ker, pid, &proc));
        proc_mem = new ProcMemInfo(pid);
        ASSERT_NE(proc_mem, nullptr);
    }

    void TearDown() override {
        delete proc_mem;
        pm_process_destroy(proc);
        pm_kernel_destroy(ker);
    }

    pm_kernel_t* ker;
    pm_process_t* proc;
    ProcMemInfo* proc_mem;
};

TEST_F(ValidateProcMemInfo, TestMapsSize) {
    const std::vector<Vma>& maps = proc_mem->Maps();
    ASSERT_FALSE(maps.empty()) << "Process " << getpid() << " maps are empty";
}

TEST_F(ValidateProcMemInfo, TestMapsEquality) {
    const std::vector<Vma>& maps = proc_mem->Maps();
    ASSERT_EQ(proc->num_maps, maps.size());

    for (size_t i = 0; i < maps.size(); ++i) {
        EXPECT_EQ(proc->maps[i]->start, maps[i].start);
        EXPECT_EQ(proc->maps[i]->end, maps[i].end);
        EXPECT_EQ(proc->maps[i]->offset, maps[i].offset);
        EXPECT_EQ(std::string(proc->maps[i]->name), maps[i].name);
    }
}

TEST_F(ValidateProcMemInfo, TestMaps) {
    const std::vector<Vma>& maps = proc_mem->Maps();
    ASSERT_FALSE(maps.empty());
    ASSERT_EQ(proc->num_maps, maps.size());

    pm_memusage_t map_usage, proc_usage;
    pm_memusage_zero(&map_usage);
    pm_memusage_zero(&proc_usage);
    for (size_t i = 0; i < maps.size(); i++) {
        ASSERT_EQ(0, pm_map_usage(proc->maps[i], &map_usage));
        EXPECT_EQ(map_usage.vss, maps[i].usage.vss) << "VSS mismatch for map: " << maps[i].name;
        EXPECT_EQ(map_usage.rss, maps[i].usage.rss) << "RSS mismatch for map: " << maps[i].name;
        EXPECT_EQ(map_usage.pss, maps[i].usage.pss) << "PSS mismatch for map: " << maps[i].name;
        EXPECT_EQ(map_usage.uss, maps[i].usage.uss) << "USS mismatch for map: " << maps[i].name;
        pm_memusage_add(&proc_usage, &map_usage);
    }

    EXPECT_EQ(proc_usage.vss, proc_mem->Usage().vss);
    EXPECT_EQ(proc_usage.rss, proc_mem->Usage().rss);
    EXPECT_EQ(proc_usage.pss, proc_mem->Usage().pss);
    EXPECT_EQ(proc_usage.uss, proc_mem->Usage().uss);
}

TEST_F(ValidateProcMemInfo, TestSwapUsage) {
    const std::vector<Vma>& maps = proc_mem->Maps();
    ASSERT_FALSE(maps.empty());
    ASSERT_EQ(proc->num_maps, maps.size());

    pm_memusage_t map_usage, proc_usage;
    pm_memusage_zero(&map_usage);
    pm_memusage_zero(&proc_usage);
    for (size_t i = 0; i < maps.size(); i++) {
        ASSERT_EQ(0, pm_map_usage(proc->maps[i], &map_usage));
        EXPECT_EQ(map_usage.swap, maps[i].usage.swap) << "SWAP mismatch for map: " << maps[i].name;
        pm_memusage_add(&proc_usage, &map_usage);
    }

    EXPECT_EQ(proc_usage.swap, proc_mem->Usage().swap);
}

TEST_F(ValidateProcMemInfo, TestSwapOffsets) {
    const MemUsage& proc_usage = proc_mem->Usage();
    const std::vector<uint16_t>& swap_offsets = proc_mem->SwapOffsets();

    EXPECT_EQ(proc_usage.swap / getpagesize(), swap_offsets.size());
}

class ValidateProcMemInfoWss : public ::testing::Test {
  protected:
    void SetUp() override {
        ASSERT_EQ(0, pm_kernel_create(&ker));
        ASSERT_EQ(0, pm_process_create(ker, pid, &proc));
        proc_mem = new ProcMemInfo(pid, true);
        ASSERT_NE(proc_mem, nullptr);
    }

    void TearDown() override {
        delete proc_mem;
        pm_process_destroy(proc);
        pm_kernel_destroy(ker);
    }

    pm_kernel_t* ker;
    pm_process_t* proc;
    ProcMemInfo* proc_mem;
};

TEST_F(ValidateProcMemInfoWss, TestWorkingTestReset) {
    // Expect reset to succeed
    EXPECT_TRUE(ProcMemInfo::ResetWorkingSet(pid));
}

TEST_F(ValidateProcMemInfoWss, TestWssEquality) {
    // Read wss using libpagemap
    pm_memusage_t wss_pagemap;
    EXPECT_EQ(0, pm_process_workingset(proc, &wss_pagemap, 0));

    // Read wss using libmeminfo
    MemUsage wss = proc_mem->Wss();

    // compare
    EXPECT_EQ(wss_pagemap.rss, wss.rss);
    EXPECT_EQ(wss_pagemap.pss, wss.pss);
    EXPECT_EQ(wss_pagemap.uss, wss.uss);
}

class ValidatePageAcct : public ::testing::Test {
  protected:
    void SetUp() override {
        ASSERT_EQ(0, pm_kernel_create(&ker));
        ASSERT_EQ(0, pm_process_create(ker, pid, &proc));
    }

    void TearDown() override {
        pm_process_destroy(proc);
        pm_kernel_destroy(ker);
    }

    pm_kernel_t* ker;
    pm_process_t* proc;
};

TEST_F(ValidatePageAcct, TestPageFlags) {
    PageAcct& pi = PageAcct::Instance();
    pi.InitPageAcct(false);

    uint64_t* pagemap;
    size_t num_pages;
    for (size_t i = 0; i < proc->num_maps; i++) {
        ASSERT_EQ(0, pm_map_pagemap(proc->maps[i], &pagemap, &num_pages));
        for (size_t j = 0; j < num_pages; j++) {
            if (!PM_PAGEMAP_PRESENT(pagemap[j])) continue;

            uint64_t pfn = PM_PAGEMAP_PFN(pagemap[j]);
            uint64_t page_flags_pagemap, page_flags_meminfo;

            ASSERT_EQ(0, pm_kernel_flags(ker, pfn, &page_flags_pagemap));
            ASSERT_TRUE(pi.PageFlags(pfn, &page_flags_meminfo));
            // check if page flags equal
            EXPECT_EQ(page_flags_pagemap, page_flags_meminfo);
        }
        free(pagemap);
    }
}

TEST_F(ValidatePageAcct, TestPageCounts) {
    PageAcct& pi = PageAcct::Instance();
    pi.InitPageAcct(false);

    uint64_t* pagemap;
    size_t num_pages;
    for (size_t i = 0; i < proc->num_maps; i++) {
        ASSERT_EQ(0, pm_map_pagemap(proc->maps[i], &pagemap, &num_pages));
        for (size_t j = 0; j < num_pages; j++) {
            uint64_t pfn = PM_PAGEMAP_PFN(pagemap[j]);
            uint64_t map_count_pagemap, map_count_meminfo;

            ASSERT_EQ(0, pm_kernel_count(ker, pfn, &map_count_pagemap));
            ASSERT_TRUE(pi.PageMapCount(pfn, &map_count_meminfo));
            // check if map counts are equal
            EXPECT_EQ(map_count_pagemap, map_count_meminfo);
        }
        free(pagemap);
    }
}

TEST_F(ValidatePageAcct, TestPageIdle) {
    // skip the test if idle page tracking isn't enabled
    if (pm_kernel_init_page_idle(ker) != 0) {
        return;
    }

    PageAcct& pi = PageAcct::Instance();
    ASSERT_TRUE(pi.InitPageAcct(true));

    uint64_t* pagemap;
    size_t num_pages;
    for (size_t i = 0; i < proc->num_maps; i++) {
        ASSERT_EQ(0, pm_map_pagemap(proc->maps[i], &pagemap, &num_pages));
        for (size_t j = 0; j < num_pages; j++) {
            if (!PM_PAGEMAP_PRESENT(pagemap[j])) continue;
            uint64_t pfn = PM_PAGEMAP_PFN(pagemap[j]);

            ASSERT_EQ(0, pm_kernel_mark_page_idle(ker, &pfn, 1));
            int idle_status_pagemap = pm_kernel_get_page_idle(ker, pfn);
            int idle_status_meminfo = pi.IsPageIdle(pfn);
            EXPECT_EQ(idle_status_pagemap, idle_status_meminfo);
        }
        free(pagemap);
    }
}

TEST(TestProcMemInfo, TestMapsEmpty) {
    ProcMemInfo proc_mem(pid);
    const std::vector<Vma>& maps = proc_mem.Maps();
    EXPECT_GT(maps.size(), 0);
}

TEST(TestProcMemInfo, TestUsageEmpty) {
    // If we created the object for getting working set,
    // the usage must be empty
    ProcMemInfo proc_mem(pid, true);
    const MemUsage& usage = proc_mem.Usage();
    EXPECT_EQ(usage.rss, 0);
    EXPECT_EQ(usage.vss, 0);
    EXPECT_EQ(usage.pss, 0);
    EXPECT_EQ(usage.uss, 0);
    EXPECT_EQ(usage.swap, 0);
}

TEST(TestProcMemInfoWssReset, TestWssEmpty) {
    // If we created the object for getting usage,
    // the working set must be empty
    ProcMemInfo proc_mem(pid, false);
    const MemUsage& wss = proc_mem.Wss();
    EXPECT_EQ(wss.rss, 0);
    EXPECT_EQ(wss.vss, 0);
    EXPECT_EQ(wss.pss, 0);
    EXPECT_EQ(wss.uss, 0);
    EXPECT_EQ(wss.swap, 0);
}

TEST(TestProcMemInfoWssReset, TestSwapOffsetsEmpty) {
    // If we created the object for getting working set,
    // the swap offsets must be empty
    ProcMemInfo proc_mem(pid, true);
    const std::vector<uint16_t>& swap_offsets = proc_mem.SwapOffsets();
    EXPECT_EQ(swap_offsets.size(), 0);
}

TEST(ValidateProcMemInfoFlags, TestPageFlags1) {
    // Create proc object using libpagemap
    pm_kernel_t* ker;
    ASSERT_EQ(0, pm_kernel_create(&ker));
    pm_process_t* proc;
    ASSERT_EQ(0, pm_process_create(ker, pid, &proc));

    // count swapbacked pages using libpagemap
    pm_memusage_t proc_usage;
    pm_memusage_zero(&proc_usage);
    ASSERT_EQ(0, pm_process_usage_flags(proc, &proc_usage, (1 << KPF_SWAPBACKED),
                                        (1 << KPF_SWAPBACKED)));

    // Create ProcMemInfo that counts swapbacked pages
    ProcMemInfo proc_mem(pid, false, (1 << KPF_SWAPBACKED), (1 << KPF_SWAPBACKED));

    EXPECT_EQ(proc_usage.vss, proc_mem.Usage().vss);
    EXPECT_EQ(proc_usage.rss, proc_mem.Usage().rss);
    EXPECT_EQ(proc_usage.pss, proc_mem.Usage().pss);
    EXPECT_EQ(proc_usage.uss, proc_mem.Usage().uss);

    pm_process_destroy(proc);
    pm_kernel_destroy(ker);
}

TEST(ValidateProcMemInfoFlags, TestPageFlags2) {
    // Create proc object using libpagemap
    pm_kernel_t* ker;
    ASSERT_EQ(0, pm_kernel_create(&ker));
    pm_process_t* proc;
    ASSERT_EQ(0, pm_process_create(ker, pid, &proc));

    // count non-swapbacked pages using libpagemap
    pm_memusage_t proc_usage;
    pm_memusage_zero(&proc_usage);
    ASSERT_EQ(0, pm_process_usage_flags(proc, &proc_usage, (1 << KPF_SWAPBACKED), 0));

    // Create ProcMemInfo that counts non-swapbacked pages
    ProcMemInfo proc_mem(pid, false, 0, (1 << KPF_SWAPBACKED));

    EXPECT_EQ(proc_usage.vss, proc_mem.Usage().vss);
    EXPECT_EQ(proc_usage.rss, proc_mem.Usage().rss);
    EXPECT_EQ(proc_usage.pss, proc_mem.Usage().pss);
    EXPECT_EQ(proc_usage.uss, proc_mem.Usage().uss);

    pm_process_destroy(proc);
    pm_kernel_destroy(ker);
}

TEST(SysMemInfoParser, TestSysMemInfoFile) {
    std::string meminfo = R"meminfo(MemTotal:        3019740 kB
MemFree:         1809728 kB
MemAvailable:    2546560 kB
Buffers:           54736 kB
Cached:           776052 kB
SwapCached:            0 kB
Active:           445856 kB
Inactive:         459092 kB
Active(anon):      78492 kB
Inactive(anon):     2240 kB
Active(file):     367364 kB
Inactive(file):   456852 kB
Unevictable:        3096 kB
Mlocked:            3096 kB
SwapTotal:         32768 kB
SwapFree:           4096 kB
Dirty:                32 kB
Writeback:             0 kB
AnonPages:         74988 kB
Mapped:            62624 kB
Shmem:              4020 kB
Slab:              86464 kB
SReclaimable:      44432 kB
SUnreclaim:        42032 kB
KernelStack:        4880 kB
PageTables:         2900 kB
NFS_Unstable:          0 kB
Bounce:                0 kB
WritebackTmp:          0 kB
CommitLimit:     1509868 kB
Committed_AS:      80296 kB
VmallocTotal:   263061440 kB
VmallocUsed:       65536 kB
VmallocChunk:          0 kB
AnonHugePages:      6144 kB
ShmemHugePages:        0 kB
ShmemPmdMapped:        0 kB
CmaTotal:         131072 kB
CmaFree:          130380 kB
HugePages_Total:       0
HugePages_Free:        0
HugePages_Rsvd:        0
HugePages_Surp:        0
Hugepagesize:       2048 kB)meminfo";

    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    ASSERT_TRUE(::android::base::WriteStringToFd(meminfo, tf.fd));

    SysMemInfo mi;
    ASSERT_TRUE(mi.ReadMemInfo(tf.path));
    EXPECT_EQ(mi.mem_total_kb(), 3019740);
    EXPECT_EQ(mi.mem_free_kb(), 1809728);
    EXPECT_EQ(mi.mem_buffers_kb(), 54736);
    EXPECT_EQ(mi.mem_cached_kb(), 776052);
    EXPECT_EQ(mi.mem_shmem_kb(), 4020);
    EXPECT_EQ(mi.mem_slab_kb(), 86464);
    EXPECT_EQ(mi.mem_slab_reclaimable_kb(), 44432);
    EXPECT_EQ(mi.mem_slab_unreclaimable_kb(), 42032);
    EXPECT_EQ(mi.mem_swap_kb(), 32768);
    EXPECT_EQ(mi.mem_swap_free_kb(), 4096);
    EXPECT_EQ(mi.mem_mapped_kb(), 62624);
    EXPECT_EQ(mi.mem_vmalloc_used_kb(), 65536);
    EXPECT_EQ(mi.mem_page_tables_kb(), 2900);
    EXPECT_EQ(mi.mem_kernel_stack_kb(), 4880);
}

TEST(SysMemInfoParser, TestEmptyFile) {
    TemporaryFile tf;
    std::string empty_string = "";
    ASSERT_TRUE(tf.fd != -1);
    ASSERT_TRUE(::android::base::WriteStringToFd(empty_string, tf.fd));

    SysMemInfo mi;
    EXPECT_TRUE(mi.ReadMemInfo(tf.path));
    EXPECT_EQ(mi.mem_total_kb(), 0);
}

TEST(SysMemInfoParser, TestZramTotal) {
    std::string exec_dir = ::android::base::GetExecutableDirectory();

    SysMemInfo mi;
    std::string zram_mmstat_dir = exec_dir + "/testdata1/";
    EXPECT_EQ(mi.mem_zram_kb(zram_mmstat_dir), 30504);

    std::string zram_memused_dir = exec_dir + "/testdata2/";
    EXPECT_EQ(mi.mem_zram_kb(zram_memused_dir), 30504);
}

enum {
    MEMINFO_TOTAL,
    MEMINFO_FREE,
    MEMINFO_BUFFERS,
    MEMINFO_CACHED,
    MEMINFO_SHMEM,
    MEMINFO_SLAB,
    MEMINFO_SLAB_RECLAIMABLE,
    MEMINFO_SLAB_UNRECLAIMABLE,
    MEMINFO_SWAP_TOTAL,
    MEMINFO_SWAP_FREE,
    MEMINFO_ZRAM_TOTAL,
    MEMINFO_MAPPED,
    MEMINFO_VMALLOC_USED,
    MEMINFO_PAGE_TABLES,
    MEMINFO_KERNEL_STACK,
    MEMINFO_COUNT
};

TEST(SysMemInfoParser, TestZramWithTags) {
    std::string meminfo = R"meminfo(MemTotal:        3019740 kB
MemFree:         1809728 kB
MemAvailable:    2546560 kB
Buffers:           54736 kB
Cached:           776052 kB
SwapCached:            0 kB
Active:           445856 kB
Inactive:         459092 kB
Active(anon):      78492 kB
Inactive(anon):     2240 kB
Active(file):     367364 kB
Inactive(file):   456852 kB
Unevictable:        3096 kB
Mlocked:            3096 kB
SwapTotal:         32768 kB
SwapFree:           4096 kB
Dirty:                32 kB
Writeback:             0 kB
AnonPages:         74988 kB
Mapped:            62624 kB
Shmem:              4020 kB
Slab:              86464 kB
SReclaimable:      44432 kB
SUnreclaim:        42032 kB
KernelStack:        4880 kB
PageTables:         2900 kB
NFS_Unstable:          0 kB
Bounce:                0 kB
WritebackTmp:          0 kB
CommitLimit:     1509868 kB
Committed_AS:      80296 kB
VmallocTotal:   263061440 kB
VmallocUsed:       65536 kB
VmallocChunk:          0 kB
AnonHugePages:      6144 kB
ShmemHugePages:        0 kB
ShmemPmdMapped:        0 kB
CmaTotal:         131072 kB
CmaFree:          130380 kB
HugePages_Total:       0
HugePages_Free:        0
HugePages_Rsvd:        0
HugePages_Surp:        0
Hugepagesize:       2048 kB)meminfo";

    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    ASSERT_TRUE(::android::base::WriteStringToFd(meminfo, tf.fd));
    std::string file = std::string(tf.path);
    std::vector<uint64_t> mem(MEMINFO_COUNT);
    std::vector<std::string> tags(SysMemInfo::kDefaultSysMemInfoTags);
    auto it = tags.begin();
    tags.insert(it + MEMINFO_ZRAM_TOTAL, "Zram:");
    SysMemInfo mi;

    // Read system memory info
    EXPECT_TRUE(mi.ReadMemInfo(tags, &mem, file));

    EXPECT_EQ(mem[MEMINFO_TOTAL], 3019740);
    EXPECT_EQ(mem[MEMINFO_FREE], 1809728);
    EXPECT_EQ(mem[MEMINFO_BUFFERS], 54736);
    EXPECT_EQ(mem[MEMINFO_CACHED], 776052);
    EXPECT_EQ(mem[MEMINFO_SHMEM], 4020);
    EXPECT_EQ(mem[MEMINFO_SLAB], 86464);
    EXPECT_EQ(mem[MEMINFO_SLAB_RECLAIMABLE], 44432);
    EXPECT_EQ(mem[MEMINFO_SLAB_UNRECLAIMABLE], 42032);
    EXPECT_EQ(mem[MEMINFO_SWAP_TOTAL], 32768);
    EXPECT_EQ(mem[MEMINFO_SWAP_FREE], 4096);
    EXPECT_EQ(mem[MEMINFO_MAPPED], 62624);
    EXPECT_EQ(mem[MEMINFO_VMALLOC_USED], 65536);
    EXPECT_EQ(mem[MEMINFO_PAGE_TABLES], 2900);
    EXPECT_EQ(mem[MEMINFO_KERNEL_STACK], 4880);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    if (argc <= 1) {
        cerr << "Pid of a permanently sleeping process must be provided." << endl;
        exit(EXIT_FAILURE);
    }
    ::android::base::InitLogging(argv, android::base::StderrLogger);
    pid = std::stoi(std::string(argv[1]));
    return RUN_ALL_TESTS();
}
