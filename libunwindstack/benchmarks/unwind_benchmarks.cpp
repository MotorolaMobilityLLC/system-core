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

#include <stdint.h>

#include <memory>

#include <benchmark/benchmark.h>

#include <unwindstack/Maps.h>
#include <unwindstack/Memory.h>
#include <unwindstack/Regs.h>
#include <unwindstack/RegsGetLocal.h>
#include <unwindstack/Unwinder.h>

size_t Call6(std::shared_ptr<unwindstack::Memory>& process_memory, unwindstack::Maps* maps) {
  std::unique_ptr<unwindstack::Regs> regs(unwindstack::Regs::CreateFromLocal());
  unwindstack::RegsGetLocal(regs.get());
  unwindstack::Unwinder unwinder(32, maps, regs.get(), process_memory);
  unwinder.Unwind();
  return unwinder.NumFrames();
}

size_t Call5(std::shared_ptr<unwindstack::Memory>& process_memory, unwindstack::Maps* maps) {
  return Call6(process_memory, maps);
}

size_t Call4(std::shared_ptr<unwindstack::Memory>& process_memory, unwindstack::Maps* maps) {
  return Call5(process_memory, maps);
}

size_t Call3(std::shared_ptr<unwindstack::Memory>& process_memory, unwindstack::Maps* maps) {
  return Call4(process_memory, maps);
}

size_t Call2(std::shared_ptr<unwindstack::Memory>& process_memory, unwindstack::Maps* maps) {
  return Call3(process_memory, maps);
}

size_t Call1(std::shared_ptr<unwindstack::Memory>& process_memory, unwindstack::Maps* maps) {
  return Call2(process_memory, maps);
}

static void BM_uncached_unwind(benchmark::State& state) {
  auto process_memory = unwindstack::Memory::CreateProcessMemory(getpid());
  unwindstack::LocalMaps maps;
  if (!maps.Parse()) {
    state.SkipWithError("Failed to parse local maps.");
  }

  for (auto _ : state) {
    benchmark::DoNotOptimize(Call1(process_memory, &maps));
  }
}
BENCHMARK(BM_uncached_unwind);

static void BM_cached_unwind(benchmark::State& state) {
  auto process_memory = unwindstack::Memory::CreateProcessMemoryCached(getpid());
  unwindstack::LocalMaps maps;
  if (!maps.Parse()) {
    state.SkipWithError("Failed to parse local maps.");
  }

  for (auto _ : state) {
    benchmark::DoNotOptimize(Call1(process_memory, &maps));
  }
}
BENCHMARK(BM_cached_unwind);

BENCHMARK_MAIN();
