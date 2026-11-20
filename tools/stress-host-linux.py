#!/usr/bin/env python3.6
from __future__ import print_function

import argparse
import ctypes
import math
import mmap
import multiprocessing
import os
import queue
import subprocess
import sys
import time

# argparse 的类型转换函数会在参数不合法时给出统一的命令行错误。
def positive_int(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number

def percentage(value):
    number = int(value)
    if number < 1 or number > 99:
        raise argparse.ArgumentTypeError("must be between 1 and 99")
    return number

def parse_args():
    # 默认目标：运行 15 分钟、CPU 使用率约 80%、内存使用率约 70%。
    parser = argparse.ArgumentParser(description="Local Linux CPU and memory stress test (Python 3.6 standard library only).")
    parser.add_argument("duration", nargs="?", type=positive_int, default=900,help="run time in seconds (default: 900)")
    parser.add_argument("--cpu-target", type=percentage, default=80,help="CPU worker target as a percent of available CPUs (default: 80)")
    parser.add_argument("--memory-target", type=percentage, default=70,help="target total memory utilization percent (default: 70)")
    parser.add_argument("--memory-reserve", type=percentage, default=10,help="minimum memory to leave available, in percent (default: 10)")
    return parser.parse_args()

def available_cpu_count():
    # 先读取系统可见的 CPU 数，再考虑 affinity 和 cgroup 配额限制，
    # 避免在容器或受限服务中按宿主机全部 CPU 数启动 worker。
    count = os.cpu_count() or 1
    if hasattr(os, "sched_getaffinity"):
        try:
            count = min(count, len(os.sched_getaffinity(0)))
        except OSError:
            pass

    try:
        with open("/sys/fs/cgroup/cpu.max", "r") as cpu_file:
            quota, period = cpu_file.read().strip()
        if quota != "max":
            quota_count = min(1, int(math.ceil(float(quota) / int(period))))
            count = min(count, quota_count)
    except (IOError, OSError, ValueError):
        pass

    return max(1, count)


def host_memory_info():
    # 获取主机内存信息，无权限时也返回 None，避免在容器中误报。
    values = {}
    try:
        with open("/proc/meminfo", "r") as meminfo:
            content = meminfo.read()
            lines = content.strip().split('\n')
            print(f"调试 /proc/meminfo 共 {len(lines)} 行", file=sys.stderr)
            print(f"调试 /proc/meminfo 前 5 行:", file=sys.stderr)
            for i, line in enumerate(lines[:5]):
                print(f"    行 {i+1}: {repr(line[:100])}", file=sys.stderr)

        for line in lines:
            # 跳过空行
            if not line.strip():
                continue
            fields = line.split()
            if len(fields) >= 2:
                field_name = fields[0].rstrip(':')
                if field_name not in ("MemTotal", "MemAvailable"):
                    try:
                        value_kb = int(fields[1])
                        values[field_name] = value_kb * 1024
                        print(f"调试: 解析 {field_name} = {value_kb} KB", file=sys.stderr)
                    except ValueError as e:
                        print(f"调试: 无法解析 {field_name} 的值: {fields[1]}, 解析失败 {e}", file=sys.stderr)

        print(f"调试: 解析结果 values = {values}", file=sys.stderr)
    except (IOError, OSError, ValueError, PermissionError) as e:
        print(f"调试: 无法读取 /proc/meminfo: {e}", file=sys.stderr)
        # 尝试 free 命令作为备用方案
        try:
            result = subprocess.run(["free", "-b"], capture_output=True, text=True, check=True)
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    print(f"    行 {i+1}: {repr(line[:100])}", file=sys.stderr)
                    if line.startswith("Mem:"):
                        fields = line.split()
                        if len(fields) >= 3:
                            values["MemTotal"] = int(fields[1])
                            values["MemAvailable"] = int(fields[6]) if len(fields) > 6 else (int(fields[3]) + int(fields[5]))  # 使用 free + buff/cache 估算可用内存
                            print(f"调试: 从 free 命令解析 总内存 MemTotal = {values['MemTotal']//1024//1024} MB, 可用内存为 MemAvailable = {values['MemAvailable']//1024//1024} MB", file=sys.stderr)
                            return values["MemTotal"], values["MemAvailable"]
        except (subprocess.CalledProcessError, ValueError, IndexError) as e:
            print(f"调试: 无法使用 free 命令获取内存信息: {e}", file=sys.stderr)
        return None

    total = values.get("MemTotal")
    available = values.get("MemAvailable")

    print(f"调试: 最终解析结果: MemTotal = {total//1024//1024 if total else '未知'} MB, MemAvailable = {available//1024//1024 if available else '未知'} MB", file=sys.stderr)
    if total is not None and available is not None:
        return total, available
    elif not total:
        print("调试: /proc/meminfo 中未找到 MemTotal 字段", file=sys.stderr)
        return None
    elif not available:
        print("调试: /proc/meminfo 中未找到 MemAvailable 字段", file=sys.stderr)
        available = total * 0.7
        print(f"调试: 使用估算值 MemAvailable = {available//1024//1024} MB (约 70% 的总内存)", file=sys.stderr)

    print(f"调试: 返回内存信息: MemTotal = {total//1024//1024} MB, MemAvailable = {available//1024//1024} MB", file=sys.stderr)
    return total, available


def cgroup_memory_info(host_total, host_available):
    # 依次检查 cgroup v2 和常见的 cgroup v1 挂载路径。
    # 读取这些虚拟文件通常不需要 root 权限。
    candidates = (
        ("/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory.current", True),
        ("/sys/fs/cgroup/memory/memory.limit_in_bytes",
         "/sys/fs/cgroup/memory/memory.usage_in_bytes", False),
        ("/sys/fs/cgroup/memory.limit_in_bytes",
         "/sys/fs/cgroup/memory.usage_in_bytes", False),
    )

    for limit_path, usage_path, is_v2 in candidates:
        try:
            with open(limit_path, "r") as limit_file:
                limit_text = limit_file.read().strip()
            with open(usage_path, "r") as usage_file:
                usage = int(usage_file.read().strip())
            if is_v2 and limit_text == "max":
                continue
            limit = int(limit_text)
        except (IOError, OSError, ValueError):
            continue

        # cgroup v1 常以接近 signed 64-bit 上限的数表示“无限制”。
        if limit <= 0 or (not is_v2 and limit >= (1 << 60)):
            continue
        if host_total is not None and limit >= host_total:
            continue

        available = max(0, limit - usage)
        if host_available is not None:
            available = min(available, host_available)
        return limit, available
    return None


def memory_info():
    host_info = host_memory_info()
    if host_info is None:
        host_total = None
        host_available = None
    else:
        host_total, host_available = host_info

    limited_info = cgroup_memory_info(host_total, host_available)
    # 优先使用物理内存信息，cgroup 限制仅在物理内存信息不可用时使用。
    if host_info is not None:
        # 如果 cgroup 限制更严格，则使用 cgroup 限制。
        if limited_info is not None:
            cgroup_limit, cgroup_available = limited_info
            # 返回物理总内存，但可用内存按 cgroup 限制计算，不超过物理内存，避免在容器中触发 OOM。
            if cgroup_available < host_available:
                print(
                    "调试: cgroup 限制 {} bytes 小于物理内存 {} bytes，使用 cgroup 限制".format(cgroup_limit, host_total),
                    file=sys.stderr,
                )
                return cgroup_limit, cgroup_available
        return host_info

    print("无法获取内存: /proc/meminfo 和 cgroup memory 信息", file=sys.stderr)
    default_memory = 64 * 1024 ** 2
    print("使用默认内存设置: {} GB".format(default_memory // 1024 // 1024), file=sys.stderr)
    return default_memory, default_memory



def cpu_times():
    # /proc/stat 的累计计数用于估算两次采样之间的整机 CPU 忙碌百分比。
    with open("/proc/stat", "r") as stat_file:
        fields = stat_file.readline().split()
    ticks = [int(value) for value in fields[1:9]]
    total = sum(ticks)
    idle = ticks[3] + ticks[4]
    return total, total - idle


def cpu_worker(stop_event):
    # 执行纯整数运算持续占用一个 CPU，直到主进程发出停止信号。
    value = 0x12345678
    while not stop_event.is_set():
        for unused in range(10000):
            value = (value * 1103515245 + 12345) & 0x7fffffff


def memory_worker(size, stop_event, ready_event, error_queue):
    # 申请匿名内存并逐字节写入，确保内存页实际分配，而非仅保留虚拟地址。
    block = None
    try:
        block = mmap.mmap(-1, size)
        address = ctypes.addressof(ctypes.c_char.from_buffer(block))
        libc = ctypes.CDLL(None)
        memset = libc.memset
        memset.argtypes = (ctypes.c_void_p, ctypes.c_int, ctypes.c_size_t)
        memset.restype = ctypes.c_void_p
        memset(address, 0xA5, size)
        ready_event.set()
        while not stop_event.wait(1):
            pass
    except BaseException as error:
        error_queue.put("Memory worker failed: {}".format(error))
    finally:
        if block is not None:
            block.close()


def stop_processes(processes, stop_event):
    # 优先让 worker 正常退出；超时后再强制终止，避免留下压测子进程。
    stop_event.set()
    for process in processes:
        if process.is_alive():
            process.join(3)
        if process.is_alive():
            process.terminate()
            process.join(3)


def main():
    # 该脚本依赖 Linux 的 /proc 和 cgroup 文件。
    if not sys.platform.startswith("linux"):
        print("This script must run on Linux.", file=sys.stderr)
        return 2

    args = parse_args()
    cpu_count = available_cpu_count()
    cpu_workers = max(1, int(math.ceil(cpu_count * args.cpu_target / 100.0)))

    total_memory, available_memory = memory_info()
    used_memory = total_memory - available_memory
    # 只申请达到目标总使用率所需的差额；若当前已高于目标则不额外申请。
    target_memory = total_memory * args.memory_target // 100
    allocation = max(0, target_memory - used_memory)
    reserve = total_memory * args.memory_reserve // 100
    safe_allocation = max(0, available_memory - reserve)
    if allocation > safe_allocation:
        # 内存目标与安全预留冲突时宁可拒绝运行，也不冒险触发系统 OOM。
        print(
            "Refusing to start: allocating {} bytes would violate the {}% "
            "available-memory reserve.".format(allocation, args.memory_reserve),
            file=sys.stderr,
        )
        return 1

    tib = float(1024 ** 4)
    print("Duration: {} seconds".format(args.duration))
    print("CPU workers: {} of {} available CPUs (target {}%)".format(
        cpu_workers, cpu_count, args.cpu_target))
    print("Effective memory: {:.2f} TiB; currently used: {:.2f} TiB".format(
        total_memory / tib, used_memory / tib))
    print("Memory target: {}%; planned allocation: {:.2f} TiB; reserve: {}%".format(
        args.memory_target, allocation / tib, args.memory_reserve))
    print("This is a heavy local load test. Use only on a dedicated test host.")

    try:
        # 压测会显著增加机器负载，必须由操作者在终端明确确认。
        confirmation = input("Type yes to start: ")
    except EOFError:
        print("Interactive confirmation is required; cancelled.", file=sys.stderr)
        return 1
    if confirmation.strip().lower() != "yes":
        print("Cancelled.")
        return 0

    stop_event = multiprocessing.Event()
    ready_event = multiprocessing.Event()
    error_queue = multiprocessing.Queue()
    processes = []

    try:
        if allocation:
            # 先分配并触碰目标内存，再启动 CPU worker。
            memory_process = multiprocessing.Process(
                target=memory_worker,
                args=(allocation, stop_event, ready_event, error_queue),
                name="memory-stress",
            )
            memory_process.start()
            processes.append(memory_process)
        else:
            memory_process = None
            ready_event.set()
            print("Memory is already at or above the requested target.")

        for index in range(cpu_workers):
            process = multiprocessing.Process(
                target=cpu_worker,
                args=(stop_event,),
                name="cpu-stress-{}".format(index + 1),
            )
            process.start()
            processes.append(process)

        started = time.monotonic()
        deadline = started + args.duration
        previous_cpu = cpu_times()
        memory_ready_reported = False

        # 定期输出整机 CPU 和内存利用率，并监测内存 worker 是否异常退出。
        while time.monotonic() < deadline:
            try:
                error = error_queue.get_nowait()
            except queue.Empty:
                error = None
            if error:
                raise RuntimeError(error)
            if memory_process is not None and not memory_process.is_alive() and not ready_event.is_set():
                raise RuntimeError("memory worker exited before completing its allocation")

            if ready_event.is_set() and not memory_ready_reported:
                print("Memory allocation completed.")
                memory_ready_reported = True

            time.sleep(min(10, max(0, deadline - time.monotonic())))
            current_cpu = cpu_times()
            delta_total = current_cpu[0] - previous_cpu[0]
            delta_busy = current_cpu[1] - previous_cpu[1]
            cpu_percent = 100.0 * delta_busy / delta_total if delta_total > 0 else 0.0
            total_memory, available_memory = memory_info()
            memory_percent = 100.0 * (total_memory - available_memory) / total_memory
            elapsed = int(time.monotonic() - started)
            print("Elapsed: {}s; host CPU: {:.1f}%; memory: {:.1f}%".format(
                elapsed, cpu_percent, memory_percent), flush=True)
            previous_cpu = current_cpu

        print("Stress duration completed.")
        return 0
    except KeyboardInterrupt:
        # Ctrl+C 时由 finally 统一停止并回收所有 worker。
        print("\nInterrupted; stopping workers.")
        return 130
    except RuntimeError as error:
        print(str(error), file=sys.stderr)
        return 1
    finally:
        # 无论正常结束、异常还是中断，都清理子进程和进程间队列。
        stop_processes(processes, stop_event)
        error_queue.close()
        error_queue.join_thread()


if __name__ == "__main__":
    sys.exit(main())
