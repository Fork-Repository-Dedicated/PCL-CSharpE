using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace PCL.Core.Utils.OS;

/// <summary>
/// 通过 NT 内核系统调用执行系统级内存优化。需要管理员权限。
/// </summary>
public static unsafe partial class MemoryOptimizer
{
    // ReSharper disable InconsistentNaming, UnusedMember.Local

    #region NT Enums

    private enum SYSTEM_INFORMATION_CLASS
    {
        SystemFileCacheInformation       = 0x15,
        SystemMemoryListInformation      = 0x50,
        SystemCombinePhysicalMemory      = 0x82,
        SystemRegistryReconciliation     = 0x9B,
    }

    private enum SYSTEM_MEMORY_LIST_COMMAND
    {
        MemoryEmptyWorkingSets            = 2,
        MemoryFlushModifiedList           = 3,
        MemoryPurgeStandbyList            = 4,
        MemoryPurgeLowPriorityStandbyList = 5,
    }

    private const int SE_PRIVILEGE_ENABLED      = 0x02;
    private const int TOKEN_ADJUST_PRIVILEGES   = 0x20;
    private const int PROCESS_QUERY_INFORMATION = 0x0400;
    private const int PROCESS_SET_QUOTA         = 0x0100;
    private const uint HEAP_OPTIMIZE_RESOURCES  = 0x00000003;

    #endregion

    #region NT Structs

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID
    {
        public uint LowPart;
        public int  HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public LUID Luid;
        public int  Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_FILECACHE_INFORMATION
    {
        public nuint CurrentSize;
        public nuint PeakSize;
        public uint  PageFaultCount;
        public nuint MinimumWorkingSet;
        public nuint MaximumWorkingSet;
        public nuint CurrentSizeIncludingTransitionInPages;
        public nuint PeakSizeIncludingTransitionInPages;
        public uint  TransitionRePurposeCount;
        public uint  Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORY_COMBINE_INFORMATION_EX
    {
        public nint  Handle;
        public nuint PagesCombined;
        public uint  Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct HEAP_OPTIMIZE_RESOURCES_INFORMATION
    {
        public uint  Version;
        public uint  Flags;
    }

    #endregion

    #region P/Invoke

    [LibraryImport("ntdll.dll")]
    private static partial uint NtSetSystemInformation(
        int systemInformationClass, void* systemInformation, int systemInformationLength);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial nint GetCurrentProcess();

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseHandle(nint handle);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial nint OpenProcess(int desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, int processId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetProcessWorkingSetSizeEx(
        nint hProcess, nint minWorkingSetSize, nint maxWorkingSetSize, uint flags);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial nint GetProcessHeap();

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial uint GetProcessHeaps(uint numberOfHeaps, nint* processHeaps);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial nuint HeapCompact(nint hHeap, uint dwFlags);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool HeapSetInformation(
        nint heapHandle, int heapInformationClass, void* heapInformation, nuint heapInformationLength);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool OpenProcessToken(nint processHandle, int desiredAccess, out nint tokenHandle);

    [LibraryImport("advapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool LookupPrivilegeValue(string? systemName, string name, out LUID luid);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool AdjustTokenPrivileges(
        nint tokenHandle, [MarshalAs(UnmanagedType.Bool)] bool disableAll,
        TOKEN_PRIVILEGES* newState, int bufferLength, nint previousState, nint returnLength);

    [LibraryImport("psapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool EmptyWorkingSet(nint hProcess);

    // ReSharper restore InconsistentNaming, UnusedMember.Local

    #endregion

    /// <summary>
    /// 执行全套系统内存优化。零堆分配内核路径 + 逐进程 WorkingSet 清扫 + 托管堆压缩。
    /// </summary>
    public static void Execute()
    {
        if (!ProcessInterop.IsAdmin())
            throw new InvalidOperationException("内存优化需要管理员权限");

        AcquirePrivileges();

        // 走 NT 内核把系统级的脏页、Standby、文件缓存全部刷掉
        NtSetMemoryListCommand(SYSTEM_MEMORY_LIST_COMMAND.MemoryEmptyWorkingSets);
        NtSetFileCacheSize();
        NtSetMemoryListCommand(SYSTEM_MEMORY_LIST_COMMAND.MemoryFlushModifiedList);
        NtSetMemoryListCommand(SYSTEM_MEMORY_LIST_COMMAND.MemoryPurgeStandbyList);
        NtSetMemoryListCommand(SYSTEM_MEMORY_LIST_COMMAND.MemoryPurgeLowPriorityStandbyList);
        NtReconcileRegistry();
        NtCombinePhysicalMemory();

        // 逐个进程裁 WorkingSet，内核全局清不掉的这里补刀
        TrimAllProcessWorkingSets();

        // 收拾自己：本机堆碎片整理 + CLR 托管堆压缩
        CompactSelfHeaps();
        CompactManagedHeap();
    }

    #region Privilege Escalation

    private static void AcquirePrivileges()
    {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, out var token))
            throw new Win32Exception(Marshal.GetLastWin32Error());

        try
        {
            EnablePrivilege(token, "SeProfileSingleProcessPrivilege");
            EnablePrivilege(token, "SeIncreaseQuotaPrivilege");
            EnablePrivilege(token, "SeDebugPrivilege");
        }
        finally
        {
            CloseHandle(token);
        }
    }

    private static void EnablePrivilege(nint token, string privilege)
    {
        if (!LookupPrivilegeValue(null, privilege, out var luid))
            throw new Win32Exception(Marshal.GetLastWin32Error());

        var tp = new TOKEN_PRIVILEGES { PrivilegeCount = 1, Luid = luid, Attributes = SE_PRIVILEGE_ENABLED };
        if (!AdjustTokenPrivileges(token, false, &tp, 0, nint.Zero, nint.Zero))
            throw new Win32Exception(Marshal.GetLastWin32Error());
    }

    #endregion

    #region NT Kernel Memory Reclamation

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void NtSetMemoryListCommand(SYSTEM_MEMORY_LIST_COMMAND command)
    {
        var cmd = (int)command;
        var status = NtSetSystemInformation(
            (int)SYSTEM_INFORMATION_CLASS.SystemMemoryListInformation, &cmd, sizeof(int));
        if (status != 0)
            throw new SystemException($"NtSetSystemInformation(MemoryList, {command}) = 0x{status:X8}");
    }

    private static void NtSetFileCacheSize()
    {
        var info = default(SYSTEM_FILECACHE_INFORMATION);
        info.MinimumWorkingSet = nuint.MaxValue;
        info.MaximumWorkingSet = nuint.MaxValue;

        var status = NtSetSystemInformation(
            (int)SYSTEM_INFORMATION_CLASS.SystemFileCacheInformation, &info, sizeof(SYSTEM_FILECACHE_INFORMATION));
        if (status != 0)
            throw new SystemException($"NtSetSystemInformation(FileCacheInfo) = 0x{status:X8}");
    }

    private static void NtReconcileRegistry()
    {
        NtSetSystemInformation((int)SYSTEM_INFORMATION_CLASS.SystemRegistryReconciliation, null, 0);
    }

    private static void NtCombinePhysicalMemory()
    {
        var info = default(MEMORY_COMBINE_INFORMATION_EX);
        NtSetSystemInformation(
            (int)SYSTEM_INFORMATION_CLASS.SystemCombinePhysicalMemory, &info, sizeof(MEMORY_COMBINE_INFORMATION_EX));
    }

    #endregion

    #region Per-Process Working Set Trim

    /// <summary>
    /// 带 SeDebugPrivilege 遍历全部进程，逐个清空 WorkingSet。受保护进程静默跳过。
    /// </summary>
    private static void TrimAllProcessWorkingSets()
    {
        var selfPid = Environment.ProcessId;
        var pids = stackalloc int[2048];
        var count = SnapshotProcessIds(pids, 2048);

        for (var i = 0; i < count; i++)
        {
            var pid = pids[i];
            if (pid == 0 || pid == 4 || pid == selfPid) continue;

            var hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_SET_QUOTA, false, pid);
            if (hProcess == nint.Zero) continue;

            EmptyWorkingSet(hProcess);
            SetProcessWorkingSetSizeEx(hProcess, -1, -1, 0);
            CloseHandle(hProcess);
        }

        // 自身进程最后处理，避免运行时页面被提前换出
        EmptyWorkingSet(GetCurrentProcess());
        SetProcessWorkingSetSizeEx(GetCurrentProcess(), -1, -1, 0);
    }

    /// <summary>
    /// 取 PID 快照写入栈缓冲区。NoInlining 隔离托管分配，方便 GC 精确回收。
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static int SnapshotProcessIds(int* buffer, int capacity)
    {
        var processes = Process.GetProcesses();
        var count = Math.Min(processes.Length, capacity);
        for (var i = 0; i < count; i++)
        {
            try { buffer[i] = processes[i].Id; }
            catch { buffer[i] = 0; }
        }
        for (var i = 0; i < processes.Length; i++) processes[i].Dispose();
        return count;
    }

    #endregion

    #region Self Process Deep Cleanup

    /// <summary>
    /// 压缩当前进程所有本机堆。HeapCompact 合并碎片，HeapOptimizeResources 释放延迟空闲块。
    /// </summary>
    private static void CompactSelfHeaps()
    {
        const int maxHeaps = 128;
        var heaps = stackalloc nint[maxHeaps];
        var count = (int)GetProcessHeaps((uint)maxHeaps, heaps);

        for (var i = 0; i < count; i++)
        {
            HeapCompact(heaps[i], 0);

            var optInfo = new HEAP_OPTIMIZE_RESOURCES_INFORMATION { Version = 1, Flags = 0 };
            HeapSetInformation(heaps[i], (int)HEAP_OPTIMIZE_RESOURCES, &optInfo,
                (nuint)sizeof(HEAP_OPTIMIZE_RESOURCES_INFORMATION));
        }
    }

    /// <summary>
    /// 全代 GC + LOH 压缩，两轮收集清扫终结器复活对象。
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void CompactManagedHeap()
    {
        GCSettings.LargeObjectHeapCompactionMode = GCLargeObjectHeapCompactionMode.CompactOnce;
        GC.Collect(GC.MaxGeneration, GCCollectionMode.Aggressive, true, true);
        GC.WaitForPendingFinalizers();
        GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, true, true);
    }

    #endregion
}
