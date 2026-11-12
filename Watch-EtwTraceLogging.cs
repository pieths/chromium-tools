// Copyright (c) 2026 Piet Hein Schouten
// SPDX-License-Identifier: MIT

// ETW real-time consumer used by Watch-EtwTraceLogging.ps1 (compiled with Add-Type).
// Windows PowerShell 5.1 compiles this as C# 5: avoid newer language features.
//
// TODOs:
//   - Skip fields that cannot be decoded (binary, SYSTEMTIME, SID, arrays,
//     structs) by working out their length, so that the fields after them are
//     still shown. Today such a field is shown as <undecoded> and decoding stops
//     there (see ProcessEvent and ReadValue).
//   - Process labels (see Describe): a PID that is reused during a run keeps
//     its old label, and a process that exits before its first lookup stays "?".
//   - ANSI strings are always decoded as UTF-8, but they use the provider's
//     code page unless the field has the UTF8 out-type (tdh.h, TDH_OUTTYPE_STRING
//     and TDH_OUTTYPE_UTF8).
//   - Events that are not TraceLogging events (manifest-based or classic) are
//     skipped without a message. Warn once, or decode them with TDH.
//   - Show the opcode and the activity ID.
//   - Give a clearer message for an invalid -Pattern or -ExcludePattern regex.
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using EtwWatch.WindowsSdk;

// Windows declarations used by the ETW consumer below, kept in one place so
// that every Windows defined name, number and layout can be found and checked
// here. They are written by hand, only for what this script uses, and for x64
// only. Sources are the public Windows SDK headers (named at each declaration)
// and the Microsoft Learn pages for the functions.  Everything is internal to
// this script. PowerShell only sees EtwWatch.ProviderSpec and EtwWatch.EtwSession.
namespace EtwWatch.WindowsSdk
{
    // Constants from the SDK headers (the header is named at each group).
    // Values are the numbers in the headers, not hand-computed.
    internal static class SdkConstants
    {
        // winerror.h
        public const uint ERROR_ACCESS_DENIED = 5;
        public const uint ERROR_ALREADY_EXISTS = 183;

        // wmistr.h: WNODE_HEADER.Flags, marks the header of a trace session
        // (EVENT_TRACE_PROPERTIES).
        public const uint WNODE_FLAG_TRACED_GUID = 0x00020000;

        // evntrace.h: EVENT_TRACE_PROPERTIES.LogFileMode, the session delivers
        // events in real time.
        public const uint EVENT_TRACE_REAL_TIME_MODE = 0x00000100;

        // evntrace.h: ControlTrace control codes.
        public const uint EVENT_TRACE_CONTROL_QUERY = 0;
        public const uint EVENT_TRACE_CONTROL_STOP = 1;

        // evntrace.h: EnableTraceEx2 control code.
        public const uint EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1;

        // evntcons.h: EVENT_TRACE_LOGFILE.ProcessTraceMode. Without
        // PROCESS_TRACE_MODE_RAW_TIMESTAMP, ProcessTrace converts the event
        // header time stamp to system time (FILETIME).
        public const uint PROCESS_TRACE_MODE_REAL_TIME = 0x00000100;
        public const uint PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000;

        // evntcons.h: EVENT_HEADER_EXTENDED_DATA_ITEM.ExtType of the
        // TraceLogging event schema.
        public const ushort EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL = 0x000B;

        // evntrace.h: EVENT_TRACE_LOGFILEW.CurrentEvent is an EVENT_TRACE and
        // LogfileHeader a TRACE_LOGFILE_HEADER. They are never read here, so
        // they are only byte arrays of their x64 sizes.
        public const int EVENT_TRACE_SIZE = 88;
        public const int TRACE_LOGFILE_HEADER_SIZE = 280;

        // WNODE_HEADER.ClientContext value that makes the session stamp events
        // with the query performance counter. Documented at
        // https://learn.microsoft.com/en-us/windows/win32/etw/wnode-header (the
        // header only says "Reserved").
        public const uint WNODE_CLIENT_CONTEXT_QPC = 1;
    }

    // TraceLogging field types ("in-types") that appear in an event's metadata.
    // The numbers are the TlgIn_t enumerators of TraceLoggingProvider.h
    // (Windows SDK, shared folder), named here without the Tlg/TlgIn prefix;
    // the same numbers are the TDH_INTYPE_ values of tdh.h.  All of them are
    // listed, including the types that ReadValue does not decode.
    internal static class TlgIn
    {
        public const int NULL = 0;                  // invalid
        public const int UNICODESTRING = 1;         // UTF-16, NUL-terminated
        public const int ANSISTRING = 2;            // MBCS (UTF-8 here), NUL-terminated
        public const int INT8 = 3;
        public const int UINT8 = 4;
        public const int INT16 = 5;
        public const int UINT16 = 6;
        public const int INT32 = 7;
        public const int UINT32 = 8;
        public const int INT64 = 9;
        public const int UINT64 = 10;
        public const int FLOAT = 11;
        public const int DOUBLE = 12;
        public const int BOOL32 = 13;
        public const int BINARY = 14;               // UINT16 byte count, then the bytes
        public const int GUID = 15;
        public const int POINTER_UNSUPPORTED = 16;  // _TlgInPOINTER_unsupported: "Do not use"
        public const int FILETIME = 17;
        public const int SYSTEMTIME = 18;
        public const int SID = 19;
        public const int HEXINT32 = 20;
        public const int HEXINT64 = 21;
        public const int COUNTEDSTRING = 22;        // UINT16 byte count, then UTF-16
        public const int COUNTEDANSISTRING = 23;    // UINT16 byte count, then MBCS
        public const int STRUCT = 24;               // _TlgInSTRUCT: groups the following fields
        public const int COUNTEDBINARY = 25;        // UINT16 byte count, then the bytes

        // The InType byte of a field also holds flags (_TlgInTypeMask, _TlgInCcount, TlgInVcount,
        // _TlgInChain, _TlgInCountMask).
        public const int TYPE_MASK = 31;            // the type number
        public const int CCOUNT = 32;               // fixed-length array: a UINT16 count follows in the metadata
        public const int VCOUNT = 64;               // variable-length array: a UINT16 count precedes the data
        public const int CHAIN = 128;               // an OutType byte follows in the metadata
        public const int COUNT_MASK = VCOUNT | CCOUNT;
    }

    // TraceLogging formatting hints ("out-types"): the TlgOut_t enumerators of
    // TraceLoggingProvider.h.  They only say how to show a value (the encoding
    // is decided by the in-type), and a reader may ignore them.
    internal static class TlgOut
    {
        public const int NULL = 0;
        public const int NOPRINT = 1;
        public const int STRING = 2;
        public const int BOOLEAN = 3;               // with a UINT8
        public const int HEX = 4;
        public const int PID = 5;
        public const int TID = 6;
        public const int PORT = 7;
        public const int IPV4 = 8;
        public const int IPV6 = 9;
        public const int SOCKETADDRESS = 10;
        public const int XML = 11;
        public const int JSON = 12;
        public const int WIN32ERROR = 13;
        public const int NTSTATUS = 14;
        public const int HRESULT = 15;
        public const int FILETIME = 16;
        public const int SIGNED = 17;
        public const int UNSIGNED = 18;
        public const int UTF8 = 35;
        public const int PKCS7_WITH_TYPE_INFO = 36;
        public const int CODE_POINTER = 37;
        public const int DATETIME_UTC = 38;
        public const int TYPE_MASK = 127;           // _TlgOutTypeMask
        public const int CHAIN = 128;               // _TlgOutChain: a tag follows in the metadata
    }

    // PEVENT_RECORD_CALLBACK (evntrace.h): called by ProcessTrace for every event.
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate void EventRecordCallback(IntPtr eventRecord);

    // WNODE_HEADER (wmistr.h), the first member of EVENT_TRACE_PROPERTIES. The
    // header declares unions for HistoricalContext (or Version and Linkage) and
    // for TimeStamp, CountLost and KernelHandle; each is declared here as its
    // 8-byte member.
    [StructLayout(LayoutKind.Sequential)]
    internal struct WNODE_HEADER
    {
        public uint BufferSize;
        public uint ProviderId;
        public ulong HistoricalContext;
        public long TimeStamp;
        public Guid Guid;
        public uint ClientContext;
        public uint Flags;
    }

    // EVENT_TRACE_PROPERTIES (evntrace.h): the settings of a trace session.
    // AgeLimit is declared in a union with FlushThreshold.
    [StructLayout(LayoutKind.Sequential)]
    internal struct EVENT_TRACE_PROPERTIES
    {
        public WNODE_HEADER Wnode;
        public uint BufferSize;
        public uint MinimumBuffers;
        public uint MaximumBuffers;
        public uint MaximumFileSize;
        public uint LogFileMode;
        public uint FlushTimer;
        public uint EnableFlags;
        public int AgeLimit;
        public uint NumberOfBuffers;
        public uint FreeBuffers;
        public uint EventsLost;
        public uint BuffersWritten;
        public uint LogBuffersLost;
        public uint RealTimeBuffersLost;
        public IntPtr LoggerThreadId;
        public uint LogFileNameOffset;
        public uint LoggerNameOffset;
    }

    // EVENT_DESCRIPTOR (evntprov.h)
    [StructLayout(LayoutKind.Sequential)]
    internal struct EVENT_DESCRIPTOR
    {
        public ushort Id;
        public byte Version;
        public byte Channel;
        public byte Level;
        public byte Opcode;
        public ushort Task;
        public ulong Keyword;
    }

    // EVENT_HEADER (evntcons.h). ProcessorTime is declared in a union with
    // KernelTime and UserTime.
    [StructLayout(LayoutKind.Sequential)]
    internal struct EVENT_HEADER
    {
        public ushort Size;
        public ushort HeaderType;
        public ushort Flags;
        public ushort EventProperty;
        public uint ThreadId;
        public uint ProcessId;
        public long TimeStamp;
        public Guid ProviderId;
        public EVENT_DESCRIPTOR EventDescriptor;
        public ulong ProcessorTime;
        public Guid ActivityId;
    }

    // ETW_BUFFER_CONTEXT (evntrace.h). ProcessorIndex is declared in a union
    // with the two bytes ProcessorNumber and Alignment.
    [StructLayout(LayoutKind.Sequential)]
    internal struct ETW_BUFFER_CONTEXT
    {
        public ushort ProcessorIndex;
        public ushort LoggerId;
    }

    // EVENT_HEADER_EXTENDED_DATA_ITEM (evntcons.h). The 16 bits after ExtType
    // are the bit fields Linkage (1 bit) and Reserved2 (15 bits).
    [StructLayout(LayoutKind.Sequential)]
    internal struct EVENT_HEADER_EXTENDED_DATA_ITEM
    {
        public ushort Reserved1;
        public ushort ExtType;
        public ushort LinkageAndReserved2;
        public ushort DataSize;
        public ulong DataPtr;
    }

    // EVENT_RECORD (evntcons.h): what ProcessTrace passes to the event callback.
    [StructLayout(LayoutKind.Sequential)]
    internal struct EVENT_RECORD
    {
        public EVENT_HEADER EventHeader;
        public ETW_BUFFER_CONTEXT BufferContext;
        public ushort ExtendedDataCount;
        public ushort UserDataLength;
        public IntPtr ExtendedData;
        public IntPtr UserData;
        public IntPtr UserContext;
    }

    // EVENT_TRACE_LOGFILEW (evntrace.h). The script never reads CurrentEvent
    // (an EVENT_TRACE) or LogfileHeader (a TRACE_LOGFILE_HEADER), so they are
    // only byte arrays of their sizes.
    [StructLayout(LayoutKind.Sequential)]
    internal struct EVENT_TRACE_LOGFILE
    {
        public IntPtr LogFileName;
        public IntPtr LoggerName;
        public long CurrentTime;
        public uint BuffersRead;
        public uint ProcessTraceMode;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = SdkConstants.EVENT_TRACE_SIZE)]
        public byte[] CurrentEvent;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = SdkConstants.TRACE_LOGFILE_HEADER_SIZE)]
        public byte[] LogfileHeader;
        public IntPtr BufferCallback;
        public uint BufferSize;
        public uint Filled;
        public uint EventsLost;
        public IntPtr EventRecordCallback;
        public uint IsKernelTrace;
        public IntPtr Context;
    }

    // Byte offsets of the EVENT_RECORD members that are read for every event,
    // and the layout of the extended data items it points to. They are taken
    // from the structs above once, because Marshal.OffsetOf is far too slow to
    // call per event, and are used with Marshal.ReadXxx so that no struct is
    // copied out of the event for each event. LayoutCheck.Verify() reads them
    // at start, so the values are ready before the first event and a wrong
    // field name fails at start, not silently inside the event callback.
    internal static class EventRecordLayout
    {
        static int Offset(Type type, string field)
        {
            return (int)Marshal.OffsetOf(type, field);
        }

        static readonly int header = Offset(typeof(EVENT_RECORD), "EventHeader");

        public static readonly int ProcessId = header + Offset(typeof(EVENT_HEADER), "ProcessId");
        public static readonly int TimeStamp = header + Offset(typeof(EVENT_HEADER), "TimeStamp");
        public static readonly int ProviderId = header + Offset(typeof(EVENT_HEADER), "ProviderId");
        public static readonly int ExtendedDataCount = Offset(typeof(EVENT_RECORD), "ExtendedDataCount");
        public static readonly int UserDataLength = Offset(typeof(EVENT_RECORD), "UserDataLength");
        public static readonly int ExtendedData = Offset(typeof(EVENT_RECORD), "ExtendedData");
        public static readonly int UserData = Offset(typeof(EVENT_RECORD), "UserData");

        public static readonly int ItemSize = Marshal.SizeOf(typeof(EVENT_HEADER_EXTENDED_DATA_ITEM));
        public static readonly int ItemExtType = Offset(typeof(EVENT_HEADER_EXTENDED_DATA_ITEM), "ExtType");
        public static readonly int ItemDataSize = Offset(typeof(EVENT_HEADER_EXTENDED_DATA_ITEM), "DataSize");
        public static readonly int ItemDataPtr = Offset(typeof(EVENT_HEADER_EXTENDED_DATA_ITEM), "DataPtr");
    }

    // Compares the struct definitions above with the x64 sizes and offsets that
    // a C++ compiler reported (sizeof and offsetof) for the same structures from
    // the Windows SDK headers.
    internal static class LayoutCheck
    {
        public static void Verify()
        {
            Check("sizeof(WNODE_HEADER)", Marshal.SizeOf(typeof(WNODE_HEADER)), 48);
            Check("sizeof(EVENT_TRACE_PROPERTIES)", Marshal.SizeOf(typeof(EVENT_TRACE_PROPERTIES)), 120);
            Check("sizeof(EVENT_DESCRIPTOR)", Marshal.SizeOf(typeof(EVENT_DESCRIPTOR)), 16);
            Check("sizeof(EVENT_HEADER)", Marshal.SizeOf(typeof(EVENT_HEADER)), 80);
            Check("sizeof(ETW_BUFFER_CONTEXT)", Marshal.SizeOf(typeof(ETW_BUFFER_CONTEXT)), 4);
            Check("sizeof(EVENT_HEADER_EXTENDED_DATA_ITEM)", EventRecordLayout.ItemSize, 16);
            Check("sizeof(EVENT_RECORD)", Marshal.SizeOf(typeof(EVENT_RECORD)), 112);
            Check("sizeof(EVENT_TRACE_LOGFILEW)", Marshal.SizeOf(typeof(EVENT_TRACE_LOGFILE)), 448);

            Check("offsetof(EVENT_HEADER, ProcessId)", EventRecordLayout.ProcessId, 12);
            Check("offsetof(EVENT_HEADER, TimeStamp)", EventRecordLayout.TimeStamp, 16);
            Check("offsetof(EVENT_HEADER, ProviderId)", EventRecordLayout.ProviderId, 24);
            Check("offsetof(EVENT_RECORD, ExtendedDataCount)", EventRecordLayout.ExtendedDataCount, 84);
            Check("offsetof(EVENT_RECORD, UserDataLength)", EventRecordLayout.UserDataLength, 86);
            Check("offsetof(EVENT_RECORD, ExtendedData)", EventRecordLayout.ExtendedData, 88);
            Check("offsetof(EVENT_RECORD, UserData)", EventRecordLayout.UserData, 96);
            Check("offsetof(EVENT_HEADER_EXTENDED_DATA_ITEM, ExtType)", EventRecordLayout.ItemExtType, 2);
            Check("offsetof(EVENT_HEADER_EXTENDED_DATA_ITEM, DataSize)", EventRecordLayout.ItemDataSize, 6);
            Check("offsetof(EVENT_HEADER_EXTENDED_DATA_ITEM, DataPtr)", EventRecordLayout.ItemDataPtr, 8);
            Check("offsetof(EVENT_TRACE_PROPERTIES, EventsLost)", Offset(typeof(EVENT_TRACE_PROPERTIES), "EventsLost"), 88);
            Check("offsetof(EVENT_TRACE_PROPERTIES, RealTimeBuffersLost)", Offset(typeof(EVENT_TRACE_PROPERTIES), "RealTimeBuffersLost"), 100);
            Check("offsetof(EVENT_TRACE_PROPERTIES, LoggerNameOffset)", Offset(typeof(EVENT_TRACE_PROPERTIES), "LoggerNameOffset"), 116);
        }

        static int Offset(Type type, string field)
        {
            return (int)Marshal.OffsetOf(type, field);
        }

        static void Check(string what, int actual, int expected)
        {
            if (actual != expected)
                throw new InvalidOperationException("Unexpected layout: " + what + " is " + actual + ", expected " + expected + ".");
        }
    }

    // Functions exported by advapi32.dll, declared in evntrace.h. Each is
    // documented on Microsoft Learn, under
    // https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ at the page
    // named here.
    internal static class Advapi32
    {
        // nf-evntrace-starttracew
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        public static extern uint StartTraceW(out ulong sessionHandle, string sessionName, IntPtr properties);

        // nf-evntrace-controltracew
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        public static extern uint ControlTraceW(ulong sessionHandle, string sessionName, IntPtr properties, uint controlCode);

        // nf-evntrace-enabletraceex2
        [DllImport("advapi32.dll")]
        public static extern uint EnableTraceEx2(ulong sessionHandle, ref Guid providerId, uint controlCode,
            byte level, ulong matchAnyKeyword, ulong matchAllKeyword, uint timeout, IntPtr enableParameters);

        // nf-evntrace-opentracew
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern ulong OpenTraceW(ref EVENT_TRACE_LOGFILE logfile);

        // nf-evntrace-processtrace
        [DllImport("advapi32.dll")]
        public static extern uint ProcessTrace(ref ulong handleArray, uint handleCount, IntPtr startTime, IntPtr endTime);

        // nf-evntrace-closetrace
        [DllImport("advapi32.dll")]
        public static extern uint CloseTrace(ulong traceHandle);
    }
}

namespace EtwWatch
{
    // One provider to enable. ETW keyword bits and levels are defined per
    // provider. Keywords and Level are the MatchAnyKeyword and Level arguments
    // of EnableTraceEx2, which defines how they select events:
    // https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2
    public sealed class ProviderSpec
    {
        public Guid Id;
        public ulong Keywords; // EnableTraceEx2 MatchAnyKeyword
        public byte Level;
        // Field names left out of the printed line.
        // The Pattern/ExcludePattern filters still see them.
        public string[] HideFields;
    }

    public static class EtwSession
    {
        static readonly ConcurrentQueue<string> Lines = new ConcurrentQueue<string>();
        public static volatile string WorkerError;

        // ETW's own loss counters, read from the session just before it is stopped.
        public static long EventsLost;
        public static long RealTimeBuffersLost;

        // Decoded lines waiting for Drain; a growing value means the caller is falling behind.
        public static int Backlog { get { return Lines.Count; } }

        // ControlTrace documents that a stop or query only needs the session
        // name and log file name offsets and that the maximum name length of
        // each is 1024 characters (UTF-16 here):
        // https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-controltracew
        const int MaxLogFileNameBytes = 1024 * 2;

        static readonly object Sync = new object();
        static string sessionName;
        static EventRecordCallback callback;
        static Thread worker;
        static ulong sessionHandle;
        static ulong traceHandle;
        static IntPtr loggerName = IntPtr.Zero;
        static bool started;
        static volatile bool stopping;
        static Regex[] includes = new Regex[0];
        static Regex[] excludes = new Regex[0];
        static ProviderInfo[] providerInfos = new ProviderInfo[0];
        static readonly Dictionary<uint, string> ProcessCache = new Dictionary<uint, string>();

        // Use invariant culture for printed field values that should not depend
        // on the user's locale.
        static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

        // Starting size for the per-event fields text. Measured on Chromium
        // events it is 57-177 characters (median 66), so 128 fits nearly all.
        // A longer one just makes the builder grow.
        const int FieldsCapacity = 128;

        class Field
        {
            public string Name;
            public int Type;
            public int OutType;
            public bool Unsupported;
        }

        // Per-provider data worked out once in Start, so each event needs only a
        // scan of this short array instead of formatting the provider GUID again.
        sealed class ProviderInfo
        {
            public Guid Id;
            // first 8 hex digits of the GUID, as printed on every line
            public string Prefix;
            // null when nothing is hidden for this provider
            public HashSet<string> Hidden;
        }

        static ProviderInfo FindProvider(Guid id)
        {
            ProviderInfo[] all = providerInfos;
            for (int i = 0; i < all.Length; i++)
            {
                if (all[i].Id == id) return all[i];
            }
            ProviderInfo unknown = new ProviderInfo();
            unknown.Id = id;
            unknown.Prefix = id.ToString().Substring(0, 8);
            return unknown;
        }

        static ProviderInfo[] BuildProviderInfos(ProviderSpec[] providers)
        {
            List<ProviderInfo> list = new List<ProviderInfo>();
            foreach (ProviderSpec p in providers)
            {
                ProviderInfo info = new ProviderInfo();
                info.Id = p.Id;
                info.Prefix = p.Id.ToString().Substring(0, 8);
                if (p.HideFields != null && p.HideFields.Length > 0)
                    info.Hidden = new HashSet<string>(p.HideFields, StringComparer.OrdinalIgnoreCase);
                list.Add(info);
            }
            return list.ToArray();
        }

        static Regex[] CompileAll(string[] patterns)
        {
            List<Regex> list = new List<Regex>();
            if (patterns != null)
            {
                foreach (string p in patterns)
                    list.Add(new Regex(p, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant));
            }
            return list.ToArray();
        }

        static bool MatchesAny(Regex[] regexes, string text)
        {
            for (int i = 0; i < regexes.Length; i++)
            {
                if (regexes[i].IsMatch(text)) return true;
            }
            return false;
        }

        static IntPtr AllocProps()
        {
            return AllocProps(0);
        }

        // extraBytes leaves room after the session name for strings that ETW
        // writes back, such as the log file name of an existing session being
        // stopped. If the buffer is too small, ControlTrace returns
        // ERROR_MORE_DATA (documented on the ControlTrace page above); when
        // stopping, ETW has already stopped the session by then.
        static IntPtr AllocProps(int extraBytes)
        {
            // EVENT_TRACE_PROPERTIES is followed in the same buffer by the session name
            // (LoggerNameOffset) and, when ETW writes it back, the log file name.
            int structSize = Marshal.SizeOf(typeof(EVENT_TRACE_PROPERTIES));
            int size = structSize + (sessionName.Length + 1) * 2 + extraBytes;

            EVENT_TRACE_PROPERTIES props = new EVENT_TRACE_PROPERTIES();
            props.Wnode.BufferSize = (uint)size;
            props.Wnode.ClientContext = SdkConstants.WNODE_CLIENT_CONTEXT_QPC;
            props.Wnode.Flags = SdkConstants.WNODE_FLAG_TRACED_GUID;
            props.BufferSize = 64;     // KB per buffer
            props.MinimumBuffers = 2;
            props.MaximumBuffers = 8;
            props.LogFileMode = SdkConstants.EVENT_TRACE_REAL_TIME_MODE;
            props.FlushTimer = 1;      // seconds
            props.LoggerNameOffset = (uint)structSize;

            IntPtr p = Marshal.AllocHGlobal(size);
            Marshal.Copy(new byte[size], 0, p, size);
            Marshal.StructureToPtr(props, p, false);
            return p;
        }

        static string Win32Message(uint code)
        {
            return new Win32Exception((int)code).Message + " (" + code + ")";
        }

        static string AccessHint(uint code)
        {
            return code == SdkConstants.ERROR_ACCESS_DENIED
                ? " Run elevated or join the 'Performance Log Users' group."
                : "";
        }

        // Each call uses a new properties buffer. ControlTrace overwrites it
        // with the stopped session's settings (log file, buffers, ...),
        // which must not be passed on to the next StartTrace.
        static uint StartSession()
        {
            IntPtr props = AllocProps();
            try { return Advapi32.StartTraceW(out sessionHandle, sessionName, props); }
            finally { Marshal.FreeHGlobal(props); }
        }

        // Stops a session by name, whatever its settings are.
        static uint StopSessionByName()
        {
            IntPtr props = AllocProps(MaxLogFileNameBytes);
            try { return Advapi32.ControlTraceW(0, sessionName, props, SdkConstants.EVENT_TRACE_CONTROL_STOP); }
            finally { Marshal.FreeHGlobal(props); }
        }

        public static void Start(
            string session,
            string[] patterns,
            string[] excludePatterns,
            ProviderSpec[] providers)
        {
            lock (Sync)
            {
                if (started) throw new InvalidOperationException("Already started.");
                // Throws if a struct definition no longer matches the SDK layout, and makes the
                // offsets used for every event ready before the first event arrives.
                LayoutCheck.Verify();

                sessionName = session;
                includes = CompileAll(patterns);
                excludes = CompileAll(excludePatterns);
                providerInfos = BuildProviderInfos(providers);
                stopping = false;
                WorkerError = null;
                EventsLost = 0;
                RealTimeBuffersLost = 0;

                // Remove leftovers from an earlier run in this PowerShell session
                string stale;
                while (Lines.TryDequeue(out stale)) { }
                lock (ProcessCache) { ProcessCache.Clear(); }

                uint startRc = StartSession();
                if (startRc == SdkConstants.ERROR_ALREADY_EXISTS)
                {
                    uint stopRc = StopSessionByName();
                    if (stopRc != 0)
                        throw new InvalidOperationException("Could not replace the existing session '" + sessionName + "': " + Win32Message(stopRc) + AccessHint(stopRc));
                    startRc = StartSession();
                }
                if (startRc != 0)
                    throw new InvalidOperationException("StartTrace failed: " + Win32Message(startRc) + AccessHint(startRc));

                started = true;
                try
                {
                    foreach (ProviderSpec p in providers)
                    {
                        Guid id = p.Id;
                        // MatchAllKeyword 0 = not used.
                        uint rc = Advapi32.EnableTraceEx2(sessionHandle, ref id,
                            SdkConstants.EVENT_CONTROL_CODE_ENABLE_PROVIDER, p.Level, p.Keywords, 0, 0, IntPtr.Zero);
                        if (rc != 0)
                            throw new InvalidOperationException("EnableTraceEx2 failed for " + id + ": " + Win32Message(rc));
                    }

                    callback = new EventRecordCallback(OnEvent);
                    loggerName = Marshal.StringToHGlobalUni(sessionName);
                    worker = new Thread(Worker);
                    worker.IsBackground = true;
                    worker.Name = "EtwWatch-ProcessTrace";
                    worker.Start();
                }
                catch (Exception)
                {
                    Stop();
                    throw;
                }
            }
        }

        public static void Stop()
        {
            lock (Sync)
            {
                if (!started) return;
                started = false;
                stopping = true;

                // The loss counters are session statistics, so query them before stopping.
                IntPtr stats = AllocProps();
                try
                {
                    if (Advapi32.ControlTraceW(sessionHandle, sessionName, stats, SdkConstants.EVENT_TRACE_CONTROL_QUERY) == 0)
                    {
                        EVENT_TRACE_PROPERTIES result =
                            (EVENT_TRACE_PROPERTIES)Marshal.PtrToStructure(stats, typeof(EVENT_TRACE_PROPERTIES));
                        EventsLost = result.EventsLost;
                        RealTimeBuffersLost = result.RealTimeBuffersLost;
                    }
                }
                finally { Marshal.FreeHGlobal(stats); }

                IntPtr props = AllocProps();
                try { Advapi32.ControlTraceW(sessionHandle, sessionName, props, SdkConstants.EVENT_TRACE_CONTROL_STOP); }
                finally { Marshal.FreeHGlobal(props); }

                if (worker != null) worker.Join(5000);
                if (traceHandle != 0 && traceHandle != ulong.MaxValue) Advapi32.CloseTrace(traceHandle);
                traceHandle = 0;
                if (loggerName != IntPtr.Zero) { Marshal.FreeHGlobal(loggerName); loggerName = IntPtr.Zero; }
            }
        }

        // Removes up to max queued lines (oldest first) and returns them.
        // An empty array means none were queued.
        public static string[] Drain(int max)
        {
            List<string> batch = new List<string>();
            string line;
            while (batch.Count < max && Lines.TryDequeue(out line)) batch.Add(line);
            return batch.ToArray();
        }

        // Runs on its own background thread, started once by Start(). Opens the
        // real-time session and calls ProcessTrace, which blocks and delivers every
        // event to OnEvent on this thread until the session is stopped. A failure
        // while the script is still running is left in WorkerError for the caller.
        static void Worker()
        {
            try
            {
                EVENT_TRACE_LOGFILE lf = new EVENT_TRACE_LOGFILE();
                lf.CurrentEvent = new byte[SdkConstants.EVENT_TRACE_SIZE];
                lf.LogfileHeader = new byte[SdkConstants.TRACE_LOGFILE_HEADER_SIZE];
                lf.LoggerName = loggerName;
                lf.ProcessTraceMode = SdkConstants.PROCESS_TRACE_MODE_REAL_TIME | SdkConstants.PROCESS_TRACE_MODE_EVENT_RECORD;
                lf.EventRecordCallback = Marshal.GetFunctionPointerForDelegate(callback);

                traceHandle = Advapi32.OpenTraceW(ref lf);
                if (traceHandle == ulong.MaxValue)
                {
                    // Not an error if Stop() has already been called.
                    if (!stopping) WorkerError =
                        "OpenTrace failed: " + Win32Message((uint)Marshal.GetLastWin32Error());

                    return;
                }

                ulong h = traceHandle;
                uint rc = Advapi32.ProcessTrace(ref h, 1, IntPtr.Zero, IntPtr.Zero);
                if (rc != 0 && !stopping) WorkerError = "ProcessTrace failed: " + Win32Message(rc);
            }
            catch (Exception e)
            {
                if (!stopping) WorkerError = e.Message;
            }
        }

        static void OnEvent(IntPtr record)
        {
            try { ProcessEvent(record); }
            catch (Exception) { }
        }

        static void AppendField(StringBuilder sb, string name, string value)
        {
            sb.Append(' ').Append(name).Append('=').Append(value);
        }

        // An "Extension" in the metadata (the tag of an event or of a field) is
        // one or more bytes, each with 7 bits of tag; the high bit of a byte
        // says that another byte follows (TraceLoggingProvider.h, "How to
        // encode metadata"). The tag is not used here, so it is only skipped.
        const int ExtensionMoreBit = 0x80;

        static void SkipExtension(byte[] meta, ref int idx, int limit)
        {
            while (idx < limit && (meta[idx++] & ExtensionMoreBit) != 0) { }
        }

        static void ProcessEvent(IntPtr rec)
        {
            // Members of the EVENT_RECORD, at offsets taken once from the
            // structs (see EventRecordLayout).
            int extCount = (ushort)Marshal.ReadInt16(rec, EventRecordLayout.ExtendedDataCount);
            if (extCount == 0) return;
            int userLen = (ushort)Marshal.ReadInt16(rec, EventRecordLayout.UserDataLength);
            IntPtr ext = Marshal.ReadIntPtr(rec, EventRecordLayout.ExtendedData);
            IntPtr user = Marshal.ReadIntPtr(rec, EventRecordLayout.UserData);
            uint pid = (uint)Marshal.ReadInt32(rec, EventRecordLayout.ProcessId);
            Guid provider = (Guid)Marshal.PtrToStructure(
                new IntPtr(rec.ToInt64() + EventRecordLayout.ProviderId), typeof(Guid));

            // The TraceLogging schema is one of the extended data items of the event.
            byte[] meta = null;
            for (int i = 0; i < extCount; i++)
            {
                IntPtr item = new IntPtr(ext.ToInt64() + (long)EventRecordLayout.ItemSize * i);
                int type = (ushort)Marshal.ReadInt16(item, EventRecordLayout.ItemExtType);
                int size = (ushort)Marshal.ReadInt16(item, EventRecordLayout.ItemDataSize);
                if (type == SdkConstants.EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL)
                {
                    meta = new byte[size];
                    Marshal.Copy(Marshal.ReadIntPtr(item, EventRecordLayout.ItemDataPtr), meta, 0, size);
                    break;
                }
            }
            if (meta == null || meta.Length < 4) return;

            byte[] payload = new byte[userLen];
            if (userLen > 0) Marshal.Copy(user, payload, 0, userLen);

            // The metadata is described under "How to encode metadata" in
            // TraceLoggingProvider.h (Windows SDK, shared folder). It is packed
            // with no padding:
            //   - Event: a 2-byte little-endian total size (these two bytes
            //     included), the event's tag bytes (see SkipExtension), the event
            //     name as a NUL-terminated UTF-8 string, and then the fields, up
            //     to the total size.
            //   - Field: its name as a NUL-terminated UTF-8 string, and one
            //     in-type byte (a TlgIn value plus flags). If TlgIn.CHAIN is set,
            //     an out-type byte follows (a TlgOut value) and, if TlgOut.CHAIN
            //     is set on that, the field's tag bytes after it.
            //   - Array types carry more in the metadata (an element count, or
            //     custom type information).  That is not read here: such a field
            //     is shown as <undecoded> and decoding stops there, so the fields
            //     after it are never used.
            int idx = 2;
            SkipExtension(meta, ref idx, meta.Length);
            string eventName = ReadCString(meta, ref idx);

            int total = Math.Min(meta[0] | (meta[1] << 8), meta.Length);
            List<Field> fields = new List<Field>();
            while (idx < total)
            {
                Field f = new Field();
                f.Name = ReadCString(meta, ref idx);
                if (idx >= total) break;
                int inType = meta[idx++];
                if ((inType & TlgIn.CHAIN) != 0 && idx < total)
                {
                    f.OutType = meta[idx++];
                    if ((f.OutType & TlgOut.CHAIN) != 0) SkipExtension(meta, ref idx, total);
                    f.OutType &= TlgOut.TYPE_MASK;
                }
                f.Type = inType & TlgIn.TYPE_MASK;
                f.Unsupported = (inType & TlgIn.COUNT_MASK) != 0;
                fields.Add(f);
            }

            // The filters see every field. Hidden fields are only left out of
            // the printed line, which is built separately when this provider
            // hides anything.
            ProviderInfo info = FindProvider(provider);
            StringBuilder all = new StringBuilder(FieldsCapacity);
            StringBuilder shown = info.Hidden == null ? null : new StringBuilder(FieldsCapacity);
            int pos = 0;
            foreach (Field f in fields)
            {
                string value;
                if (f.Unsupported || !ReadValue(payload, ref pos, f, out value))
                {
                    // Shown even for a hidden field. The fields after it cannot
                    // be decoded either.
                    AppendField(all, f.Name, "<undecoded>");
                    if (shown != null) AppendField(shown, f.Name, "<undecoded>");
                    break;
                }
                AppendField(all, f.Name, value);
                if (shown != null && !info.Hidden.Contains(f.Name)) AppendField(shown, f.Name, value);
            }

            string head = Describe(pid) + "  " + info.Prefix + "  " + eventName;
            string text = head + all;
            if (MatchesAny(excludes, text)) return;
            if (includes.Length > 0 && !MatchesAny(includes, text)) return;
            string printed = shown == null ? text : head + shown;
            Lines.Enqueue(EventTime(Marshal.ReadInt64(rec, EventRecordLayout.TimeStamp)).ToString("HH:mm:ss.fff", Inv) + "  " + printed);
        }

        // EVENT_HEADER.TimeStamp. The session clock is QPC (ClientContext = 1),
        // but ProcessTrace converts the stamp to system time (FILETIME, UTC)
        // unless PROCESS_TRACE_MODE_RAW_TIMESTAMP is set (see ProcessTraceMode on
        // https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_logfilew).
        // Shown as local time.
        static DateTime EventTime(long fileTime)
        {
            try { return DateTime.FromFileTime(fileTime); }
            catch (ArgumentOutOfRangeException) { return DateTime.Now; }
        }

        // Event, provider and field names in the metadata are UTF-8, NUL-terminated.
        static string ReadCString(byte[] b, ref int idx)
        {
            int start = idx;
            while (idx < b.Length && b[idx] != 0) idx++;
            string s = Encoding.UTF8.GetString(b, start, idx - start);
            if (idx < b.Length) idx++;
            return s;
        }

        // Reads one field's value from the event data. Data encoding is
        // described under "Encoding data" in TraceLoggingProvider.h. The values
        // are packed one after the other with no padding and scalars are
        // little-endian. A string is NUL-terminated, and the counted types
        // start with a UINT16 byte count.  The sizes of the fixed-size types
        // are in tdh.h (TDH_INTYPE_*, "Field size is N bytes").
        //
        // Returns false for the types that are not decoded (BINARY, SYSTEMTIME,
        // SID, STRUCT, COUNTEDBINARY, and POINTER_UNSUPPORTED, which the header
        // says not to use) and for data that is too short. The caller then
        // shows <undecoded> and stops, because the size of such a field, and so
        // where the next field starts, is not known.
        static bool ReadValue(byte[] p, ref int pos, Field f, out string value)
        {
            value = null;
            int n;
            switch (f.Type)
            {
                case TlgIn.UNICODESTRING:
                {
                    int start = pos;
                    while (pos + 1 < p.Length && (p[pos] != 0 || p[pos + 1] != 0)) pos += 2;
                    if (pos + 1 >= p.Length) return false;
                    value = Encoding.Unicode.GetString(p, start, pos - start);
                    pos += 2;
                    return true;
                }
                case TlgIn.ANSISTRING:
                {
                    int start = pos;
                    while (pos < p.Length && p[pos] != 0) pos++;
                    if (pos >= p.Length) return false;
                    value = Encoding.UTF8.GetString(p, start, pos - start);
                    pos++;
                    return true;
                }
                case TlgIn.COUNTEDSTRING:
                case TlgIn.COUNTEDANSISTRING:
                {
                    if (pos + 2 > p.Length) return false;
                    n = p[pos] | (p[pos + 1] << 8);
                    pos += 2;
                    if (pos + n > p.Length) return false;
                    value = f.Type == TlgIn.COUNTEDSTRING ? Encoding.Unicode.GetString(p, pos, n) : Encoding.UTF8.GetString(p, pos, n);
                    pos += n;
                    return true;
                }
            }

            switch (f.Type)
            {
                case TlgIn.INT8:
                case TlgIn.UINT8:
                    n = 1;
                    break;
                case TlgIn.INT16:
                case TlgIn.UINT16:
                    n = 2;
                    break;
                case TlgIn.INT32:
                case TlgIn.UINT32:
                case TlgIn.FLOAT:
                case TlgIn.BOOL32:
                case TlgIn.HEXINT32:
                    n = 4;
                    break;
                case TlgIn.INT64:
                case TlgIn.UINT64:
                case TlgIn.DOUBLE:
                case TlgIn.FILETIME:
                case TlgIn.HEXINT64:
                    n = 8;
                    break;
                case TlgIn.GUID:
                    n = 16;
                    break;
                default:
                    return false;
            }
            if (pos + n > p.Length) return false;

            // Signed and floating-point values depend on the current culture
            // (minus sign, decimal separator), so they are formatted with the
            // invariant culture. Unsigned values do not.
            //
            // An out-type only says how to show a value, so one that does not go
            // with the field's in-type, or that is not handled here, is ignored
            // and the value is shown in its default form. The out-types handled
            // here are described in TraceLoggingProvider.h (TlgOut_t, and the
            // TraceLogging* macros that attach them) and in tdh.h
            // (TDH_OUTTYPE_*).
            switch (f.Type)
            {
                case TlgIn.INT8: value = ((sbyte)p[pos]).ToString(Inv); break;
                case TlgIn.UINT8:
                    if (f.OutType == TlgOut.BOOLEAN)
                    {
                        value = p[pos] != 0 ? "true" : "false";
                    }
                    else if (f.OutType == TlgOut.HEX)
                    {
                        value = "0x" + p[pos].ToString("x");
                    }
                    else
                    {
                        value = p[pos].ToString();
                    }
                    break;
                case TlgIn.INT16: value = BitConverter.ToInt16(p, pos).ToString(Inv); break;
                case TlgIn.UINT16:
                    if (f.OutType == TlgOut.HEX)
                    {
                        value = "0x" + BitConverter.ToUInt16(p, pos).ToString("x");
                    }
                    else if (f.OutType == TlgOut.PORT)
                    {
                        // A port is stored big-endian (network byte order), unlike
                        // the other scalar types ("Encoding data" in TraceLoggingProvider.h).
                        value = ((p[pos] << 8) | p[pos + 1]).ToString();
                    }
                    else
                    {
                        value = BitConverter.ToUInt16(p, pos).ToString();
                    }
                    break;
                case TlgIn.INT32:
                    if (f.OutType == TlgOut.HRESULT)
                    {
                        value = "0x" + BitConverter.ToUInt32(p, pos).ToString("x");
                    }
                    else
                    {
                        value = BitConverter.ToInt32(p, pos).ToString(Inv);
                    }
                    break;
                case TlgIn.UINT32:
                    if (f.OutType == TlgOut.HEX ||
                        f.OutType == TlgOut.NTSTATUS ||
                        f.OutType == TlgOut.WIN32ERROR)
                    {
                        value = "0x" + BitConverter.ToUInt32(p, pos).ToString("x");
                    }
                    else if (f.OutType == TlgOut.IPV4)
                    {
                        // An IPv4 address is stored in network byte order as well (it
                        // is the raw sin_addr.s_addr), so the first byte is the first number.
                        value = p[pos] + "." + p[pos + 1] + "." + p[pos + 2] + "." + p[pos + 3];
                    }
                    else
                    {
                        value = BitConverter.ToUInt32(p, pos).ToString();
                    }
                    break;
                case TlgIn.INT64: value = BitConverter.ToInt64(p, pos).ToString(Inv); break;
                case TlgIn.UINT64:
                    if (f.OutType == TlgOut.HEX)
                    {
                        value = "0x" + BitConverter.ToUInt64(p, pos).ToString("x");
                    }
                    else
                    {
                        value = BitConverter.ToUInt64(p, pos).ToString();
                    }
                    break;
                case TlgIn.FLOAT: value = BitConverter.ToSingle(p, pos).ToString(Inv); break;
                case TlgIn.DOUBLE: value = BitConverter.ToDouble(p, pos).ToString(Inv); break;
                case TlgIn.BOOL32: value = BitConverter.ToInt32(p, pos) != 0 ? "true" : "false"; break;
                case TlgIn.GUID:
                {
                    byte[] g = new byte[16];
                    Array.Copy(p, pos, g, 0, 16);
                    value = new Guid(g).ToString();
                    break;
                }
                case TlgIn.HEXINT64: value = "0x" + BitConverter.ToUInt64(p, pos).ToString("x"); break;
                case TlgIn.FILETIME:
                    value = FormatFileTime(BitConverter.ToInt64(p, pos));
                    break;
                case TlgIn.HEXINT32: value = "0x" + BitConverter.ToUInt32(p, pos).ToString("x"); break;
            }
            pos += n;
            return true;
        }

        // The largest FILETIME that DateTime can hold (the end of year 9999).
        static readonly long MaxFileTime = DateTime.MaxValue.ToFileTimeUtc();

        // A FILETIME field counts 100 ns intervals since 1601-01-01. tdh.h says
        // (TDH_OUTTYPE_DATETIME) that it is usually, but not always, UTC, and
        // TlgOut.DATETIME_UTC marks it as UTC. It is always shown as UTC, for
        // example 2026-11-12T18:25:48.8321234Z: that is the quickest form (no time
        // zone lookup) and does not depend on the culture. A value that DateTime
        // cannot hold is shown as the number. It is range-checked and not caught,
        // because an exception costs far more than the formatting.
        static string FormatFileTime(long fileTime)
        {
            if (fileTime < 0 || fileTime > MaxFileTime) return fileTime.ToString(Inv);
            return DateTime.FromFileTimeUtc(fileTime).ToString("o", Inv);
        }

        // "name[pid]", plus ":type/subtype" when the process was started with
        // Chromium's --type= and --utility-sub-type= switches (kProcessType and
        // kUtilitySubType in content/public/common/content_switches.cc; the
        // type values such as renderer, gpu-process and utility are defined
        // next to them).
        // TODO: need better process tracking so that destroyed processes are
        // removed from ProcessCache.
        static string Describe(uint pid)
        {
            string d;
            lock (ProcessCache)
            {
                if (ProcessCache.TryGetValue(pid, out d)) return d;
            }

            string name = "?";
            try
            {
                using (Process p = Process.GetProcessById((int)pid))
                {
                    name = p.ProcessName;
                }
            }
            catch (Exception) { }

            string kind = "";
            try
            {
                using (ManagementObjectSearcher s = new ManagementObjectSearcher(
                    "SELECT CommandLine FROM Win32_Process WHERE ProcessId=" + pid))
                using (ManagementObjectCollection results = s.Get())
                {
                    foreach (ManagementBaseObject mo in results)
                    {
                        using (mo)
                        {
                            string cmd = mo["CommandLine"] as string;
                            if (cmd == null) continue;
                            Match t = Regex.Match(cmd, @"--type=([^\s""]+)");
                            Match sub = Regex.Match(cmd, @"--utility-sub-type=([^\s""]+)");
                            if (t.Success) kind = t.Groups[1].Value;
                            if (sub.Success)
                            {
                                string v = sub.Groups[1].Value;
                                kind += "/" + v.Substring(v.LastIndexOf('.') + 1);
                            }
                        }
                    }
                }
            }
            catch (Exception) { }

            d = name + (kind.Length > 0 ? ":" + kind : "") + "[" + pid + "]";
            lock (ProcessCache) { ProcessCache[pid] = d; }
            return d;
        }
    }
}
