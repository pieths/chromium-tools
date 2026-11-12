// Copyright (c) 2026 Piet Hein Schouten
// SPDX-License-Identifier: MIT

// MfCapabilitiesProbe implementation (compiled with Add-Type).
// Windows PowerShell 5.1 compiles this as C# 5: avoid newer language features.
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;
using MfCapabilities.WindowsSdk;

// Windows declarations used by the probe below, kept in one place so that every
// Windows defined name, number and layout can be found and checked here. They
// are written by hand, only for what this script uses. Sources are the public
// Windows SDK headers (named at each declaration) and the Microsoft Learn pages
// for the functions. Everything is internal to this script. PowerShell only sees
// DisplayInfo and MfCapabilitiesProbe.
namespace MfCapabilities.WindowsSdk
{
    // Constants from the SDK headers (the header is named at each group).
    internal static class SdkConstants
    {
        // winerror.h
        public const int E_NOTIMPL = unchecked((int)0x80004001);

        // mfapi.h: MFStartup arguments. MF_VERSION is defined there as
        // (MF_SDK_VERSION << 16 | MF_API_VERSION), with the Windows 7 values.
        public const int MF_SDK_VERSION = 0x0002;
        public const int MF_API_VERSION = 0x0070;
        public const int MF_VERSION = (MF_SDK_VERSION << 16) | MF_API_VERSION;
        public const int MFSTARTUP_FULL = 0;

        // mfmediaengine.h: MF_MEDIA_ENGINE_CANPLAY, the answer of
        // IMFExtendedDRMTypeSupport::IsTypeSupportedEx.
        public const int MF_MEDIA_ENGINE_CANPLAY_NOT_SUPPORTED = 0;
        public const int MF_MEDIA_ENGINE_CANPLAY_MAYBE = 1;
        public const int MF_MEDIA_ENGINE_CANPLAY_PROBABLY = 2;

        // mfmediaengine.h: the media engine class factory, and the attribute
        // that gives the media engine a window.
        public static readonly Guid CLSID_MFMediaEngineClassFactory = new Guid("b44392da-499b-446b-a4cb-005fead0e6d5");
        public static readonly Guid MF_MEDIA_ENGINE_COREWINDOW = new Guid("fccae4dc-0b7f-41c2-9f96-4659948acddc");

        // winuser.h: window styles.
        public const int WS_POPUP = unchecked((int)0x80000000);
        public const int WS_EX_TOOLWINDOW = 0x00000080;
        public const int WS_EX_NOACTIVATE = 0x08000000;

        // windef.h: DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 is ((DPI_AWARENESS_CONTEXT)-4).
        public const int DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = -4;

        // shellscalingapi.h: MONITOR_DPI_TYPE, the kind of DPI that GetDpiForMonitor returns.
        public const int MDT_EFFECTIVE_DPI = 0;
    }

    // IMFExtendedDRMTypeSupport (mfmediaengine.h)
    [ComImport, Guid("332EC562-3758-468D-A784-E38F23552128"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface IMFExtendedDRMTypeSupport
    {
        [PreserveSig]
        int IsTypeSupportedEx(
            [MarshalAs(UnmanagedType.BStr)] string type,
            [MarshalAs(UnmanagedType.BStr)] string keySystem, out int answer);
    }

    // IMFAttributes (mfobjects.h)
    [ComImport, Guid("2cd2d921-c447-44a7-a13c-4adabfc247e3"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface IMFAttributes
    {
        // Vtable slots 3-26 are unused here; they are declared only to reach SetUnknown (slot 27).
        void s03(); void s04(); void s05(); void s06(); void s07(); void s08(); void s09(); void s10();
        void s11(); void s12(); void s13(); void s14(); void s15(); void s16(); void s17(); void s18();
        void s19(); void s20(); void s21(); void s22(); void s23(); void s24(); void s25(); void s26();
        [PreserveSig] int SetUnknown(ref Guid key, [MarshalAs(UnmanagedType.IUnknown)] object value);
    }

    // Windows.UI.Core.ICoreWindow (windows.ui.core.h), declared empty, see FakeCoreWindow.
    [ComImport, Guid("79B9D5F2-879E-4B89-B798-79E47598030C"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface ICoreWindow { }

    // ICoreWindowInterop (CoreWindow.h, in the winrt folder)
    [ComImport, Guid("45D64A29-A63E-4CB6-B498-5781D298CB4F"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface ICoreWindowInterop
    {
        [PreserveSig] int get_WindowHandle(out IntPtr hwnd);
        [PreserveSig] int put_MessageHandled(byte value);
    }

    // IDXGIFactory (dxgi.h)
    [ComImport, Guid("7b7166ec-21c7-44ae-b21a-c9ae321ae369"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface IDXGIFactory
    {
        void s03(); void s04(); void s05(); void s06();
        [PreserveSig] int EnumAdapters(uint index, out IDXGIAdapter adapter);
    }

    // IDXGIAdapter (dxgi.h)
    [ComImport, Guid("2411e7e1-12ac-4ccf-bd14-9798e8534dc0"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface IDXGIAdapter
    {
        void s03(); void s04(); void s05(); void s06();
        [PreserveSig] int EnumOutputs(uint index, [MarshalAs(UnmanagedType.IUnknown)] out object output);
        [PreserveSig] int GetDesc(out DXGI_ADAPTER_DESC desc);
    }

    // IDXGIOutput6 (dxgi1_6.h)
    [ComImport, Guid("068346e8-aaec-4b84-add7-137f513f77a1"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface IDXGIOutput6
    {
        // Vtable slots 3-26 are unused here; they are declared only to reach GetDesc1 (slot 27).
        void s03(); void s04(); void s05(); void s06(); void s07(); void s08(); void s09(); void s10();
        void s11(); void s12(); void s13(); void s14(); void s15(); void s16(); void s17(); void s18();
        void s19(); void s20(); void s21(); void s22(); void s23(); void s24(); void s25(); void s26();
        [PreserveSig] int GetDesc1(out DXGI_OUTPUT_DESC1 desc);
    }

    // DXGI_ADAPTER_DESC (dxgi.h). AdapterLuid (a LUID) is declared as its two
    // members, LuidLow (LowPart) and LuidHigh (HighPart).
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct DXGI_ADAPTER_DESC
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string Description;
        public uint VendorId, DeviceId, SubSysId, Revision;
        public UIntPtr DedicatedVideoMemory, DedicatedSystemMemory, SharedSystemMemory;
        public uint LuidLow; public int LuidHigh;
    }

    // DXGI_OUTPUT_DESC1 (dxgi1_6.h). DesktopCoordinates (a RECT) is declared as
    // Left, Top, Right and Bottom. The arrays RedPrimary, GreenPrimary,
    // BluePrimary and WhitePoint, each of two floats, are declared as Rx, Ry,
    // Gx, Gy, Bx, By, Wx and Wy.
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct DXGI_OUTPUT_DESC1
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string DeviceName;
        public int Left, Top, Right, Bottom, AttachedToDesktop, Rotation;
        public IntPtr Monitor;
        public uint BitsPerColor;
        public int ColorSpace;
        public float Rx, Ry, Gx, Gy, Bx, By, Wx, Wy, MinLuminance, MaxLuminance, MaxFullFrameLuminance;
    }

    // Functions exported by dxgi.dll, declared in dxgi.h. Each is documented on
    // Microsoft Learn, under https://learn.microsoft.com/en-us/windows/win32/api/dxgi/
    // at the page named here.
    internal static class Dxgi
    {
        // nf-dxgi-createdxgifactory1
        [DllImport("dxgi.dll")]
        public static extern int CreateDXGIFactory1(ref Guid riid, out IDXGIFactory factory);
    }

    // Functions exported by mfplat.dll, declared in mfapi.h. Each is documented
    // on Microsoft Learn, under https://learn.microsoft.com/en-us/windows/win32/api/mfapi/
    // at the page named here.
    internal static class Mfplat
    {
        // nf-mfapi-mfstartup
        [DllImport("mfplat.dll")]
        public static extern int MFStartup(int version, int flags);
    }

    // Functions exported by user32.dll, declared in winuser.h. Each is
    // documented on Microsoft Learn, under https://learn.microsoft.com/en-us/windows/win32/api/winuser/
    // at the page named here.
    internal static class User32
    {
        // nf-winuser-setthreaddpiawarenesscontext
        [DllImport("user32.dll")]
        public static extern IntPtr SetThreadDpiAwarenessContext(IntPtr context);

        // nf-winuser-createwindowexw
        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        public static extern IntPtr CreateWindowExW(int exStyle, string cls, string name, int style, int x, int y,
            int w, int h, IntPtr parent, IntPtr menu, IntPtr inst, IntPtr param);

        // nf-winuser-destroywindow
        [DllImport("user32.dll")]
        public static extern bool DestroyWindow(IntPtr hwnd);
    }

    // Functions exported by shcore.dll, declared in shellscalingapi.h. Each is
    // documented on Microsoft Learn, under https://learn.microsoft.com/en-us/windows/win32/api/shellscalingapi/
    // at the page named here.
    internal static class Shcore
    {
        // nf-shellscalingapi-getdpiformonitor
        [DllImport("shcore.dll")]
        public static extern int GetDpiForMonitor(IntPtr monitor, int type, out uint dpiX, out uint dpiY);
    }
}

public class DisplayInfo
{
    public string Display, Adapter, VendorId;
    public int X, Y, Width, Height, BitsPerColor, ColorSpace, Dpi;
    public float MaxLuminance;
}

// A fake ICoreWindow is set as the MF_MEDIA_ENGINE_COREWINDOW attribute on
// Media Foundation's IMFExtendedDRMTypeSupport interface so that Media
// Foundation can pick a GPU adapter based on the HWND's monitor.
// ICoreWindowInterop::get_WindowHandle() is the only method that is needed so
// the ICoreWindow can be empty.
[ComVisible(true), ClassInterface(ClassInterfaceType.None)]
class FakeCoreWindow : ICoreWindow, ICoreWindowInterop
{
    readonly IntPtr hwnd;
    public FakeCoreWindow(IntPtr hwnd) { this.hwnd = hwnd; }
    public int get_WindowHandle(out IntPtr h) { h = hwnd; return 0; }
    public int put_MessageHandled(byte value) { return SdkConstants.E_NOTIMPL; }
}

public static class MfCapabilitiesProbe
{
    // Runs 'work' on a per-monitor DPI aware MTA thread
    // so DXGI and window coordinates are physical pixels.
    static T RunOnMtaThread<T>(Func<T> work)
    {
        T result = default(T);
        var t = new Thread(() =>
        {
            User32.SetThreadDpiAwarenessContext(new IntPtr(SdkConstants.DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2));
            result = work();
        });
        t.SetApartmentState(ApartmentState.MTA);
        t.Start();
        t.Join();
        return result;
    }

    public static List<DisplayInfo> GetDisplays() { return RunOnMtaThread(() => GetDisplaysOnThread()); }

    // If 'display' is not null, a hidden window covering that display is passed to
    // Media Foundation through MF_MEDIA_ENGINE_COREWINDOW.
    public static string Query(DisplayInfo display, string keySystem, string type)
    {
        return RunOnMtaThread(() => QueryOnThread(display, keySystem, type));
    }

    static List<DisplayInfo> GetDisplaysOnThread()
    {
        var list = new List<DisplayInfo>();
        Guid iid = typeof(IDXGIFactory).GUID;
        IDXGIFactory factory;
        Marshal.ThrowExceptionForHR(Dxgi.CreateDXGIFactory1(ref iid, out factory));
        IDXGIAdapter adapter;
        for (uint a = 0; factory.EnumAdapters(a, out adapter) == 0; a++)
        {
            DXGI_ADAPTER_DESC ad;
            adapter.GetDesc(out ad);
            object o;
            for (uint i = 0; adapter.EnumOutputs(i, out o) == 0; i++)
            {
                DXGI_OUTPUT_DESC1 d;
                ((IDXGIOutput6)o).GetDesc1(out d);
                uint dpi, dpiY;
                Shcore.GetDpiForMonitor(d.Monitor, SdkConstants.MDT_EFFECTIVE_DPI, out dpi, out dpiY);
                list.Add(new DisplayInfo
                {
                    Display = d.DeviceName,
                    Adapter = ad.Description,
                    VendorId = ad.VendorId.ToString("X4"),
                    X = d.Left,
                    Y = d.Top,
                    Width = d.Right - d.Left,
                    Height = d.Bottom - d.Top,
                    Dpi = (int)dpi,
                    BitsPerColor = (int)d.BitsPerColor,
                    ColorSpace = d.ColorSpace,
                    MaxLuminance = d.MaxLuminance
                });
            }
        }
        return list;
    }

    static string QueryOnThread(DisplayInfo display, string keySystem, string type)
    {
        Mfplat.MFStartup(SdkConstants.MF_VERSION, SdkConstants.MFSTARTUP_FULL);
        object engine = Activator.CreateInstance(Type.GetTypeFromCLSID(SdkConstants.CLSID_MFMediaEngineClassFactory));
        IntPtr hwnd = IntPtr.Zero;
        try
        {
            if (display != null)
            {
                // WS_POPUP, never shown. Inset by 1px so it stays within the display.
                hwnd = User32.CreateWindowExW(SdkConstants.WS_EX_NOACTIVATE | SdkConstants.WS_EX_TOOLWINDOW,
                                              "STATIC", "", SdkConstants.WS_POPUP,
                                              display.X + 1, display.Y + 1, display.Width - 2, display.Height - 2,
                                              IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
                Guid coreWindowKey = SdkConstants.MF_MEDIA_ENGINE_COREWINDOW;
                int hr = ((IMFAttributes)engine).SetUnknown(ref coreWindowKey, new FakeCoreWindow(hwnd));
                if (hr < 0) return "ERROR(SetUnknown) 0x" + hr.ToString("X8");
            }
            // MAYBE is only returned while HDCP is being negotiated; poll up to ~10s as MF docs advise.
            int answer = 0;
            for (int i = 0; i < 20; i++)
            {
                int hr = ((IMFExtendedDRMTypeSupport)engine).IsTypeSupportedEx(type, keySystem, out answer);
                if (hr < 0) return "ERROR 0x" + hr.ToString("X8");
                if (answer != SdkConstants.MF_MEDIA_ENGINE_CANPLAY_MAYBE) break;
                Thread.Sleep(500);
            }
            return answer == SdkConstants.MF_MEDIA_ENGINE_CANPLAY_PROBABLY ? "PROBABLY"
                 : answer == SdkConstants.MF_MEDIA_ENGINE_CANPLAY_MAYBE ? "MAYBE"
                 : "NOT_SUPPORTED";
        }
        finally
        {
            if (hwnd != IntPtr.Zero) User32.DestroyWindow(hwnd);
            Marshal.ReleaseComObject(engine);
        }
    }
}
