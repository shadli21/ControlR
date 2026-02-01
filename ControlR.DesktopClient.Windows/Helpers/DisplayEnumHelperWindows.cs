using System.Drawing;
using System.Runtime.InteropServices;
using Windows.Win32;
using Windows.Win32.Graphics.Gdi;
using ControlR.DesktopClient.Common.Models;

namespace ControlR.DesktopClient.Windows.Helpers;

internal static class DisplayEnumHelperWindows
{
  private const int Cchdevicename = 32;

  private delegate bool EnumMonitorsDelegate(nint hMonitor, nint hdcMonitor, ref Rect lprcMonitor, nint dwData);

  public static List<DisplayInfo> GetDisplays()
  {
    var displays = new List<DisplayInfo>();

    EnumDisplayMonitors(
      nint.Zero,
      nint.Zero,
      (nint hMonitor, nint _, ref Rect _, nint _) =>
      {
        var mi = new MonitorInfoEx();
        mi.Size = Marshal.SizeOf(mi);
        var success = GetMonitorInfo(hMonitor, ref mi);
        if (!success)
        {
          return true;
        }

        // Try to determine the display DPI so we can populate LogicalMonitorArea and ScaleFactor.
        var scale = 1.0;

        var monitorRect = new Rectangle(
          mi.Monitor.Left,
          mi.Monitor.Top,
          mi.Monitor.Right - mi.Monitor.Left,
          mi.Monitor.Bottom - mi.Monitor.Top);

        unsafe
        {
          var devMode = new DEVMODEW { dmSize = (ushort)sizeof(DEVMODEW) };
          if (PInvoke.EnumDisplaySettings(mi.DeviceName, ENUM_DISPLAY_SETTINGS_MODE.ENUM_CURRENT_SETTINGS, ref devMode))
          {
            scale = devMode.dmLogPixels / 96.0;
          }
        }

        var logicalLeft = (int)Math.Round(monitorRect.Left / scale);
        var logicalTop = (int)Math.Round(monitorRect.Top / scale);
        var logicalWidth = (int)Math.Round(monitorRect.Width / scale);
        var logicalHeight = (int)Math.Round(monitorRect.Height / scale);

        var info = new DisplayInfo
        {
          DisplayName = $"Display {displays.Count + 1}",
          MonitorArea = monitorRect,
          LogicalMonitorArea = new Rectangle(logicalLeft, logicalTop, logicalWidth, logicalHeight),
          WorkArea = new Rectangle(
            mi.WorkArea.Left,
            mi.WorkArea.Top,
            mi.WorkArea.Right - mi.WorkArea.Left,
            mi.WorkArea.Bottom - mi.WorkArea.Top),
          IsPrimary = mi.Flags > 0,
          DeviceName = mi.DeviceName,
          Index = displays.Count,
          ScaleFactor = scale
        };
        
        displays.Add(info);

        return true;
      }, nint.Zero);

    return displays;
  }

  [DllImport("user32.dll")]
  private static extern bool EnumDisplayMonitors(nint hdc, nint lprcClip, EnumMonitorsDelegate lpfnEnum, nint dwData);

  [DllImport("user32.dll", CharSet = CharSet.Auto)]
  private static extern bool GetMonitorInfo(nint hMonitor, ref MonitorInfoEx lpmi);

  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
  private struct MonitorInfoEx
  {
    public int Size;
    public Rect Monitor;
    public Rect WorkArea;
    public uint Flags;

    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = Cchdevicename)]
    public string DeviceName;
  }

  [StructLayout(LayoutKind.Sequential)]
  private struct Rect
  {
    public int Left;
    public int Top;
    public int Right;
    public int Bottom;
  }
}