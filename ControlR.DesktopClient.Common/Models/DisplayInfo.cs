using System.Drawing;
using System.Numerics;

namespace ControlR.DesktopClient.Common.Models;

public class DisplayInfo
{
  public required string DeviceName { get; init; }
  public string DisplayName { get; set; } = string.Empty;
  public int Index { get; set; }
  public bool IsPrimary { get; init; }

  /// <summary>
  /// Monitor bounds expressed in logical (device-independent) units used by the OS/compositor.
  /// Use these when reasoning about layout, UI coordinates, or APIs that expect logical units.
  /// Conversion: physical = logical * ScaleFactor
  /// </summary>
  public Rectangle LogicalMonitorArea { get; init; }

  /// <summary>
  /// Monitor bounds expressed in physical/native pixels. Use this when dealing with image
  /// buffer sizes, frame captures, or any pixel-oriented operation.
  /// </summary>
  public Rectangle MonitorArea { get; init; }

  /// <summary>
  /// Scale factor to convert logical units to physical pixels.
  /// physical = logical * ScaleFactor
  /// </summary>
  public double ScaleFactor { get; set; } = 1;

  /// <summary>
  /// Work area (physical pixels) available on the monitor.
  /// </summary>
  public Rectangle WorkArea { get; set; }
}
