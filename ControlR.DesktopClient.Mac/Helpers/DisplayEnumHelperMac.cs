using ControlR.DesktopClient.Common.Models;
using ControlR.Libraries.NativeInterop.Unix.MacOs;
using Microsoft.Extensions.Logging;
using System.Drawing;

namespace ControlR.DesktopClient.Mac.Helpers;

internal interface IDisplayEnumHelperMac
{
  List<DisplayInfo> GetDisplays();
}

internal class DisplayEnumHelperMac(ILogger<DisplayEnumHelperMac> logger) : IDisplayEnumHelperMac
{
  private const uint MaxDisplays = 32;
  private readonly ILogger<DisplayEnumHelperMac> _logger = logger;

  public List<DisplayInfo> GetDisplays()
  {
    var displays = new List<DisplayInfo>();

    try
    {
      var displayIds = new uint[MaxDisplays];
      var result = CoreGraphics.CGGetOnlineDisplayList(MaxDisplays, displayIds, out var displayCount);

      if (result != 0 || displayCount == 0)
      {
        // Fallback to main display only
        _logger.LogWarning("DisplayEnumHelperMac: Using fallback, result={Result}, displayCount={Count}", result, displayCount);
        var mainDisplayId = CoreGraphics.CGMainDisplayID();
        return new List<DisplayInfo> { CreateDisplayInfo(mainDisplayId, 0, true) };
      }

      _logger.LogDebug("DisplayEnumHelperMac: Found {Count} displays", displayCount);
      for (var i = 0; i < displayCount; i++)
      {
        var displayId = displayIds[i];
        var isMain = CoreGraphics.CGDisplayIsMain(displayId);
        var displayInfo = CreateDisplayInfo(displayId, i, isMain);
        displays.Add(displayInfo);
      }
    }
    catch (Exception ex)
    {
      // Fallback to main display only
      _logger.LogError(ex, "DisplayEnumHelperMac: Exception occurred while enumerating displays");
      var mainDisplayId = CoreGraphics.CGMainDisplayID();
      displays.Add(CreateDisplayInfo(mainDisplayId, 0, true));
    }

    return displays;
  }

  private DisplayInfo CreateDisplayInfo(uint displayId, int index, bool isMain)
  {
    var bounds = CoreGraphics.CGDisplayBounds(displayId);
    var logicalWidth = (int)bounds.Width;
    var logicalHeight = (int)bounds.Height;
    
    // On macOS, CGDisplayPixelsWide/High return logical dimensions, not physical pixels
    // To get physical pixel dimensions, we need to capture the display and check the image size
    // Or use the backing scale factor. Let's try capturing to get the physical dimensions.
    nint testImageRef = nint.Zero;
    int physicalPixelWidth = logicalWidth;
    int physicalPixelHeight = logicalHeight;
    double scaleFactor = 1.0;
    
    try
    {
      // Create a test capture to get actual pixel dimensions
      testImageRef = CoreGraphics.CGDisplayCreateImage(displayId);
      if (testImageRef != nint.Zero)
      {
        physicalPixelWidth = (int)CoreGraphics.CGImageGetWidth(testImageRef);
        physicalPixelHeight = (int)CoreGraphics.CGImageGetHeight(testImageRef);
        
        // Calculate the backing scale factor (physical / logical)
        scaleFactor = Math.Max(
          (double)physicalPixelWidth / logicalWidth,
          (double)physicalPixelHeight / logicalHeight);
      }
    }
    catch
    {
      // If we can't capture, fall back to logical dimensions
      physicalPixelWidth = logicalWidth;
      physicalPixelHeight = logicalHeight;
      scaleFactor = 1.0;
    }
    finally
    {
      if (testImageRef != nint.Zero)
      {
        CoreGraphics.CFRelease(testImageRef);
      }
    }

    // The captured image will be in pixel coordinates starting from (0,0) for each display
    // But the MonitorArea should reflect the physical screen area for coordinate calculations
    var monitorArea = new Rectangle(
      (int)(bounds.X * scaleFactor), // Scale logical position to pixel position
      (int)(bounds.Y * scaleFactor), // Scale logical position to pixel position
      physicalPixelWidth, 
      physicalPixelHeight);

    // Debug logging - this will help identify coordinate mismatches
    _logger.LogDebug("Display {DisplayId}: Logical bounds={LogicalW}x{LogicalH} at ({X},{Y}), Physical pixel size={PhysW}x{PhysH}, Scale={Scale:F2}, MonitorArea={MAW}x{MAH} at ({MAX},{MAY})",
      displayId, logicalWidth, logicalHeight, bounds.X, bounds.Y, physicalPixelWidth, physicalPixelHeight, scaleFactor, monitorArea.Width, monitorArea.Height, monitorArea.X, monitorArea.Y);

    return new DisplayInfo
    {
      DeviceName = displayId.ToString(),
      DisplayName = $"Display {index + 1}",
      Index = index,
      IsPrimary = isMain,
      MonitorArea = monitorArea,
      WorkArea = monitorArea,
      ScaleFactor = scaleFactor
    };
  }
}
