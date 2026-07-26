#pragma warning disable BB0001 // Member order is incorrect
using System.Runtime.InteropServices;
using ControlR.Libraries.Api.Contracts.Dtos.Devices;
using ControlR.Libraries.Api.Contracts.Enums;
using ControlR.Web.Client.Helpers;

namespace ControlR.Web.Client.Tests;

public class DeviceDisplayTests
{
  [Fact]
  public void GetDisplayName_NameAliasCustomer_ReturnsAllSegments()
  {
    var device = CreateDevice("WS-01", alias: "Front Desk", customerName: "Acme");

    var result = DeviceDisplay.GetDisplayName(device);

    Assert.Equal("Name: WS-01 | Alias: Front Desk | Customer: Acme", result);
  }

  [Fact]
  public void GetDisplayName_NullAlias_OmitsAliasSegment()
  {
    var device = CreateDevice("WS-01", alias: null, customerName: "Acme");

    var result = DeviceDisplay.GetDisplayName(device);

    Assert.Equal("Name: WS-01 | Customer: Acme", result);
  }

  [Fact]
  public void GetDisplayName_WhitespaceAlias_OmitsAliasSegment()
  {
    var device = CreateDevice("WS-01", alias: "   ", customerName: "Acme");

    var result = DeviceDisplay.GetDisplayName(device);

    Assert.Equal("Name: WS-01 | Customer: Acme", result);
  }

  [Fact]
  public void GetDisplayName_NullCustomer_RendersEmDash()
  {
    var device = CreateDevice("WS-01", alias: null, customerName: null);

    var result = DeviceDisplay.GetDisplayName(device);

    Assert.Equal("Name: WS-01 | Customer: —", result);
  }

  [Fact]
  public void GetCustomerDisplay_WithCustomer_ReturnsName()
  {
    var device = CreateDevice("WS-01", customerName: "Acme");

    Assert.Equal("Acme", DeviceDisplay.GetCustomerDisplay(device));
  }

  [Fact]
  public void GetCustomerDisplay_NullCustomer_ReturnsEmDash()
  {
    var device = CreateDevice("WS-01", customerName: null);

    Assert.Equal("—", DeviceDisplay.GetCustomerDisplay(device));
  }

  [Fact]
  public void GetCustomerDisplay_WhitespaceCustomer_ReturnsEmDash()
  {
    var device = CreateDevice("WS-01", customerName: "  ");

    Assert.Equal("—", DeviceDisplay.GetCustomerDisplay(device));
  }

  private static DeviceResponseDto CreateDevice(string name, string? alias = null, string? customerName = null)
  {
    return new DeviceResponseDto(
      Name: name,
      AgentVersion: "1.0.0",
      CpuUtilization: 0,
      Id: Guid.NewGuid(),
      Is64Bit: true,
      IsOnline: true,
      LastSeen: DateTimeOffset.UtcNow,
      OsArchitecture: Architecture.X64,
      Platform: SystemPlatform.Windows,
      ProcessorCount: 8,
      ConnectionId: "connection",
      OsDescription: "OS",
      TenantId: Guid.NewGuid(),
      TotalMemory: 16,
      TotalStorage: 512,
      UsedMemory: 8,
      UsedStorage: 256,
      CurrentUsers: [],
      MacAddresses: [],
      PublicIpV4: "1.2.3.4",
      PublicIpV6: "::1",
      LocalIpV4: "10.0.0.1",
      LocalIpV6: "::1",
      Drives: [],
      IsOutdated: false)
    {
      Alias = alias,
      CustomerName = customerName
    };
  }
}
