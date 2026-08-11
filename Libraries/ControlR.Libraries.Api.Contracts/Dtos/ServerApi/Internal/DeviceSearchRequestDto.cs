using ControlR.Libraries.Api.Contracts.FilterSort;

namespace ControlR.Libraries.Api.Contracts.Dtos.ServerApi.Internal;

public class DeviceSearchRequestDto
{
  public IReadOnlyList<Guid>? CustomerIds { get; set; }
  public FilterMatchMode DeviceGroupFilterMatchMode { get; set; }
  public IReadOnlyList<Guid>? DeviceGroupIds { get; set; }
  public IReadOnlyList<DeviceColumnFilter>? FilterDefinitions { get; set; }
  public bool HideOfflineDevices { get; set; }
  public bool ShowOnlyUntaggedDevices { get; set; }
  public bool ShowOnlyUngroupedDevices { get; set; }
  public int Page { get; set; }
  public int PageSize { get; set; }
  public string? SearchText { get; set; }
  public IReadOnlyList<DeviceColumnSort>? SortDefinitions { get; set; }
  public FilterMatchMode TagFilterMatchMode { get; set; }
  public IReadOnlyList<Guid>? TagIds { get; set; }
}
