using ControlR.Libraries.Api.Contracts.Dtos;
using ControlR.Libraries.Api.Contracts.FilterSort;

namespace ControlR.Web.Client.Components.Shared;

public sealed record ScopeOption(Guid Id, string DisplayName);

public partial class ScopeAutocomplete
{
  private PermissionScopeKind _previousScopeKind;
  private ScopeOption? _selected;

  [Parameter]
  public string? Class { get; set; }

  [Inject]
  public required IControlrApi ControlrApi { get; init; }

  [Parameter]
  public string Label { get; set; } = "Scope";

  [Parameter]
  public PermissionScopeKind ScopeKind { get; set; } = PermissionScopeKind.Tenant;

  [Parameter]
  public Guid? SelectedId { get; set; }

  [Parameter]
  public EventCallback<Guid?> SelectedIdChanged { get; set; }

  private string ImplicitScopeMessage => ScopeKind switch
  {
    PermissionScopeKind.Server => "Server-wide scope. No specific target is required.",
    _ => "Tenant-wide scope. No specific target is required."
  };
  private bool RequiresTarget => ScopeKind is PermissionScopeKind.Device or PermissionScopeKind.DeviceGroup;

  protected override void OnParametersSet()
  {
    if (ScopeKind == _previousScopeKind)
    {
      return;
    }

    _previousScopeKind = ScopeKind;
    _selected = null;
    _ = SelectedIdChanged.InvokeAsync(null);
  }

  private async Task HandleValueChanged(ScopeOption? value)
  {
    _selected = value;
    await SelectedIdChanged.InvokeAsync(value?.Id);
  }

  private async Task<IEnumerable<ScopeOption>> Search(string query, CancellationToken cancellationToken)
  {
    if (string.IsNullOrWhiteSpace(query) || query.Length < 2)
    {
      return [];
    }

    return ScopeKind switch
    {
      PermissionScopeKind.Device => await SearchDevices(query, cancellationToken),
      PermissionScopeKind.DeviceGroup => await SearchDeviceGroups(query, cancellationToken),
      _ => []
    };
  }

  private async Task<IEnumerable<ScopeOption>> SearchDeviceGroups(string query, CancellationToken cancellationToken)
  {
    var result = await ControlrApi.Internal.DeviceGroups.GetAll(cancellationToken);
    if (!result.IsSuccess)
    {
      return [];
    }

    return result.Value
      .Where(x => x.Name.Contains(query, StringComparison.OrdinalIgnoreCase))
      .Select(x => new ScopeOption(x.Id, x.Name));
  }

  private async Task<IEnumerable<ScopeOption>> SearchDevices(string query, CancellationToken cancellationToken)
  {
    var request = new DeviceSearchRequestDto
    {
      SearchText = query,
      HideOfflineDevices = false,
      Page = 0,
      PageSize = 10,
      SortDefinitions = [new DeviceColumnSort { PropertyName = nameof(DeviceResponseDto.Name), Descending = false, SortOrder = 0 }]
    };

    var response = await ControlrApi.Internal.Devices.SearchDevices(request, cancellationToken);
    if (!response.IsSuccess)
    {
      return [];
    }

    return (response.Value.Items ?? [])
      .Select(x => new ScopeOption(x.Id, x.Name));
  }
}
