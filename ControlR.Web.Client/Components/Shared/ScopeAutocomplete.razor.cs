using ControlR.Libraries.Api.Contracts.Dtos;

namespace ControlR.Web.Client.Components.Shared;

public sealed record ScopeOption(Guid Id, string DisplayName);

public partial class ScopeAutocomplete
{
  private PermissionScopeKind _previousScopeKind;
  private ScopeOption? _selected;
  private DeviceResponseDto? _selectedDevice;

  [Parameter]
  public string? Class { get; set; }

  [Inject]
  public required IControlrApi ControlrApi { get; init; }

  [Inject]
  public required IDialogService DialogService { get; init; }

  [Parameter]
  public string Label { get; set; } = "Scope";

  [Parameter]
  public PermissionScopeKind ScopeKind { get; set; } = PermissionScopeKind.Tenant;

  [Parameter]
  public Guid? SelectedId { get; set; }

  [Parameter]
  public EventCallback<Guid?> SelectedIdChanged { get; set; }

  private string DeviceDisplayText =>
    _selectedDevice is null ? string.Empty : DeviceDisplay.GetDisplayName(_selectedDevice);

  private string ImplicitScopeMessage => ScopeKind switch
  {
    PermissionScopeKind.Server => "Server-wide scope. No specific target is required.",
    _ => "Tenant-wide scope. No specific target is required."
  };

  private bool IsDeviceScope => ScopeKind == PermissionScopeKind.Device;

  private bool RequiresTarget => ScopeKind is PermissionScopeKind.Device or PermissionScopeKind.DeviceGroup;

  protected override void OnParametersSet()
  {
    if (ScopeKind == _previousScopeKind)
    {
      return;
    }

    _previousScopeKind = ScopeKind;
    _selected = null;
    _selectedDevice = null;
    _ = SelectedIdChanged.InvokeAsync(null);
  }

  private async Task ClearDevice()
  {
    _selectedDevice = null;
    await SelectedIdChanged.InvokeAsync(null);
  }

  private async Task HandleValueChanged(ScopeOption? value)
  {
    _selected = value;
    await SelectedIdChanged.InvokeAsync(value?.Id);
  }

  private async Task OpenDevicePicker()
  {
    var options = new DialogOptions { FullWidth = true, MaxWidth = MaxWidth.Medium };
    var dialog = await DialogService.ShowAsync<DevicePickerDialog>("Select Device", options);
    var result = await dialog.Result;

    if (result is null || result.Canceled || result.Data is not DeviceResponseDto device)
    {
      return;
    }

    _selectedDevice = device;
    await SelectedIdChanged.InvokeAsync(device.Id);
  }

  private async Task<IEnumerable<ScopeOption>> SearchDeviceGroups(string query, CancellationToken cancellationToken)
  {
    if (string.IsNullOrWhiteSpace(query) || query.Length < 2)
    {
      return [];
    }

    var result = await ControlrApi.Internal.DeviceGroups.GetAll(cancellationToken);
    if (!result.IsSuccess)
    {
      return [];
    }

    return result.Value
      .Where(x => x.Name.Contains(query, StringComparison.OrdinalIgnoreCase))
      .Select(x => new ScopeOption(x.Id, x.Name));
  }
}
