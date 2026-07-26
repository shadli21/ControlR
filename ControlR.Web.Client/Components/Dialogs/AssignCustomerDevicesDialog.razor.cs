using ControlR.Libraries.Api.Contracts.FilterSort;
using InternalDtos = ControlR.Libraries.Api.Contracts.Dtos.ServerApi.Internal;

namespace ControlR.Web.Client.Components.Dialogs;

public partial class AssignCustomerDevicesDialog : ComponentBase
{
  private const int PageSize = 10;

  private int _currentPage = 1;
  private List<DeviceResponseDto> _devices = [];
  private bool _loading;
  private string _searchText = string.Empty;
  private HashSet<Guid> _selectedIds = [];
  private int _totalPages = 1;

  [Inject]
  public required IControlrApi ControlrApi { get; init; }

  [Parameter]
  public required Guid CustomerId { get; set; }

  [CascadingParameter]
  public required IMudDialogInstance MudDialog { get; init; }

  [Inject]
  public required ISnackbar Snackbar { get; init; }

  protected override async Task OnInitializedAsync()
  {
    await LoadDevices();
  }

  private async Task Assign()
  {
    var result = await ControlrApi.Internal.Customers.AssignDevices(
      CustomerId, new InternalDtos.AssignCustomerDevicesRequestDto([.. _selectedIds]));

    if (!result.IsSuccess)
    {
      Snackbar.Add(result.Reason, Severity.Error);
      return;
    }

    Snackbar.Add($"Assigned {_selectedIds.Count} device(s)", Severity.Success);
    MudDialog.Close(DialogResult.Ok(true));
  }

  private void Cancel() => MudDialog.Cancel();

  private async Task LoadDevices()
  {
    _loading = true;
    await InvokeAsync(StateHasChanged);

    try
    {
      var request = new DeviceSearchRequestDto
      {
        SearchText = _searchText,
        HideOfflineDevices = false,
        Page = _currentPage - 1,
        PageSize = PageSize,
        SortDefinitions = [new DeviceColumnSort { PropertyName = nameof(DeviceResponseDto.Name), Descending = false, SortOrder = 0 }]
      };

      var response = await ControlrApi.Internal.Devices.SearchDevices(request);
      if (!response.IsSuccess)
      {
        Snackbar.Add("Failed to load devices", Severity.Error);
        return;
      }

      _devices = [.. response.Value.Items ?? []];
      _totalPages = Math.Max(1, (int)Math.Ceiling(response.Value.TotalItems / (double)PageSize));
    }
    finally
    {
      _loading = false;
      StateHasChanged();
    }
  }

  private async Task OnPageChanged(int page)
  {
    _currentPage = page;
    await LoadDevices();
  }

  private async Task OnSearchChanged(string _)
  {
    _currentPage = 1;
    await LoadDevices();
  }

  private void ToggleSelection(Guid deviceId, bool isSelected)
  {
    if (isSelected)
    {
      _selectedIds.Add(deviceId);
    }
    else
    {
      _selectedIds.Remove(deviceId);
    }
  }
}
