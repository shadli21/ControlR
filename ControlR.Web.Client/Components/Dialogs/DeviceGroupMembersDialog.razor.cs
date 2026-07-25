using ControlR.Libraries.Api.Contracts.Dtos;

namespace ControlR.Web.Client.Components.Dialogs;

public partial class DeviceGroupMembersDialog : ComponentBase
{
  private List<DeviceResponseDto> _devices = [];
  private bool _loading;
  private HashSet<Guid> _memberIds = [];

  [Inject]
  public required IControlrApi ControlrApi { get; init; }

  [Inject]
  public required IDialogService DialogService { get; init; }

  [Parameter]
  public required Guid GroupId { get; set; }

  [Parameter]
  public required string GroupName { get; set; }

  [CascadingParameter]
  public required IMudDialogInstance MudDialog { get; set; }

  [Inject]
  public required ISnackbar Snackbar { get; init; }

  private string _groupName => GroupName;

  protected override async Task OnInitializedAsync()
  {
    _loading = true;
    StateHasChanged();

    try
    {
      var groupResult = await ControlrApi.Internal.DeviceGroups.Get(GroupId);
      if (groupResult.IsSuccess)
      {
        _memberIds = [.. groupResult.Value.Members.Select(m => m.DeviceId)];
      }

      var searchResult = await ControlrApi.Internal.Devices.SearchDevices(
        new DeviceSearchRequestDto { Page = 0, PageSize = 1000 });
      if (searchResult.IsSuccess)
      {
        _devices = [.. (searchResult.Value.Items ?? []).OrderBy(d => d.Name)];
      }
    }
    finally
    {
      _loading = false;
      StateHasChanged();
    }
  }

  private void Cancel() => MudDialog.Cancel();

  private async Task ToggleDevice(Guid deviceId, bool isToggled)
  {
    ApiResult result;
    if (isToggled)
    {
      result = await ControlrApi.Internal.DeviceGroups.AddMembers(
        GroupId, new AddDeviceGroupMembersRequestDto([deviceId]));
      if (result.IsSuccess)
      {
        _memberIds.Add(deviceId);
      }
    }
    else
    {
      result = await ControlrApi.Internal.DeviceGroups.RemoveMembers(
        GroupId, new RemoveDeviceGroupMembersRequestDto([deviceId]));
      if (result.IsSuccess)
      {
        _memberIds.Remove(deviceId);
      }
    }

    if (!result.IsSuccess)
    {
      Snackbar.Add(result.Reason, Severity.Error);
    }

    StateHasChanged();
  }
}
