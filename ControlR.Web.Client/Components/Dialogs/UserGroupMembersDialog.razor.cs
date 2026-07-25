using ControlR.Libraries.Api.Contracts.Dtos;
using ControlR.Libraries.Api.Contracts.Dtos.ServerApi.Internal;
using Microsoft.AspNetCore.Components;

namespace ControlR.Web.Client.Components.Dialogs;

public partial class UserGroupMembersDialog : ComponentBase
{
  private bool _loading;
  private HashSet<Guid> _memberIds = [];
  private List<UserResponseDto> _users = [];

  [Inject]
  public required IControlrApi ControlrApi { get; init; }

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
      var groupResult = await ControlrApi.Internal.UserGroups.Get(GroupId);
      if (groupResult.IsSuccess)
      {
        _memberIds = [.. groupResult.Value.Members.Select(m => m.UserId)];
      }

      var usersResult = await ControlrApi.Internal.Users.GetAllUsers();
      if (usersResult.IsSuccess)
      {
        _users = [.. usersResult.Value.OrderBy(u => u.UserName)];
      }
    }
    finally
    {
      _loading = false;
      StateHasChanged();
    }
  }

  private void Cancel() => MudDialog.Cancel();

  private async Task ToggleUser(Guid userId, bool isToggled)
  {
    ApiResult result;
    if (isToggled)
    {
      result = await ControlrApi.Internal.UserGroups.AddMembers(
        GroupId, new AddUserGroupMembersRequestDto([userId]));
      if (result.IsSuccess)
      {
        _memberIds.Add(userId);
      }
    }
    else
    {
      result = await ControlrApi.Internal.UserGroups.RemoveMembers(
        GroupId, new RemoveUserGroupMembersRequestDto([userId]));
      if (result.IsSuccess)
      {
        _memberIds.Remove(userId);
      }
    }

    if (!result.IsSuccess)
    {
      Snackbar.Add(result.Reason, Severity.Error);
    }

    StateHasChanged();
  }
}
