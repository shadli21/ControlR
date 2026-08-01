using Microsoft.AspNetCore.Components.Authorization;
using InternalDtos = ControlR.Libraries.Api.Contracts.Dtos.ServerApi.Internal;

namespace ControlR.Web.Client.Components.Pages;

public partial class Users : ComponentBase
{
  private Guid? _currentUserId;
  private bool _loading;
  private string _searchString = string.Empty;
  private IEnumerable<InternalDtos.UserResponseDto> _users = [];

  [Inject]
  public required AuthenticationStateProvider AuthState { get; init; }

  [Inject]
  public required IClipboardManager ClipboardManager { get; init; }

  [Inject]
  public required IControlrApi ControlrApi { get; init; }

  [Inject]
  public required IDialogService DialogService { get; init; }

  [Inject]
  public required ISnackbar Snackbar { get; init; }

  private Func<InternalDtos.UserResponseDto, bool> QuickFilter => user =>
  {
    if (string.IsNullOrWhiteSpace(_searchString))
    {
      return true;
    }

    return (user.UserName?.Contains(_searchString, StringComparison.OrdinalIgnoreCase) ?? false) ||
           (user.Email?.Contains(_searchString, StringComparison.OrdinalIgnoreCase) ?? false);
  };

  protected override async Task OnInitializedAsync()
  {
    var state = await AuthState.GetAuthenticationStateAsync();
    if (state.User.TryGetUserId(out var currentUserId))
    {
      _currentUserId = currentUserId;
    }

    await Refresh();
  }

  private async Task CopyId(Guid id)
  {
    await ClipboardManager.SetText(id.ToString());
    Snackbar.Add("Copied to clipboard", Severity.Success);
  }

  private async Task DeleteUser(InternalDtos.UserResponseDto user)
  {
    var confirmed = await DialogService.ShowMessageBoxAsync(
      "Delete User",
      $"Are you sure you want to delete \"{user.UserName}\"? This will permanently remove the user and all of their access.",
      "Delete", "Cancel");

    if (!confirmed.GetValueOrDefault())
    {
      return;
    }

    var result = await ControlrApi.Internal.Users.DeleteUser(user.Id);
    if (!result.IsSuccess)
    {
      Snackbar.Add(result.Reason, Severity.Error);
      return;
    }

    Snackbar.Add("User deleted", Severity.Success);
    await Refresh();
  }

  private async Task EditPermissions(InternalDtos.UserResponseDto user)
  {
    var parameters = new DialogParameters<PermissionAssignmentPanelDialog>
    {
      { x => x.PrincipalKind, PermissionPrincipalKind.User },
      { x => x.PrincipalId, user.Id }
    };

    await DialogService.ShowAsync<PermissionAssignmentPanelDialog>(
      $"Permissions: {user.UserName ?? user.Email ?? user.Id.ToString()}",
      parameters,
      PermissionAssignmentPanelDialog.DefaultOptions);
  }

  private async Task Refresh()
  {
    _loading = true;
    StateHasChanged();

    try
    {
      var result = await ControlrApi.Internal.Users.GetAllUsers();
      if (result.IsSuccess)
      {
        _users = result.Value;
      }
      else
      {
        Snackbar.Add(result.Reason, Severity.Error);
      }
    }
    finally
    {
      _loading = false;
      StateHasChanged();
    }
  }

  private string TruncateId(Guid id)
  {
    return $"{id.ToString()[..8]}...";
  }
}
