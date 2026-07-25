using ControlR.Libraries.Api.Contracts.Enums;
using ControlR.Web.Client.Authz;
using Microsoft.AspNetCore.Components;
using InternalDtos = ControlR.Libraries.Api.Contracts.Dtos.ServerApi.Internal;

namespace ControlR.Web.Client.Components.Pages;

public partial class PermissionAssignments : ComponentBase
{
  private InternalDtos.PermissionAssignmentDto[]? _assignments;
  private bool _loading;
  private string _principalId = string.Empty;
  private string _principalKind = "User";

  [Inject]
  public required IControlrApi ControlrApi { get; init; }

  [Inject]
  public required IDialogService DialogService { get; init; }

  [Inject]
  public required ISnackbar Snackbar { get; init; }

  private async Task CreateAssignment()
  {
    if (!Guid.TryParse(_principalId, out var principalId))
    {
      Snackbar.Add("Invalid principal ID", Severity.Error);
      return;
    }

    var parameters = new DialogParameters<CreatePermissionAssignmentDialog>
    {
      { x => x.PrincipalKind, Enum.Parse<PermissionPrincipalKind>(_principalKind) },
      { x => x.PrincipalId, principalId }
    };

    var dialog = await DialogService.ShowAsync<CreatePermissionAssignmentDialog>("Create Assignment", parameters);
    var result = await dialog.Result;

    if (result is not null && !result.Canceled)
    {
      await LoadAssignments();
    }
  }

  private async Task DeleteAssignment(InternalDtos.PermissionAssignmentDto assignment)
  {
    var confirmed = await DialogService.ShowMessageBoxAsync(
      "Delete Assignment",
      $"Delete the \"{assignment.PermissionName}\" ({assignment.Effect}) assignment?",
      "Delete", "Cancel");

    if (!confirmed.GetValueOrDefault())
    {
      return;
    }

    var result = await ControlrApi.Internal.PermissionAssignments.Delete(assignment.Id);
    if (!result.IsSuccess)
    {
      Snackbar.Add(result.Reason, Severity.Error);
      return;
    }

    Snackbar.Add("Assignment deleted", Severity.Success);
    await LoadAssignments();
  }

  private async Task LoadAssignments()
  {
    if (!Guid.TryParse(_principalId, out var principalId))
    {
      Snackbar.Add("Invalid principal ID format", Severity.Error);
      return;
    }

    _loading = true;
    StateHasChanged();

    try
    {
      var result = await ControlrApi.Internal.PermissionAssignments.GetByPrincipal(_principalKind, principalId);
      if (result.IsSuccess)
      {
        _assignments = result.Value;
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
}
