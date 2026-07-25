using ControlR.Libraries.Api.Contracts.Enums;
using ControlR.Libraries.Api.Contracts.Dtos.ServerApi.Internal;
using Microsoft.AspNetCore.Components;

namespace ControlR.Web.Client.Components.Dialogs;

public partial class CreatePermissionAssignmentDialog : ComponentBase
{
  private List<PermissionCatalogEntryDto> _catalog = [];
  private PermissionEffect _effect = PermissionEffect.Allow;
  private string _notes = string.Empty;
  private string _permissionName = string.Empty;
  private string _scopeId = string.Empty;
  private PermissionScopeKind _scopeKind = PermissionScopeKind.Tenant;

  [Inject]
  public required IControlrApi ControlrApi { get; init; }

  [CascadingParameter]
  public required IMudDialogInstance MudDialog { get; set; }

  [Parameter]
  public required Guid PrincipalId { get; set; }

  [Parameter]
  public required PermissionPrincipalKind PrincipalKind { get; set; }

  [Inject]
  public required ISnackbar Snackbar { get; init; }

  protected override async Task OnInitializedAsync()
  {
    var result = await ControlrApi.Internal.PermissionAssignments.GetCatalog();
    if (result.IsSuccess)
    {
      _catalog = [.. result.Value];
    }
  }

  private void Cancel() => MudDialog.Cancel();

  private async Task Submit()
  {
    if (string.IsNullOrWhiteSpace(_permissionName))
    {
      Snackbar.Add("Permission name is required", Severity.Error);
      return;
    }

    Guid? scopeId = null;
    if (!string.IsNullOrWhiteSpace(_scopeId))
    {
      if (!Guid.TryParse(_scopeId, out var parsed))
      {
        Snackbar.Add("Invalid Scope ID format", Severity.Error);
        return;
      }
      scopeId = parsed;
    }

    var request = new CreatePermissionAssignmentRequestDto(
      PrincipalKind,
      PrincipalId,
      _permissionName,
      _effect,
      _scopeKind,
      scopeId,
      string.IsNullOrWhiteSpace(_notes) ? null : _notes);

    var result = await ControlrApi.Internal.PermissionAssignments.Create(request);
    if (!result.IsSuccess)
    {
      Snackbar.Add(result.Reason, Severity.Error);
      return;
    }

    Snackbar.Add("Assignment created", Severity.Success);
    MudDialog.Close(DialogResult.Ok(true));
  }
}
