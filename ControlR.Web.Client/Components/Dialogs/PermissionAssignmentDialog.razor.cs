using InternalDtos = ControlR.Libraries.Api.Contracts.Dtos.ServerApi.Internal;

namespace ControlR.Web.Client.Components.Dialogs;

public partial class PermissionAssignmentDialog : ComponentBase
{
  private IReadOnlyList<InternalDtos.PermissionCatalogEntryDto> _catalog = [];
  private PermissionEffect _effect = PermissionEffect.Allow;
  private bool _isEnabled = true;
  private string _notes = string.Empty;
  private string _permissionName = string.Empty;
  private Guid? _scopeId;
  private PermissionScopeKind _scopeKind = PermissionScopeKind.Tenant;
  private InternalDtos.PermissionCatalogEntryDto? _selectedPermission;

  public static DialogOptions DefaultOptions => new()
  {
    BackdropClick = false
  };

  [Inject]
  public required IControlrApi ControlrApi { get; init; }

  [Parameter]
  public InternalDtos.PermissionAssignmentDto? ExistingAssignment { get; set; }

  [CascadingParameter]
  public required IMudDialogInstance MudDialog { get; init; }

  [Inject]
  public required IPermissionCatalogStore PermissionCatalogStore { get; init; }

  [Parameter]
  public required Guid PrincipalId { get; set; }

  [Parameter]
  public required PermissionPrincipalKind PrincipalKind { get; set; }

  [Inject]
  public required ISnackbar Snackbar { get; init; }

  private bool IsEdit => ExistingAssignment is not null;

  protected override async Task OnInitializedAsync()
  {
    if (PermissionCatalogStore.Items.Count == 0)
    {
      await PermissionCatalogStore.Refresh();
    }

    _catalog = PermissionCatalogStore.Items;

    if (ExistingAssignment is { } existing)
    {
      _permissionName = existing.PermissionName;
      _selectedPermission = _catalog.FirstOrDefault(p => p.Name == existing.PermissionName);
      _effect = existing.Effect;
      _scopeKind = existing.ScopeKind;
      _scopeId = existing.ScopeId;
      _notes = existing.Notes ?? string.Empty;
      _isEnabled = existing.IsEnabled;
    }
  }

  private void Cancel() => MudDialog.Cancel();

  private void HandlePermissionChanged(InternalDtos.PermissionCatalogEntryDto? value)
  {
    _selectedPermission = value;
    _permissionName = value?.Name ?? string.Empty;
  }

  private async Task<IEnumerable<InternalDtos.PermissionCatalogEntryDto>> SearchPermissions(
    string query,
    CancellationToken cancellationToken)
  {
    if (string.IsNullOrWhiteSpace(query))
    {
      return _catalog;
    }

    await Task.CompletedTask;
    return _catalog.Where(p =>
      p.Name.Contains(query, StringComparison.OrdinalIgnoreCase) ||
      p.DisplayName.Contains(query, StringComparison.OrdinalIgnoreCase));
  }

  private async Task Submit()
  {
    if (string.IsNullOrWhiteSpace(_permissionName))
    {
      Snackbar.Add("Permission name is required", Severity.Error);
      return;
    }

    if (_scopeKind is PermissionScopeKind.Device or PermissionScopeKind.DeviceGroup or PermissionScopeKind.CustomerTenant && _scopeId is null)
    {
      Snackbar.Add("Select a scope target", Severity.Error);
      return;
    }

    if (ExistingAssignment is { } existing)
    {
      var updateRequest = new InternalDtos.UpdatePermissionAssignmentRequestDto(
        _permissionName,
        _effect,
        _scopeKind,
        _scopeId,
        string.IsNullOrWhiteSpace(_notes) ? null : _notes,
        _isEnabled);

      var result = await ControlrApi.Internal.PermissionAssignments.Update(existing.Id, updateRequest);
      if (!result.IsSuccess)
      {
        Snackbar.Add(result.Reason, Severity.Error);
        return;
      }

      Snackbar.Add("Assignment updated", Severity.Success);
      MudDialog.Close(DialogResult.Ok(true));
      return;
    }

    var createRequest = new InternalDtos.CreatePermissionAssignmentRequestDto(
      PrincipalKind,
      PrincipalId,
      _permissionName,
      _effect,
      _scopeKind,
      _scopeId,
      string.IsNullOrWhiteSpace(_notes) ? null : _notes);

    var createResult = await ControlrApi.Internal.PermissionAssignments.Create(createRequest);
    if (!createResult.IsSuccess)
    {
      Snackbar.Add(createResult.Reason, Severity.Error);
      return;
    }

    Snackbar.Add("Assignment created", Severity.Success);
    MudDialog.Close(DialogResult.Ok(true));
  }
}
