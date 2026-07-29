namespace ControlR.Web.Client.Components.Dialogs;

public partial class CredentialScopeDialog : ComponentBase
{
  private List<PermissionCatalogEntryDto> _catalog = [];
  private List<ScopeRow> _rows = [];

  [Inject]
  public required IControlrApi ControlrApi { get; init; }

  [Parameter]
  public required Guid CredentialId { get; set; }

  [Parameter]
  public required string CredentialName { get; set; }

  [CascadingParameter]
  public required IMudDialogInstance MudDialog { get; set; }

  [Inject]
  public required ISnackbar Snackbar { get; init; }

  protected override async Task OnInitializedAsync()
  {
    var catalogResult = await ControlrApi.Internal.PermissionAssignments.GetCatalog();
    if (catalogResult.IsSuccess)
    {
      _catalog = [.. catalogResult.Value.OrderBy(x => x.Name)];
    }

    var assignmentsResult = await ControlrApi.Internal.PermissionAssignments.GetByPrincipal(
      nameof(PermissionPrincipalKind.PersonalAccessToken), CredentialId);

    if (assignmentsResult.IsSuccess)
    {
      _rows = assignmentsResult.Value
        .Select(a => new ScopeRow(a.PermissionName, a.Effect, a.ScopeKind, a.ScopeId))
        .ToList();
    }

    if (_rows.Count == 0)
    {
      _rows.Add(new ScopeRow(
        _catalog.Count > 0 ? _catalog[0].Name : string.Empty,
        PermissionEffect.Allow,
        PermissionScopeKind.Tenant,
        null));
    }
  }

  private static ScopeRow CreateNewRow()
  {
    return new ScopeRow(string.Empty, PermissionEffect.Allow, PermissionScopeKind.Tenant, null);
  }

  private void AddRow()
  {
    _rows.Add(CreateNewRow());
  }

  private void Cancel() => MudDialog.Cancel();

  private void RemoveRow(ScopeRow row)
  {
    _rows.Remove(row);
  }

  private async Task Save()
  {
    var newAssignments = _rows
      .Select(r => new CreatePermissionAssignmentRequestDto(
        PermissionPrincipalKind.PersonalAccessToken,
        CredentialId,
        r.PermissionName,
        r.Effect,
        r.ScopeKind,
        r.ScopeId,
        null))
      .ToList();

    var existingResult = await ControlrApi.Internal.PermissionAssignments.GetByPrincipal(
      nameof(PermissionPrincipalKind.PersonalAccessToken), CredentialId);

    if (existingResult.IsSuccess)
    {
      foreach (var existing in existingResult.Value)
      {
        await ControlrApi.Internal.PermissionAssignments.Delete(existing.Id);
      }
    }

    foreach (var request in newAssignments)
    {
      var createResult = await ControlrApi.Internal.PermissionAssignments.Create(request);
      if (!createResult.IsSuccess)
      {
        Snackbar.Add(createResult.Reason, Severity.Error);
        return;
      }
    }

    Snackbar.Add("Saved", Severity.Success);
    MudDialog.Close(DialogResult.Ok(true));
  }

  private sealed class ScopeRow(string permissionName, PermissionEffect effect, PermissionScopeKind scopeKind, Guid? scopeId)
  {
    public PermissionEffect Effect { get; set; } = effect;
    public string PermissionName { get; set; } = permissionName;
    public Guid? ScopeId { get; set; } = scopeId;
    public PermissionScopeKind ScopeKind { get; set; } = scopeKind;
  }
}
