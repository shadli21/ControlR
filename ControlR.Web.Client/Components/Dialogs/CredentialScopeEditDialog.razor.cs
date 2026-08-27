using InternalDtos = ControlR.Libraries.Api.Contracts.Dtos.ServerApi.Internal;

namespace ControlR.Web.Client.Components.Dialogs;

/// <summary>
/// Result of the credential scope editor dialog.
/// </summary>
public sealed record CredentialScopeEditDialogResult(InternalDtos.CredentialScopeDto Scope);

/// <summary>
/// Collects a single permission scope (permission plus scope kind/target) for inclusion in a
/// restricted credential's initial scope set. Scopes granted at credential creation are always
/// Allow grants; use the permissions panel to manage deny rules afterwards.
/// </summary>
public partial class CredentialScopeEditDialog : ComponentBase
{
  private InternalDtos.PermissionCatalogEntryDto? _selectedPermission;
  private PermissionScopeKind _scopeKind = PermissionScopeKind.Tenant;
  private Guid? _scopeId;

  public static DialogOptions DefaultOptions => new()
  {
    BackdropClick = false
  };

  [Inject]
  public required IPermissionCatalogStore PermissionCatalogStore { get; init; }

  [CascadingParameter]
  public required IMudDialogInstance MudDialog { get; init; }

  [Inject]
  public required ISnackbar Snackbar { get; init; }

  protected override async Task OnInitializedAsync()
  {
    if (PermissionCatalogStore.Items.Count == 0)
    {
      await PermissionCatalogStore.Refresh();
    }
  }

  private static string PermissionLabel(InternalDtos.PermissionCatalogEntryDto? permission)
  {
    return permission is null ? string.Empty : $"{permission.DisplayName} ({permission.Name})";
  }

  private static PermissionScopeKind BroadestLegalScope(InternalDtos.PermissionCatalogEntryDto? entry)
  {
    return PermissionScopeKinds.GetBroadestLegalScope(entry?.AllowedScopeKinds ?? []) ?? PermissionScopeKind.Tenant;
  }

  private static string ScopeKindLabel(PermissionScopeKind scopeKind) => scopeKind switch
  {
    PermissionScopeKind.Server => "Server",
    PermissionScopeKind.Tenant => "Tenant",
    PermissionScopeKind.Device => "Device",
    PermissionScopeKind.DeviceGroup => "Device Group",
    PermissionScopeKind.CustomerTenant => "Customer",
    PermissionScopeKind.UserGroup => "User Group",
    _ => scopeKind.ToString()
  };

  private void Cancel() => MudDialog.Cancel();

  private void HandlePermissionChanged(InternalDtos.PermissionCatalogEntryDto? value)
  {
    _selectedPermission = value;
    _scopeKind = BroadestLegalScope(value);
    _scopeId = null;
  }

  private async Task<IEnumerable<InternalDtos.PermissionCatalogEntryDto>> SearchPermissions(
    string query,
    CancellationToken cancellationToken)
  {
    if (string.IsNullOrWhiteSpace(query))
    {
      return PermissionCatalogStore.Items;
    }

    await Task.CompletedTask;
    return PermissionCatalogStore.Items.Where(p =>
      p.Name.Contains(query, StringComparison.OrdinalIgnoreCase) ||
      p.DisplayName.Contains(query, StringComparison.OrdinalIgnoreCase));
  }

  private Task Submit()
  {
    if (_selectedPermission is null)
    {
      Snackbar.Add("Permission is required", Severity.Error);
      return Task.CompletedTask;
    }

    if ((_scopeKind is PermissionScopeKind.Device
          or PermissionScopeKind.DeviceGroup
          or PermissionScopeKind.CustomerTenant
          or PermissionScopeKind.UserGroup) && _scopeId is null)
    {
      Snackbar.Add("Select a scope target", Severity.Error);
      return Task.CompletedTask;
    }

    var scope = new InternalDtos.CredentialScopeDto(_selectedPermission.Name, _scopeKind, _scopeId);
    MudDialog.Close(new CredentialScopeEditDialogResult(scope));
    return Task.CompletedTask;
  }
}
