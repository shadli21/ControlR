using InternalDtos = ControlR.Libraries.Api.Contracts.Dtos.ServerApi.Internal;

namespace ControlR.Web.Client.Components.Pages;

public partial class EffectivePermissions : ComponentBase
{
  private List<InternalDtos.PermissionCatalogEntryDto> _catalog = [];
  private string _permissionName = string.Empty;
  private string _principalId = string.Empty;
  private string _principalKind = "User";
  private InternalDtos.EffectivePermissionQueryResponseDto? _result;
  private string _scopeId = string.Empty;
  private string _scopeKind = "Tenant";

  [Inject]
  public required IControlrApi ControlrApi { get; init; }

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

  private async Task Query()
  {
    if (!Guid.TryParse(_principalId, out var principalId))
    {
      Snackbar.Add("Invalid principal ID format", Severity.Error);
      return;
    }

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
        Snackbar.Add("Invalid scope ID format", Severity.Error);
        return;
      }
      scopeId = parsed;
    }

    var request = new InternalDtos.EffectivePermissionQueryRequestDto(
      Enum.Parse<PermissionPrincipalKind>(_principalKind),
      principalId,
      _permissionName,
      Enum.Parse<PermissionScopeKind>(_scopeKind),
      scopeId);

    var result = await ControlrApi.Internal.EffectivePermissions.Query(request);
    if (!result.IsSuccess)
    {
      Snackbar.Add(result.Reason, Severity.Error);
      return;
    }

    _result = result.Value;
    StateHasChanged();
  }
}
