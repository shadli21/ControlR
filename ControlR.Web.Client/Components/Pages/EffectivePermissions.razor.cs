using ControlR.Libraries.Api.Contracts.Enums;
using InternalDtos = ControlR.Libraries.Api.Contracts.Dtos.ServerApi.Internal;

namespace ControlR.Web.Client.Components.Pages;

public partial class EffectivePermissions : ComponentBase
{
  private List<InternalDtos.PermissionCatalogEntryDto> _catalog = [];
  private string _permissionName = string.Empty;
  private string _principalKind = "User";
  private InternalDtos.EffectivePermissionQueryResponseDto? _result;
  private Guid? _scopeId;
  private string _scopeKind = "Tenant";
  private Guid? _selectedPrincipalId;

  [Inject]
  public required IControlrApi ControlrApi { get; init; }

  [Inject]
  public required ISnackbar Snackbar { get; init; }

  private PermissionPrincipalKind _parsedPrincipalKind => Enum.Parse<PermissionPrincipalKind>(_principalKind);

  private PermissionScopeKind _parsedScopeKind => Enum.Parse<PermissionScopeKind>(_scopeKind);

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
    if (_selectedPrincipalId is not Guid principalId)
    {
      Snackbar.Add("Select a principal first", Severity.Error);
      return;
    }

    if (string.IsNullOrWhiteSpace(_permissionName))
    {
      Snackbar.Add("Permission name is required", Severity.Error);
      return;
    }

    var request = new InternalDtos.EffectivePermissionQueryRequestDto(
      _parsedPrincipalKind,
      principalId,
      _permissionName,
      _parsedScopeKind,
      _scopeId);

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
