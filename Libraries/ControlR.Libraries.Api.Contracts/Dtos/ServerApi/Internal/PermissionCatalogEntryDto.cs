namespace ControlR.Libraries.Api.Contracts.Dtos.ServerApi.Internal;

public record PermissionCatalogEntryDto(
  string Name,
  string DisplayName,
  string Description,
  PermissionScopeKind[] AllowedScopeKinds,
  bool SelfRemovable);
