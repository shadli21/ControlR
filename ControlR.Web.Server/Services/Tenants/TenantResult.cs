namespace ControlR.Web.Server.Services.Tenants;

/// <summary>
/// Business-layer representation of a tenant, decoupled from API DTOs.
/// Controllers map this to the appropriate DTO at the boundary.
/// </summary>
public sealed record TenantResult(
  Guid Id,
  string Name);
