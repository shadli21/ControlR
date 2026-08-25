namespace ControlR.Web.Server.Services.Tenants;

/// <summary>
/// Business-layer tenant record, mapped to an API DTO by the controller.
/// </summary>
public sealed record TenantResult(
  Guid Id,
  string Name);
