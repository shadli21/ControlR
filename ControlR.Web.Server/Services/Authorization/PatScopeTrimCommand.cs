using ControlR.Web.Server.Data.Enums;

namespace ControlR.Web.Server.Services.Authorization;

/// <summary>
/// Command enqueued when a credential's scope rows are detected as exceeding the
/// owning user's effective permissions. The background trim service processes these
/// asynchronously to avoid blocking the authentication hot path.
/// </summary>
public sealed record PatScopeTrimCommand(Guid CredentialId, PermissionPrincipalKind PrincipalKind);
