namespace ControlR.Web.Server.Authz.Permissions;

public sealed record PrincipalDescriptor(
  string PrincipalType,
  Guid PrincipalId,
  Guid? TenantId,
  string AuthMethod,
  Guid? CredentialId = null,
  string? CredentialType = null,
  Guid? DeviceScopeId = null,
  IReadOnlySet<int>? AllowedDesktopSessionIds = null,
  bool HasDesktopSessionRestriction = false)
{
  public bool IsCredentialScoped =>
    CredentialType is "PersonalAccessToken" or "LogonToken" && CredentialId is not null;
}
