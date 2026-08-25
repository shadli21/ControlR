namespace ControlR.Web.Server.Authz.Permissions;

public sealed record PrincipalDescriptor(
  PrincipalType PrincipalType,
  Guid PrincipalId,
  Guid? TenantId,
  string AuthMethod,
  Guid? CredentialId = null,
  CredentialType? CredentialType = null,
  Guid? DeviceScopeId = null,
  IReadOnlySet<int>? AllowedDesktopSessionIds = null,
  bool HasDesktopSessionRestriction = false)
{
  public bool IsCredentialScoped =>
    CredentialId is not null &&
    CredentialType is Permissions.CredentialType.PersonalAccessToken or Permissions.CredentialType.LogonToken;
}
