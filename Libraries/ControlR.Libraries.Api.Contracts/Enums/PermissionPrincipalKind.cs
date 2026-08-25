namespace ControlR.Libraries.Api.Contracts.Enums;

/// <summary>
/// The kind of principal a permission assignment targets.
/// </summary>
public enum PermissionPrincipalKind
{
  User,
  UserGroup,
  ServiceAccount,
  PersonalAccessToken,
  LogonToken
}
