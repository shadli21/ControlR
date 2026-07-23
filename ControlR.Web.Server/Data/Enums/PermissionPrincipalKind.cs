namespace ControlR.Web.Server.Data.Enums;

/// <summary>
/// The kind of principal a permission assignment targets. Stored as a human-readable
/// string in the database via EF conversion so that raw DB inspection is readable.
/// </summary>
public enum PermissionPrincipalKind
{
  User,
  UserGroup,
  ServiceAccount,
  PersonalAccessToken,
  LogonToken
}
