namespace ControlR.Web.Server.Authz.Permissions;

/// <summary>
/// The kind of credential that authenticated the principal, if any. Converted to and from the
/// <c>controlr:credential:type</c> claim value via <see cref="CredentialTypeParser"/>. A principal
/// authenticated via cookie or a bare service account has a null credential type.
/// </summary>
public enum CredentialType
{
  PersonalAccessToken,
  LogonToken,
  ServiceAccountCredential
}
