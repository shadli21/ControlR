namespace ControlR.Web.Server.Services.Authorization.PermissionRules;

/// <summary>
/// Source priority for tie-breaking. Lower values win. Credential grants are highest
/// priority because they represent the narrowest, most intentional grant.
/// </summary>
public enum SourcePriority
{
  CredentialPat = 0,
  CredentialLogonToken = 1,
  Direct = 2,
  UserGroup = 3
}
