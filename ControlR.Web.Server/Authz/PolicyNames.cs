namespace ControlR.Web.Server.Authz;

/// <summary>
/// Well-known policy names for permission-based authorization policies.
/// Used in <c>[Authorize(Policy = "...")]</c> attributes on controllers.
/// </summary>
public static class PolicyNames
{
  public const string RequireServiceAccountRead = "RequireServiceAccountRead";
  public const string RequireServiceAccountRotateCredentials = "RequireServiceAccountRotateCredentials";
  public const string RequireServiceAccountWrite = "RequireServiceAccountWrite";
}
