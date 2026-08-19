namespace ControlR.Web.Server.Constants;

public static class CacheKeys
{
  public static string GetPersonalAccessTokenAuthFailureByIp(string? remoteIp) => $"pat-auth-fail:ip:{remoteIp ?? "(unknown IP)"}";

  public static string GetPersonalAccessTokenAuthFailureByToken(string? tokenIdPrefix) => $"pat-auth-fail:token:{tokenIdPrefix ?? "(unknown token)"}";

  public static string GetServiceAccountAuthFailureByCredential(string? credentialIdPrefix) => $"sa-auth-fail:cred:{credentialIdPrefix ?? "(unknown cred)"}";

  public static string GetServiceAccountAuthFailureByIp(string? remoteIp) => $"sa-auth-fail:ip:{remoteIp ?? "(unknown IP)"}";
}
