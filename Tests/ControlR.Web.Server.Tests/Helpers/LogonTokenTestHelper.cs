namespace ControlR.Web.Server.Tests.Helpers;

/// <summary>
/// Shared helpers for decoding logon token response strings in tests.
/// A logon token response carries the token ID as a hex prefix followed by a
/// colon and the secret; the ID is what tests need to assert grant rows.
/// </summary>
internal static class LogonTokenTestHelper
{
  public static Guid ParseTokenId(string combinedToken)
  {
    var hexPart = combinedToken.Split(':', 2)[0];
    var bytes = Convert.FromHexString(hexPart);
    return new Guid(bytes);
  }
}
