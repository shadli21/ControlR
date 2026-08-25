using ControlR.Web.Server.Authn;
using ControlR.Web.Server.Authz.Permissions;

namespace ControlR.Web.Server.Tests;

public class CredentialTypeParserTests
{
  [Fact]
  public void Parse_CanonicalLogonTokenValue_ReturnsLogonToken()
  {
    Assert.Equal(
      CredentialType.LogonToken,
      CredentialTypeParser.Parse(PrincipalClaimValues.LogonTokenCredentialType));
  }

  [Fact]
  public void Parse_CanonicalPatValue_ReturnsPersonalAccessToken()
  {
    Assert.Equal(
      CredentialType.PersonalAccessToken,
      CredentialTypeParser.Parse(PrincipalClaimValues.PersonalAccessTokenCredentialType));
  }

  [Fact]
  public void Parse_CanonicalServiceAccountValue_ReturnsServiceAccountCredential()
  {
    Assert.Equal(
      CredentialType.ServiceAccountCredential,
      CredentialTypeParser.Parse(PrincipalClaimValues.ServiceAccountCredentialType));
  }

  [Theory]
  [InlineData(null)]
  [InlineData("")]
  [InlineData("pat-typo")]
  [InlineData("Unknown")]
  public void Parse_UnknownOrAbsentValue_ReturnsNull(string? value)
  {
    Assert.Null(CredentialTypeParser.Parse(value));
  }
}
