using ControlR.Web.Server.Authn;
using ControlR.Web.Server.Authz.Permissions;

namespace ControlR.Web.Server.Tests;

public class PrincipalTypeParserTests
{
  [Fact]
  public void Parse_CanonicalServerServiceAccountValue_ReturnsServerServiceAccount()
  {
    Assert.Equal(
      PrincipalType.ServerServiceAccount,
      PrincipalTypeParser.Parse(PrincipalClaimValues.ServerServiceAccount));
  }

  [Fact]
  public void Parse_CanonicalTenantServiceAccountValue_ReturnsTenantServiceAccount()
  {
    Assert.Equal(
      PrincipalType.TenantServiceAccount,
      PrincipalTypeParser.Parse(PrincipalClaimValues.TenantServiceAccount));
  }

  [Fact]
  public void Parse_CanonicalUserValue_ReturnsUser()
  {
    Assert.Equal(PrincipalType.User, PrincipalTypeParser.Parse(PrincipalClaimValues.User));
  }

  [Theory]
  [InlineData(null)]
  [InlineData("")]
  [InlineData("user-typo")]
  [InlineData("Unknown")]
  public void Parse_UnknownOrAbsentValue_ReturnsNull(string? value)
  {
    Assert.Null(PrincipalTypeParser.Parse(value));
  }
}
