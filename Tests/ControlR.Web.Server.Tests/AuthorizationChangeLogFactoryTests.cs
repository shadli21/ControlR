using ControlR.Web.Server.Services.Authorization;

namespace ControlR.Web.Server.Tests;

/// <summary>
/// Ensures the authorization change-log factory never writes a literal empty GUID. An
/// unresolved (e.g. pre-save) entity ID must become null, not "00000000-0000-0000-0000-000000000000".
/// </summary>
public class AuthorizationChangeLogFactoryTests
{
  [Fact]
  public void Create_WithEmptyActorOrTargetId_NormalizesToNull()
  {
    var log = AuthorizationChangeLogFactory.Create(
      "action",
      "user",
      Guid.Empty,
      "ServiceAccount",
      Guid.Empty,
      owningTenantId: null);

    Assert.Null(log.ActorPrincipalId);
    Assert.Null(log.TargetId);
  }

  [Fact]
  public void Create_WithRealIds_PreservesValues()
  {
    var actorId = Guid.NewGuid();
    var targetId = Guid.NewGuid();

    var log = AuthorizationChangeLogFactory.Create(
      "action",
      "user",
      actorId,
      "ServiceAccount",
      targetId,
      owningTenantId: null);

    Assert.Equal(actorId, log.ActorPrincipalId);
    Assert.Equal(targetId, log.TargetId);
  }
}
