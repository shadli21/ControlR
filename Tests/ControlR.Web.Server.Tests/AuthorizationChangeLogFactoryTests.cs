using System.Diagnostics;
using System.Net;
using ControlR.Web.Server.Services.Authorization;
using Microsoft.AspNetCore.Http;
using Moq;

namespace ControlR.Web.Server.Tests;

/// <summary>
/// Ensures the authorization change-log factory never writes a literal empty GUID. An
/// unresolved (e.g. pre-save) entity ID must become null, not "00000000-0000-0000-0000-000000000000".
/// </summary>
public class AuthorizationChangeLogFactoryTests
{
  [Fact]
  public void Create_WithActiveActivity_PopulatesCorrelationIdFromTraceId()
  {
    var factory = CreateFactory();
    using var activity = new Activity("test-operation");
    activity.SetIdFormat(ActivityIdFormat.W3C);
    activity.Start();

    var log = factory.Create("action", "user", null, "ServiceAccount", null, owningTenantId: null);

    Assert.Equal(activity.TraceId.ToString(), log.CorrelationId);
  }

  [Fact]
  public void Create_WithEmptyActorOrTargetId_NormalizesToNull()
  {
    var factory = CreateFactory();

    var log = factory.Create(
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
  public void Create_WithHttpContext_PopulatesIpAddress()
  {
    var factory = CreateFactory(remoteIp: IPAddress.Parse("203.0.113.7"));

    var log = factory.Create("action", "user", null, "ServiceAccount", null, owningTenantId: null);

    Assert.Equal("203.0.113.7", log.IpAddress);
  }

  [Fact]
  public void Create_WithIpv4MappedIpv6Address_MapsToIpv4()
  {
    var factory = CreateFactory(remoteIp: IPAddress.Parse("::ffff:192.168.1.1"));

    var log = factory.Create("action", "user", null, "ServiceAccount", null, owningTenantId: null);

    Assert.Equal("192.168.1.1", log.IpAddress);
  }

  [Fact]
  public void Create_WithoutActiveActivity_LeavesCorrelationIdNull()
  {
    var factory = CreateFactory();

    var log = factory.Create("action", "user", null, "ServiceAccount", null, owningTenantId: null);

    Assert.Null(log.CorrelationId);
  }

  [Fact]
  public void Create_WithoutHttpContext_LeavesIpAddressNull()
  {
    var factory = CreateFactory();

    var log = factory.Create("action", "user", null, "ServiceAccount", null, owningTenantId: null);

    Assert.Null(log.IpAddress);
  }

  [Fact]
  public void Create_WithRealIds_PreservesValues()
  {
    var factory = CreateFactory();
    var actorId = Guid.NewGuid();
    var targetId = Guid.NewGuid();

    var log = factory.Create(
      "action",
      "user",
      actorId,
      "ServiceAccount",
      targetId,
      owningTenantId: null);

    Assert.Equal(actorId, log.ActorPrincipalId);
    Assert.Equal(targetId, log.TargetId);
  }

  private static IAuthorizationChangeLogFactory CreateFactory(IPAddress? remoteIp = null)
  {
    HttpContext? httpContext = null;
    if (remoteIp is not null)
    {
      httpContext = new DefaultHttpContext();
      httpContext.Connection.RemoteIpAddress = remoteIp;
    }

    var accessor = new Mock<IHttpContextAccessor>();
    accessor.SetupGet(x => x.HttpContext).Returns(httpContext);
    return new AuthorizationChangeLogFactory(accessor.Object);
  }
}
