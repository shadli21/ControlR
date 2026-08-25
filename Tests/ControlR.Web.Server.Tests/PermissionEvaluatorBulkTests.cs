using ControlR.Web.Server.Authz.Permissions;
using ControlR.Web.Server.Services.Authorization;
using Moq;

namespace ControlR.Web.Server.Tests;

public class PermissionEvaluatorBulkTests
{
  [Fact]
  public async Task EmptyBulkRequests_DoNotLoadContext()
  {
    var contextLoader = new Mock<IPermissionEvaluationContextLoader>();
    var evaluator = new PermissionEvaluator(
      contextLoader.Object,
      Mock.Of<IPermissionDecisionEvaluator>());
    var principal = CreatePrincipal();
    var resource = new ResourceDescriptor(PermissionScopeKind.Server);

    var many = await evaluator.EvaluateMany(
      principal,
      [],
      resource,
      TestContext.Current.CancellationToken);
    var batch = await evaluator.EvaluateBatch(
      principal,
      [],
      TestContext.Current.CancellationToken);

    Assert.Empty(many);
    Assert.Empty(batch);
    contextLoader.Verify(
      loader => loader.Load(It.IsAny<PrincipalDescriptor>(), It.IsAny<CancellationToken>()),
      Times.Never);
  }

  [Fact]
  public async Task EvaluateBatch_WithMultipleResources_LoadsContextOnce()
  {
    var contextLoader = new Mock<IPermissionEvaluationContextLoader>();
    var decisionEvaluator = new Mock<IPermissionDecisionEvaluator>();
    var principal = CreatePrincipal();
    var context = new PermissionEvaluationContext(principal, false, [], [], false);
    contextLoader
      .Setup(loader => loader.Load(principal, It.IsAny<CancellationToken>()))
      .ReturnsAsync(context);
    decisionEvaluator
      .Setup(evaluator => evaluator.Evaluate(context, It.IsAny<string>(), It.IsAny<ResourceDescriptor>()))
      .Returns(PermissionEvaluationResult.Deny("denied"));
    var evaluator = new PermissionEvaluator(contextLoader.Object, decisionEvaluator.Object);
    var requests = new[]
    {
      new PermissionEvaluationRequest(
        PermissionNames.DeviceRead,
        new ResourceDescriptor(PermissionScopeKind.Device, Guid.NewGuid(), principal.TenantId)),
      new PermissionEvaluationRequest(
        PermissionNames.DeviceRead,
        new ResourceDescriptor(PermissionScopeKind.Device, Guid.NewGuid(), principal.TenantId))
    };

    var results = await evaluator.EvaluateBatch(
      principal,
      requests,
      TestContext.Current.CancellationToken);

    Assert.Equal(requests.Length, results.Count);
    contextLoader.Verify(
      loader => loader.Load(principal, It.IsAny<CancellationToken>()),
      Times.Once);
  }

  [Fact]
  public async Task EvaluateMany_WithMultiplePermissions_LoadsContextOnce()
  {
    var contextLoader = new Mock<IPermissionEvaluationContextLoader>();
    var decisionEvaluator = new Mock<IPermissionDecisionEvaluator>();
    var principal = CreatePrincipal();
    var context = new PermissionEvaluationContext(principal, false, [], [], false);
    contextLoader
      .Setup(loader => loader.Load(principal, It.IsAny<CancellationToken>()))
      .ReturnsAsync(context);
    decisionEvaluator
      .Setup(evaluator => evaluator.Evaluate(context, It.IsAny<string>(), It.IsAny<ResourceDescriptor>()))
      .Returns(PermissionEvaluationResult.Deny("denied"));
    var evaluator = new PermissionEvaluator(contextLoader.Object, decisionEvaluator.Object);

    var results = await evaluator.EvaluateMany(
      principal,
      [PermissionNames.DeviceRead, PermissionNames.DeviceDelete, PermissionNames.DeviceRead],
      new ResourceDescriptor(PermissionScopeKind.Device, Guid.NewGuid(), principal.TenantId),
      TestContext.Current.CancellationToken);

    Assert.Equal(2, results.Count);
    contextLoader.Verify(
      loader => loader.Load(principal, It.IsAny<CancellationToken>()),
      Times.Once);
    decisionEvaluator.Verify(
      decision => decision.Evaluate(context, It.IsAny<string>(), It.IsAny<ResourceDescriptor>()),
      Times.Exactly(2));
  }

  private static PrincipalDescriptor CreatePrincipal() =>
    new(PrincipalType.User, Guid.NewGuid(), Guid.NewGuid(), "test");
}
