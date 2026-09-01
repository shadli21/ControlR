using ControlR.Web.Server.Authz.Permissions;

namespace ControlR.Web.Server.Tests.Helpers;

/// <summary>
/// Builds the <see cref="PrincipalDescriptor"/> actors that tests supply to the service managers, so
/// that a recorded audit attribution reflects the principal the test is actually acting as.
/// </summary>
public static class TestActors
{
  /// <summary>
  /// A server service-account actor, used when the test has the account provision itself.
  /// </summary>
  public static PrincipalDescriptor ServerServiceAccount(Guid principalId) =>
    new(PrincipalType.ServerServiceAccount, principalId, null, "test");

  /// <summary>
  /// A human-user actor. Pass <paramref name="principalId"/> to pin the id when the test correlates
  /// the audit row back to a known user; otherwise a throwaway id is used.
  /// </summary>
  public static PrincipalDescriptor User(Guid? principalId = null) =>
    new(PrincipalType.User, principalId ?? Guid.NewGuid(), null, "test");
}
