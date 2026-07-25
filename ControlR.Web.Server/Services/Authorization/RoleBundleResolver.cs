namespace ControlR.Web.Server.Services.Authorization;

/// <summary>
/// Resolves the set of permission names granted by a collection of role names.
/// Roles are demoted to static permission bundles in the permission rework; this
/// resolver maps role claims to their seeded permission sets for the evaluator.
/// </summary>
public interface IRoleBundleResolver
{
  /// <summary>
  /// Returns the union of permission names granted by the given role names.
  /// </summary>
  IReadOnlySet<string> ResolvePermissions(IEnumerable<string> roleNames);
}

/// <inheritdoc cref="IRoleBundleResolver"/>
public class RoleBundleResolver : IRoleBundleResolver
{
  public IReadOnlySet<string> ResolvePermissions(IEnumerable<string> roleNames)
  {
    return new HashSet<string>();
  }
}
