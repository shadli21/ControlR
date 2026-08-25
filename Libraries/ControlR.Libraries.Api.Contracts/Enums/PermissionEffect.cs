namespace ControlR.Libraries.Api.Contracts.Enums;

/// <summary>
/// The effect of a permission assignment. Explicit deny overrides allow at any matching scope.
/// </summary>
public enum PermissionEffect
{
  Allow,
  Deny
}
