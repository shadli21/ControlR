namespace ControlR.Web.Server.Data.Enums;

/// <summary>
/// The effect of a permission assignment. Stored as a human-readable string
/// in the database via EF conversion so that raw DB inspection is readable.
/// Explicit deny overrides allow at any matching scope.
/// </summary>
public enum PermissionEffect
{
  Allow,
  Deny
}
