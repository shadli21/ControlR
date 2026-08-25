namespace ControlR.Web.Server.Authz.Permissions;

public sealed class PermissionRequirement(
  string permissionName,
  ResourceDescriptor resource)
  : IAuthorizationRequirement
{
  public string PermissionName { get; } = permissionName;
  public ResourceDescriptor Resource { get; } = resource;
}
