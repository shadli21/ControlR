namespace ControlR.Web.Server.Authz;

/// <summary>
/// Well-known policy names for permission-based authorization policies.
/// Used in <c>[Authorize(Policy = "...")]</c> attributes on controllers.
/// </summary>
public static class PolicyNames
{
  public const string RequireDeviceGroupAssignDevices = "RequireDeviceGroupAssignDevices";
  public const string RequireDeviceGroupsRead = "RequireDeviceGroupsRead";
  public const string RequireDeviceGroupsWrite = "RequireDeviceGroupsWrite";
  public const string RequirePermissionAssignmentsRead = "RequirePermissionAssignmentsRead";
  public const string RequirePermissionAssignmentsWrite = "RequirePermissionAssignmentsWrite";
  public const string RequireServiceAccountRead = "RequireServiceAccountRead";
  public const string RequireServiceAccountRotateCredentials = "RequireServiceAccountRotateCredentials";
  public const string RequireServiceAccountWrite = "RequireServiceAccountWrite";
  public const string RequireUserGroupAssignUsers = "RequireUserGroupAssignUsers";
  public const string RequireUserGroupsRead = "RequireUserGroupsRead";
  public const string RequireUserGroupsWrite = "RequireUserGroupsWrite";
}
