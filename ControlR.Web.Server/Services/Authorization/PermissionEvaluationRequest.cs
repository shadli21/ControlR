using ControlR.Web.Server.Authz.Permissions;

namespace ControlR.Web.Server.Services.Authorization;

public sealed record PermissionEvaluationRequest(
  string PermissionName,
  ResourceDescriptor Resource);
