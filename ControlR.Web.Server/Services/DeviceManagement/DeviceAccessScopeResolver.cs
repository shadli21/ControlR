using System.Security.Claims;

namespace ControlR.Web.Server.Services.DeviceManagement;

public interface IDeviceAccessScopeResolver
{
  Task<DeviceAccessScope> Resolve(ClaimsPrincipal user, Guid tenantId, CancellationToken cancellationToken = default);
}
