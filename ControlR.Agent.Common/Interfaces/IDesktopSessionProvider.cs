using ControlR.Libraries.Shared.Dtos.Devices;

namespace ControlR.Agent.Common.Interfaces;
public interface IDesktopSessionProvider
{
  Task<DesktopSession[]> GetActiveDesktopClients();
  Task<string[]> GetLoggedInUsers();
}
