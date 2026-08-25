namespace ControlR.ApiClient.Interfaces.V1;

public interface IControlrV1Api
{
  IDevicesApi Devices { get; }
  IInstallerKeysApi InstallerKeys { get; }
  ILogonTokensApi LogonTokens { get; }
  IServerServiceAccountsApi ServerServiceAccounts { get; }
  ITenantsApi Tenants { get; }
  ITenantServiceAccountsApi TenantServiceAccounts { get; }
}