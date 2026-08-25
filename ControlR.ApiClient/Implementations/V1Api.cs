using ControlR.ApiClient.Interfaces.V1;

namespace ControlR.ApiClient;

internal partial class V1Api(ControlrApi client) :
  IControlrV1Api,
  IDevicesApi,
  IInstallerKeysApi,
  ILogonTokensApi,
  IServerServiceAccountsApi,
  ITenantServiceAccountsApi,
  ITenantsApi
{
  private readonly ControlrApi _client = client;

  public IDevicesApi Devices => this;
  public IInstallerKeysApi InstallerKeys => this;
  public ILogonTokensApi LogonTokens => this;
  public IServerServiceAccountsApi ServerServiceAccounts => this;
  public ITenantsApi Tenants => this;
  public ITenantServiceAccountsApi TenantServiceAccounts => this;
}