namespace ControlR.Libraries.Api.Contracts.Dtos.ServerApi.V1.ServiceAccounts;

public class TenantServiceAccountsResponseDto
{
  public IReadOnlyList<TenantServiceAccountDto> Items { get; set; } = [];
}
