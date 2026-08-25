namespace ControlR.Libraries.Api.Contracts.Dtos.ServerApi.V1.ServiceAccounts;

public class ServiceAccountsResponseDto
{
  public IReadOnlyList<ServiceAccountDto> Items { get; set; } = [];
}