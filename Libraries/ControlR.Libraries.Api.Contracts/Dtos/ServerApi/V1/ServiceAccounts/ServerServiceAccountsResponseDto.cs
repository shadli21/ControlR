namespace ControlR.Libraries.Api.Contracts.Dtos.ServerApi.V1.ServiceAccounts;

public class ServerServiceAccountsResponseDto
{
  public IReadOnlyList<ServerServiceAccountDto> Items { get; set; } = [];
}
