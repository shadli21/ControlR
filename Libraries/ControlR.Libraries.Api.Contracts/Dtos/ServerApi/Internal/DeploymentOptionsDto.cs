namespace ControlR.Libraries.Api.Contracts.Dtos.ServerApi.Internal;

public sealed record DeploymentOptionsDto(
  bool AppendInstanceId,
  string? InstanceId);
