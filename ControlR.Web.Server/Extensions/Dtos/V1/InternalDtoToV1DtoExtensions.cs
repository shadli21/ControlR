using ControlR.Libraries.Api.Contracts.Dtos.ServerApi.V1;

namespace ControlR.Web.Server.Extensions.Dtos.V1;

/// <summary>
/// Maps Internal (BFF) DTOs to V1 (S2S) DTOs at the controller boundary.
/// Keeps the stable public contract decoupled from internal DTO shapes.
/// </summary>
internal static class InternalDtoToV1DtoExtensions
{
  public static CreateInstallerKeyResponseDto ToV1Dto(this InternalDtos.CreateInstallerKeyResponseDto internalDto)
  {
    return new CreateInstallerKeyResponseDto(
      internalDto.Id,
      internalDto.CreatorId,
      internalDto.KeyType,
      internalDto.KeySecret,
      internalDto.CreatedAt,
      internalDto.AllowedUses,
      internalDto.Expiration,
      internalDto.FriendlyName);
  }
}
