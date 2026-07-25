using ControlR.Libraries.Api.Contracts.Constants;
using Microsoft.AspNetCore.Mvc;

namespace ControlR.Web.Server.Api.Internal;

[Route(HttpConstants.Internal.ServerServiceAccountsEndpoint)]
[ApiController]
[Authorize]
[EndpointGroupName(OpenApiConstants.InternalGroupName)]
public class ServerServiceAccountsController(IServiceAccountManager serviceAccountManager) : ControllerBase
{
  private readonly IServiceAccountManager _serviceAccountManager = serviceAccountManager;

  [HttpPost("{serviceAccountId:guid}/credentials")]
  [Authorize(Policy = PolicyNames.RequireServerServiceAccountsRotateCredentials)]
  public async Task<ActionResult<InternalDtos.CreateServerServiceAccountCredentialResponseDto>> AddCredential(
    [FromRoute] Guid serviceAccountId,
    [FromBody] InternalDtos.CreateServerServiceAccountCredentialRequestDto request,
    CancellationToken cancellationToken)
  {
    var result = await _serviceAccountManager.AddCredential(serviceAccountId, request.Name, cancellationToken);

    if (!result.IsSuccess)
    {
      return result.ToHttpResult().ToActionResult();
    }

    return Ok(new InternalDtos.CreateServerServiceAccountCredentialResponseDto(
      MapCredentialToDto(result.Value.Credential),
      result.Value.PlainTextSecretKey));
  }

  [HttpPost]
  [Authorize(Policy = PolicyNames.RequireServerServiceAccountsWrite)]
  public async Task<ActionResult<InternalDtos.CreateServerServiceAccountResponseDto>> Create(
    [FromBody] InternalDtos.CreateServerServiceAccountRequestDto request,
    CancellationToken cancellationToken)
  {
    var result = await _serviceAccountManager.CreateForServer(request.Name, request.Description, cancellationToken);

    if (!result.IsSuccess)
    {
      return result.ToHttpResult().ToActionResult();
    }

    return Ok(new InternalDtos.CreateServerServiceAccountResponseDto(
      MapToDto(result.Value.ServiceAccount),
      result.Value.PlainTextSecretKey));
  }

  [HttpDelete("{serviceAccountId:guid}")]
  [Authorize(Policy = PolicyNames.RequireServerServiceAccountsWrite)]
  public async Task<IActionResult> Delete(
    [FromRoute] Guid serviceAccountId,
    CancellationToken cancellationToken)
  {
    if (!User.TryGetUserId(out var userId))
    {
      return BadRequest("User ID not found.");
    }

    var result = await _serviceAccountManager.Delete(serviceAccountId, userId, cancellationToken);
    if (!result.IsSuccess)
    {
      return result.ToActionResult();
    }

    return NoContent();
  }

  [HttpGet("{serviceAccountId:guid}")]
  [Authorize(Policy = PolicyNames.RequireServerServiceAccountsRead)]
  public async Task<ActionResult<InternalDtos.ServerServiceAccountDto>> Get(
    [FromRoute] Guid serviceAccountId,
    CancellationToken cancellationToken)
  {
    var result = await _serviceAccountManager.Get(serviceAccountId, cancellationToken);
    if (!result.IsSuccess)
    {
      return result.ToHttpResult().ToActionResult();
    }

    return Ok(MapToDto(result.Value));
  }

  [HttpGet]
  [Authorize(Policy = PolicyNames.RequireServerServiceAccountsRead)]
  public async Task<ActionResult<List<InternalDtos.ServerServiceAccountDto>>> GetAll(
    CancellationToken cancellationToken)
  {
    var accounts = await _serviceAccountManager.GetAllForServer(cancellationToken);
    return Ok(accounts.Select(MapToDto).ToList());
  }

  [HttpDelete("{serviceAccountId:guid}/credentials/{credentialId:guid}")]
  [Authorize(Policy = PolicyNames.RequireServerServiceAccountsRotateCredentials)]
  public async Task<IActionResult> RevokeCredential(
    [FromRoute] Guid serviceAccountId,
    [FromRoute] Guid credentialId,
    CancellationToken cancellationToken)
  {
    var result = await _serviceAccountManager.RevokeCredential(serviceAccountId, credentialId, cancellationToken);

    if (!result.IsSuccess)
    {
      return result.ToActionResult();
    }

    return NoContent();
  }

  [HttpPut("{serviceAccountId:guid}")]
  [Authorize(Policy = PolicyNames.RequireServerServiceAccountsWrite)]
  public async Task<ActionResult<InternalDtos.ServerServiceAccountDto>> Update(
    [FromRoute] Guid serviceAccountId,
    [FromBody] InternalDtos.UpdateServerServiceAccountRequestDto request,
    CancellationToken cancellationToken)
  {
    if (!User.TryGetUserId(out var userId))
    {
      return BadRequest("User ID not found.");
    }

    var result = await _serviceAccountManager.UpdateForServer(
      serviceAccountId, request.Name, request.Description, userId, cancellationToken);

    if (!result.IsSuccess)
    {
      return result.ToHttpResult().ToActionResult();
    }

    return Ok(MapToDto(result.Value));
  }

  private static InternalDtos.ServerServiceAccountCredentialDto MapCredentialToDto(ServiceAccountCredentialResult result)
  {
    return new InternalDtos.ServerServiceAccountCredentialDto(
      result.Id,
      result.Name,
      result.CreatedAt,
      result.ExpiresAt,
      result.RevokedAt,
      result.LastUsedAt);
  }

  private static InternalDtos.ServerServiceAccountDto MapToDto(ServiceAccountResult result)
  {
    return new InternalDtos.ServerServiceAccountDto(
      result.Id,
      result.Name,
      result.Description,
      result.IsEnabled,
      result.CreatedAt,
      [.. result.Credentials.Select(MapCredentialToDto)]);
  }
}
