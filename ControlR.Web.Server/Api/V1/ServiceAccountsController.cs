using Asp.Versioning;
using ControlR.Libraries.Api.Contracts.Constants;
using ControlR.Libraries.Api.Contracts.Dtos.ServerApi.V1.ServiceAccounts;
using ControlR.Web.Server.Authn;
using ControlR.Web.Server.Extensions.Dtos.V1;
using Microsoft.AspNetCore.Mvc;

namespace ControlR.Web.Server.Api.V1;

[Route(HttpConstants.V1.ServiceAccountsEndpoint)]
[ApiController]
[Authorize]
[ApiVersion(ApiVersions.V1)]
public class ServiceAccountsController(
  IServiceAccountManager serviceAccountManager) : ControllerBase
{
  private readonly IServiceAccountManager _serviceAccountManager = serviceAccountManager;

  [HttpPost("{serviceAccountId:guid}/credentials")]
  [Authorize(Policy = PolicyNames.RequireServerServiceAccountsRotateCredentials)]
  [ProducesResponseType<CreateServiceAccountCredentialResponseDto>(StatusCodes.Status200OK)]
  [ProducesResponseType(StatusCodes.Status400BadRequest)]
  [ProducesResponseType(StatusCodes.Status404NotFound)]
  [ProducesResponseType(StatusCodes.Status409Conflict)]
  public async Task<ActionResult<CreateServiceAccountCredentialResponseDto>> AddCredential(
    Guid serviceAccountId,
    [FromBody] CreateServiceAccountCredentialRequestDto request,
    CancellationToken cancellationToken)
  {
    var principalClaim = User.FindFirst(PrincipalClaimTypes.PrincipalId);
    if (principalClaim is null || !Guid.TryParse(principalClaim.Value, out var principalId))
    {
      return Unauthorized();
    }

    var result = await _serviceAccountManager.AddCredentialForServer(serviceAccountId, request.Name, request.ExpiresAt, principalId, cancellationToken);
    if (!result.IsSuccess)
    {
      return result.ToHttpResult().ToActionResult();
    }

    return Ok(result.Value.ToDto());
  }

  [HttpPost]
  [Authorize(Policy = PolicyNames.RequireServerServiceAccountsWrite)]
  [ProducesResponseType<ServiceAccountDto>(StatusCodes.Status201Created)]
  [ProducesResponseType(StatusCodes.Status400BadRequest)]
  [ProducesResponseType(StatusCodes.Status409Conflict)]
  public async Task<ActionResult<ServiceAccountDto>> Create(
    [FromBody] CreateServiceAccountRequestDto request,
    CancellationToken cancellationToken)
  {
    var result = await _serviceAccountManager.CreateForServer(request.Name, request.Description, cancellationToken);
    if (!result.IsSuccess)
    {
      return result.ToHttpResult().ToActionResult();
    }

    return CreatedAtAction(nameof(Get), new { serviceAccountId = result.Value.Id }, result.Value.ToDto());
  }

  [HttpDelete("{serviceAccountId:guid}")]
  [Authorize(Policy = PolicyNames.RequireServerServiceAccountsWrite)]
  [ProducesResponseType(StatusCodes.Status204NoContent)]
  [ProducesResponseType(StatusCodes.Status401Unauthorized)]
  [ProducesResponseType(StatusCodes.Status403Forbidden)]
  [ProducesResponseType(StatusCodes.Status404NotFound)]
  public async Task<IActionResult> Delete(
    Guid serviceAccountId,
    CancellationToken cancellationToken)
  {
    var principalClaim = User.FindFirst(PrincipalClaimTypes.PrincipalId);
    if (principalClaim is null)
    {
      return Unauthorized();
    }

    if (!Guid.TryParse(principalClaim.Value, out var principalId))
    {
      return Unauthorized();
    }

    var result = await _serviceAccountManager.DeleteForServer(serviceAccountId, principalId, cancellationToken);
    if (!result.IsSuccess)
    {
      return result.ToActionResult();
    }

    return NoContent();
  }

  [HttpGet("{serviceAccountId:guid}")]
  [Authorize(Policy = PolicyNames.RequireServerServiceAccountsRead)]
  [ProducesResponseType<ServiceAccountDto>(StatusCodes.Status200OK)]
  [ProducesResponseType(StatusCodes.Status404NotFound)]
  public async Task<ActionResult<ServiceAccountDto>> Get(
    Guid serviceAccountId,
    CancellationToken cancellationToken)
  {
    var result = await _serviceAccountManager.GetForServer(serviceAccountId, cancellationToken);
    if (!result.IsSuccess)
    {
      return result.ToHttpResult().ToActionResult();
    }

    return Ok(result.Value.ToDto());
  }

  [HttpGet]
  [Authorize(Policy = PolicyNames.RequireServerServiceAccountsRead)]
  [ProducesResponseType<ServiceAccountsResponseDto>(StatusCodes.Status200OK)]
  public async Task<ActionResult<ServiceAccountsResponseDto>> GetAll(CancellationToken cancellationToken)
  {
    var accounts = await _serviceAccountManager.GetAllForServer(cancellationToken);
    return Ok(new ServiceAccountsResponseDto
    {
      Items = accounts.Select(x => x.ToDto()).ToArray()
    });
  }

  [HttpDelete("{serviceAccountId:guid}/credentials/{credentialId:guid}")]
  [Authorize(Policy = PolicyNames.RequireServerServiceAccountsRotateCredentials)]
  [ProducesResponseType(StatusCodes.Status204NoContent)]
  [ProducesResponseType(StatusCodes.Status404NotFound)]
  public async Task<IActionResult> RevokeCredential(
    Guid serviceAccountId,
    Guid credentialId,
    CancellationToken cancellationToken)
  {
    var principalClaim = User.FindFirst(PrincipalClaimTypes.PrincipalId);
    if (principalClaim is null || !Guid.TryParse(principalClaim.Value, out var principalId))
    {
      return Unauthorized();
    }

    var result = await _serviceAccountManager.RevokeCredentialForServer(serviceAccountId, credentialId, principalId, cancellationToken);
    if (!result.IsSuccess)
    {
      return result.ToActionResult();
    }

    return NoContent();
  }

  [HttpPut("{serviceAccountId:guid}")]
  [Authorize(Policy = PolicyNames.RequireServerServiceAccountsWrite)]
  [ProducesResponseType<ServiceAccountDto>(StatusCodes.Status200OK)]
  [ProducesResponseType(StatusCodes.Status400BadRequest)]
  [ProducesResponseType(StatusCodes.Status404NotFound)]
  public async Task<ActionResult<ServiceAccountDto>> Update(
    Guid serviceAccountId,
    [FromBody] UpdateServiceAccountRequestDto request,
    CancellationToken cancellationToken)
  {
    var principalClaim = User.FindFirst(PrincipalClaimTypes.PrincipalId);
    if (principalClaim is null || !Guid.TryParse(principalClaim.Value, out var principalId))
    {
      return Unauthorized();
    }

    var result = await _serviceAccountManager.UpdateForServer(
      serviceAccountId, request.Name, request.Description, request.IsEnabled, principalId, cancellationToken);
    if (!result.IsSuccess)
    {
      return result.ToHttpResult().ToActionResult();
    }

    return Ok(result.Value.ToDto());
  }
}
