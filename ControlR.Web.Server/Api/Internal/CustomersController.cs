using ControlR.Web.Server.Authz.Permissions;
using Microsoft.AspNetCore.Mvc;

namespace ControlR.Web.Server.Api.Internal;

[Route(HttpConstants.Internal.CustomersEndpoint)]
[ApiController]
[Authorize]
[EndpointGroupName(OpenApiConstants.InternalGroupName)]
public class CustomersController(ICustomerManager customerManager) : ControllerBase
{
  private readonly ICustomerManager _customerManager = customerManager;

  [HttpPost("{customerId:guid}/devices")]
  [Authorize(Policy = PolicyNames.RequireCustomersWrite)]
  public async Task<IActionResult> AssignDevices(
    [FromRoute] Guid customerId,
    [FromBody] InternalDtos.AssignCustomerDevicesRequestDto request,
    CancellationToken cancellationToken)
  {
    if (!User.TryGetTenantId(out var tenantId))
    {
      return BadRequest("User tenant not found.");
    }

    if (User.ToPrincipalDescriptor() is not { } actor)
    {
      return BadRequest("User ID not found.");
    }

    var result = await _customerManager.AssignDevices(
      customerId, request.DeviceIds, request.RemoveDeviceIds, tenantId, actor, cancellationToken);

    if (!result.IsSuccess)
    {
      return result.ToActionResult();
    }

    return NoContent();
  }

  [HttpPost]
  [Authorize(Policy = PolicyNames.RequireCustomersWrite)]
  public async Task<ActionResult<InternalDtos.CustomerDto>> Create(
    [FromBody] InternalDtos.CreateCustomerRequestDto request,
    CancellationToken cancellationToken)
  {
    if (!User.TryGetTenantId(out var tenantId))
    {
      return BadRequest("User tenant not found.");
    }

    if (User.ToPrincipalDescriptor() is not { } actor)
    {
      return BadRequest("User ID not found.");
    }

    var result = await _customerManager.Create(
      request.Name, request.Description, request.Notes, tenantId, actor, cancellationToken);

    if (!result.IsSuccess)
    {
      return result.ToHttpResult().ToActionResult();
    }

    return Ok(result.Value);
  }

  [HttpDelete("{customerId:guid}")]
  [Authorize(Policy = PolicyNames.RequireCustomersWrite)]
  public async Task<IActionResult> Delete(
    [FromRoute] Guid customerId,
    CancellationToken cancellationToken)
  {
    if (!User.TryGetTenantId(out var tenantId))
    {
      return BadRequest("User tenant not found.");
    }

    if (User.ToPrincipalDescriptor() is not { } actor)
    {
      return BadRequest("User ID not found.");
    }

    var result = await _customerManager.Delete(customerId, tenantId, actor, cancellationToken);
    if (!result.IsSuccess)
    {
      return result.ToActionResult();
    }

    return NoContent();
  }

  [HttpGet("{customerId:guid}")]
  [Authorize(Policy = PolicyNames.RequireCustomersRead)]
  public async Task<ActionResult<InternalDtos.CustomerDto>> Get(
    [FromRoute] Guid customerId,
    CancellationToken cancellationToken)
  {
    if (!User.TryGetTenantId(out var tenantId))
    {
      return BadRequest("User tenant not found.");
    }

    var result = await _customerManager.Get(customerId, tenantId, cancellationToken);
    if (!result.IsSuccess)
    {
      return result.ToHttpResult().ToActionResult();
    }

    return Ok(result.Value);
  }

  [HttpGet]
  [Authorize(Policy = PolicyNames.RequireCustomersRead)]
  public async Task<ActionResult<IReadOnlyList<InternalDtos.CustomerDto>>> GetAll(
    CancellationToken cancellationToken)
  {
    if (!User.TryGetTenantId(out var tenantId))
    {
      return BadRequest("User tenant not found.");
    }

    var customers = await _customerManager.GetAll(tenantId, cancellationToken);
    return Ok(customers);
  }

  [HttpPut("{customerId:guid}")]
  [Authorize(Policy = PolicyNames.RequireCustomersWrite)]
  public async Task<ActionResult<InternalDtos.CustomerDto>> Update(
    [FromRoute] Guid customerId,
    [FromBody] InternalDtos.UpdateCustomerRequestDto request,
    CancellationToken cancellationToken)
  {
    if (!User.TryGetTenantId(out var tenantId))
    {
      return BadRequest("User tenant not found.");
    }

    if (User.ToPrincipalDescriptor() is not { } actor)
    {
      return BadRequest("User ID not found.");
    }

    var result = await _customerManager.Update(
      customerId, request.Name, request.Description, request.Notes, tenantId, actor, cancellationToken);

    if (!result.IsSuccess)
    {
      return result.ToHttpResult().ToActionResult();
    }

    return Ok(result.Value);
  }
}
