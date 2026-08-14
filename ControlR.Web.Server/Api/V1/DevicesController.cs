using System.Collections.Immutable;
using System.Runtime.CompilerServices;
using Asp.Versioning;
using ControlR.Libraries.Api.Contracts.Constants;
using ControlR.Libraries.Api.Contracts.Hubs.Clients;
using ControlR.Web.Server.Authz.Permissions;
using ControlR.Web.Server.Extensions.Dtos.V1;
using ControlR.Web.Server.Services.Authorization;
using ControlR.Web.Server.Services.DeviceManagement;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.SignalR;
using DeviceResponseDto = ControlR.Libraries.Api.Contracts.Dtos.ServerApi.V1.DeviceResponseDto;

namespace ControlR.Web.Server.Api.V1;

[Route(HttpConstants.V1.DevicesEndpoint)]
[ApiController]
[Authorize]
[ApiVersion(ApiVersions.V1)]
public class DevicesController(IDeviceAccessScopeResolver deviceAccessScopeResolver) : ControllerBase
{
  private readonly IDeviceAccessScopeResolver _deviceAccessScopeResolver = deviceAccessScopeResolver;

  [HttpDelete("{deviceId:guid}")]
  [ProducesResponseType(StatusCodes.Status204NoContent)]
  [ProducesResponseType(StatusCodes.Status404NotFound)]
  public async Task<IActionResult> DeleteDevice(
    [FromServices] AppDb appDb,
    [FromServices] IAuthorizationService authorizationService,
    [FromRoute] Guid deviceId,
    CancellationToken cancellationToken)
  {
    var device = await appDb.Devices.FirstOrDefaultAsync(x => x.Id == deviceId, cancellationToken);
    if (device is null)
    {
      return NotFound();
    }

    var authResult = await authorizationService.AuthorizeAsync(User, device, DeviceResourcePolicies.Delete);
    if (!authResult.Succeeded)
    {
      return Forbid();
    }

    appDb.Devices.Remove(device);
    await appDb.SaveChangesAsync(cancellationToken);
    return NoContent();
  }

  [HttpPost("delete-many")]
  public async Task<ActionResult<V1Dtos.DeleteManyDevicesResponseDto>> DeleteMany(
    [FromServices] AppDb appDb,
    [FromServices] IAuthorizationService authorizationService,
    [FromBody] V1Dtos.DeleteDevicesRequestDto requestDto,
    CancellationToken cancellationToken)
  {
    var candidateDevices = await appDb.Devices
      .AsNoTracking()
      .Include(x => x.DeviceGroupMembers)
      .Where(d => requestDto.DeviceIds.Contains(d.Id))
      .ToListAsync(cancellationToken);

    var authorizedIdSet = new HashSet<Guid>();
    foreach (var device in candidateDevices)
    {
      var authResult = await authorizationService.AuthorizeAsync(User, device, DeviceResourcePolicies.Delete);
      if (authResult.Succeeded)
      {
        authorizedIdSet.Add(device.Id);
      }
    }

    var deletedCount = await appDb.Devices
      .Where(x => authorizedIdSet.Contains(x.Id))
      .ExecuteDeleteAsync(cancellationToken);

    if (deletedCount == authorizedIdSet.Count)
    {
      return new V1Dtos.DeleteManyDevicesResponseDto(
        SuccessIds: [.. authorizedIdSet],
        FailureIds: [.. requestDto.DeviceIds.Except(authorizedIdSet)]);
    }

    var remainingIds = await appDb.Devices
      .Where(x => authorizedIdSet.Contains(x.Id))
      .Select(x => x.Id)
      .ToListAsync(cancellationToken);

    var successIds = authorizedIdSet.Except(remainingIds).ToImmutableList();
    var failureIds = remainingIds.Concat(requestDto.DeviceIds.Except(authorizedIdSet)).ToImmutableList();

    return new V1Dtos.DeleteManyDevicesResponseDto(successIds, failureIds);
  }

  [HttpGet]
  public async IAsyncEnumerable<DeviceResponseDto> Get(
    [FromServices] AppDb appDb,
    [FromServices] IAgentVersionProvider agentVersionProvider,
    [EnumeratorCancellation] CancellationToken cancellationToken)
  {
    var query = await ApplyDeviceScopeAsync(
      appDb.Devices.Include(x => x.Tags).AsSplitQuery(), cancellationToken);

    await foreach (var device in query.OrderBy(x => x.CreatedAt).AsAsyncEnumerable().WithCancellation(cancellationToken))
    {
      var isOutdated = await agentVersionProvider.IsAgentOutdated(device.AgentVersion, cancellationToken);
      yield return device.ToV1ResponseDto(isOutdated);
    }
  }

  [HttpGet("{deviceId:guid}/desktop-sessions")]
  [ProducesResponseType<IReadOnlyList<V1Dtos.DesktopSessionResponseDto>>(StatusCodes.Status200OK)]
  [ProducesResponseType(StatusCodes.Status404NotFound)]
  [ProducesResponseType(StatusCodes.Status409Conflict)]
  public async Task<ActionResult<IReadOnlyList<V1Dtos.DesktopSessionResponseDto>>> GetDesktopSessions(
    [FromRoute] Guid deviceId,
    [FromServices] AppDb appDb,
    [FromServices] IHubContext<AgentHub, IAgentHubClient> agentHub,
    [FromServices] IDesktopSessionAccessAuthorizer desktopSessionAccessAuthorizer,
    [FromServices] IAuthorizationService authorizationService,
    [FromServices] ILogger<DevicesController> logger,
    CancellationToken cancellationToken)
  {
    var device = await appDb.Devices
      .AsNoTracking()
      .FirstOrDefaultAsync(x => x.Id == deviceId, cancellationToken);

    if (device is null)
    {
      return NotFound();
    }

    var authResult = await authorizationService.AuthorizeAsync(User, device, DeviceResourcePolicies.Read);
    if (!authResult.Succeeded)
    {
      return Forbid();
    }

    if (!device.IsOnline || string.IsNullOrWhiteSpace(device.ConnectionId))
    {
      return Conflict("Device is currently offline.");
    }

    try
    {
      var sessions = await agentHub.Clients
        .Client(device.ConnectionId)
        .GetActiveDesktopSessions();

      var principal = PrincipalDescriptorBuilder.FromClaims(User);
      if (principal is null)
      {
        return Unauthorized();
      }

      sessions = sessions
        .Where(x => desktopSessionAccessAuthorizer.CanUse(principal, deviceId, x.SystemSessionId))
        .ToArray();

      var dtos = sessions.Select(V1Dtos.DesktopSessionResponseDto.From).ToList();
      return Ok(dtos);
    }
    catch (Exception ex)
    {
      logger.LogError(ex, "Error while getting desktop sessions for device {DeviceId}.", deviceId);
      return Problem(
        detail: "Failed to retrieve desktop sessions from the agent.",
        statusCode: StatusCodes.Status500InternalServerError,
        title: "Agent communication failed");
    }
  }

  [HttpGet("{deviceId:guid}")]
  [ProducesResponseType<DeviceResponseDto>(StatusCodes.Status200OK)]
  [ProducesResponseType(StatusCodes.Status404NotFound)]
  public async Task<ActionResult<DeviceResponseDto>> GetDevice(
    [FromServices] AppDb appDb,
    [FromServices] IAgentVersionProvider agentVersionProvider,
    [FromServices] IAuthorizationService authorizationService,
    [FromRoute] Guid deviceId,
    CancellationToken cancellationToken)
  {
    var device = await appDb.Devices.FirstOrDefaultAsync(x => x.Id == deviceId, cancellationToken);
    if (device is null)
    {
      return NotFound();
    }

    var authResult = await authorizationService.AuthorizeAsync(User, device, DeviceResourcePolicies.Read);
    if (!authResult.Succeeded)
    {
      return Forbid();
    }

    var isOutdated = await agentVersionProvider.IsAgentOutdated(device.AgentVersion, cancellationToken);
    return device.ToV1ResponseDto(isOutdated);
  }

  [HttpGet("summary")]
  public async IAsyncEnumerable<V1Dtos.DeviceSummaryDto> GetDeviceSummaries(
    [FromServices] AppDb appDb,
    [EnumeratorCancellation] CancellationToken cancellationToken)
  {
    var query = await ApplyDeviceScopeAsync(appDb.Devices, cancellationToken);

    await foreach (var device in query.OrderBy(x => x.CreatedAt).AsAsyncEnumerable().WithCancellation(cancellationToken))
    {
      yield return device.ToV1SummaryDto();
    }
  }

  [HttpPost("search")]
  public async Task<ActionResult<V1Dtos.DeviceSearchResponseDto>> SearchDevices(
    [FromBody] V1Dtos.DeviceSearchRequestDto requestDto,
    [FromServices] AppDb appDb,
    [FromServices] IAgentVersionProvider agentVersionProvider,
    [FromServices] ILogger<DevicesController> logger,
    CancellationToken cancellationToken)
  {
    var isRelationalDatabase = appDb.Database.IsRelational();
    var authorizedQuery = await ApplyDeviceScopeAsync(appDb.Devices.AsQueryable(), cancellationToken);

    var filteredQuery = authorizedQuery
      .FilterBySearchText(requestDto.SearchText, isRelationalDatabase)
      .FilterByOnlineOffline(requestDto.HideOfflineDevices)
      .FilterByColumnFilters(requestDto.FilterDefinitions, isRelationalDatabase, logger);

    var scopedQuery = filteredQuery.FilterByTagsAndDeviceGroups(
      requestDto.TagIds,
      requestDto.TagFilterMatchMode,
      requestDto.DeviceGroupIds,
      requestDto.DeviceGroupFilterMatchMode,
      requestDto.ShowOnlyUntaggedDevices,
      requestDto.ShowOnlyUngroupedDevices);
    var totalCount = await scopedQuery.CountAsync(cancellationToken);

    var devices = await scopedQuery
      .ApplySorting(requestDto.SortDefinitions)
      .Include(x => x.Tags)
      .AsSplitQuery()
      .Skip(requestDto.Page * requestDto.PageSize)
      .Take(requestDto.PageSize)
      .ToListAsync(cancellationToken);

    var pagedDtos = new List<DeviceResponseDto>(devices.Count);
    foreach (var device in devices)
    {
      var isOutdated = await agentVersionProvider.IsAgentOutdated(device.AgentVersion, cancellationToken);
      pagedDtos.Add(device.ToV1ResponseDto(isOutdated));
    }

    var response = new V1Dtos.DeviceSearchResponseDto
    {
      Items = pagedDtos,
      TotalItems = totalCount
    };

    return response;
  }

  [HttpPatch("{deviceId:guid}/alias")]
  [ProducesResponseType<DeviceResponseDto>(StatusCodes.Status200OK)]
  [ProducesResponseType(StatusCodes.Status400BadRequest)]
  [ProducesResponseType(StatusCodes.Status404NotFound)]
  public async Task<ActionResult<DeviceResponseDto>> UpdateDeviceAlias(
    [FromRoute] Guid deviceId,
    [FromBody] V1Dtos.UpdateDeviceAliasRequestDto requestDto,
    [FromServices] AppDb appDb,
    [FromServices] IAgentVersionProvider agentVersionProvider,
    [FromServices] IAuthorizationService authorizationService,
    [FromServices] ILogger<DevicesController> logger,
    CancellationToken cancellationToken)
  {
    if (deviceId != requestDto.DeviceId)
    {
      return BadRequest("Device ID mismatch.");
    }

    if (requestDto.Alias is not null && requestDto.Alias.Length > 100)
    {
      return BadRequest("Alias must be 100 characters or fewer.");
    }

    var device = await appDb.Devices.FirstOrDefaultAsync(x => x.Id == deviceId, cancellationToken);
    if (device is null)
    {
      logger.LogWarning("Device {DeviceId} not found for alias update.", deviceId);
      return NotFound();
    }

    var authResult = await authorizationService.AuthorizeAsync(User, device, DeviceResourcePolicies.AliasWrite);
    if (!authResult.Succeeded)
    {
      return Forbid();
    }

    device.Alias = requestDto.Alias ?? string.Empty;
    await appDb.SaveChangesAsync(cancellationToken);

    var isOutdated = await agentVersionProvider.IsAgentOutdated(device.AgentVersion, cancellationToken);
    return device.ToV1ResponseDto(isOutdated);
  }

  private async Task<IQueryable<Device>> ApplyDeviceScopeAsync(
    IQueryable<Device> query,
    CancellationToken cancellationToken)
  {
    if (User.IsServerPrincipal())
    {
      return query;
    }

    if (!User.TryGetTenantId(out var tenantId))
    {
      return query.Take(0);
    }

    var accessScope = await _deviceAccessScopeResolver.Resolve(User, tenantId, cancellationToken);
    return query.ApplyAccessScope(tenantId, accessScope);
  }
}
