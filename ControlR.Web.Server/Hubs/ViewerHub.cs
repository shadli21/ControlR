using System.Runtime.CompilerServices;
using System.Threading.Channels;
using ControlR.Libraries.Api.Contracts.Constants;
using ControlR.Libraries.Api.Contracts.Dtos.Devices;
using ControlR.Libraries.Api.Contracts.Dtos.HubDtos;
using ControlR.Libraries.Api.Contracts.Dtos.HubDtos.PwshCommandCompletions;
using ControlR.Libraries.Shared.Helpers;
using ControlR.Libraries.Api.Contracts.Hubs.Clients;
using Microsoft.AspNetCore.SignalR;
using ControlR.Web.Server.Services.Settings;
using ControlR.Web.Server.Authz.Permissions;
using ControlR.Web.Server.Services.Authorization;
using System.Diagnostics;
using System.Security.Claims;

namespace ControlR.Web.Server.Hubs;

[Authorize]
public class ViewerHub(
  TimeProvider timeProvider,
  UserManager<AppUser> userManager,
  AppDb appDb,
  IAuthorizationService authorizationService,
  IPermissionEvaluator permissionEvaluator,
  IHubContext<AgentHub, IAgentHubClient> agentHub,
  IEffectiveUserPreferencesResolver effectiveUserPreferencesResolver,
  IHubStreamStore hubStreamStore,
  IDesktopSessionAccessAuthorizer desktopSessionAccessAuthorizer,
  IOptionsMonitor<AppOptions> appOptions,
  ILogger<ViewerHub> logger)
  : HubWithItems<IViewerHubClient>, IViewerHub
{
  private const int MaxHeartbeatSubscriptionBatch = 100;

  private readonly IHubContext<AgentHub, IAgentHubClient> _agentHub = agentHub;
  private readonly AppDb _appDb = appDb;
  private readonly IOptionsMonitor<AppOptions> _appOptions = appOptions;
  private readonly IAuthorizationService _authorizationService = authorizationService;
  private readonly IDesktopSessionAccessAuthorizer _desktopSessionAccessAuthorizer = desktopSessionAccessAuthorizer;
  private readonly IEffectiveUserPreferencesResolver _effectiveUserPreferencesResolver = effectiveUserPreferencesResolver;
  private readonly IHubStreamStore _hubStreamStore = hubStreamStore;
  private readonly ILogger<ViewerHub> _logger = logger;
  private readonly IPermissionEvaluator _permissionEvaluator = permissionEvaluator;
  private readonly TimeProvider _timeProvider = timeProvider;
  private readonly UserManager<AppUser> _userManager = userManager;

  public Activity? SessionActivity
  {
    get => GetItem((Activity?)null);
    set => SetItem(value);
  }

  public Task AddViewerActivity(string activityName)
  {
    using var activity = SessionActivity?.StartChildActivity(activityName);
    _logger.LogInformation("Viewer Activity: {EventName}", activityName);
    return Task.CompletedTask;
  }

  public async Task<HubResult> CloseChatSession(Guid deviceId, Guid sessionId, int targetProcessId)
  {
    try
    {
      if (await TryAuthorizeAgainstDevice(deviceId, DeviceResourcePolicies.ChatSend) is not { IsSuccess: true } authResult)
      {
        return HubResult.Fail("Unauthorized.");
      }

      _logger.LogInformation(
        "Closing chat session {SessionId} for device {DeviceId} and process {ProcessId}",
        sessionId,
        deviceId,
        targetProcessId);

      var result = await _agentHub.Clients
        .Client(authResult.Value.ConnectionId)
        .CloseChatSession(sessionId, targetProcessId);

      return result;
    }
    catch (Exception ex)
    {
      _logger.LogError(ex, "Error while closing chat session {SessionId} on device {DeviceId}.", sessionId, deviceId);
      return HubResult.Fail("Agent could not be reached.");
    }
  }

  public async Task CloseTerminalSession(Guid deviceId, Guid terminalSessionId)
  {
    try
    {
      if (await TryAuthorizeAgainstDevice(deviceId, DeviceResourcePolicies.TerminalUse) is not { IsSuccess: true } authResult)
      {
        return;
      }

      await _agentHub.Clients
        .Client(authResult.Value.ConnectionId)
        .CloseTerminalSession(terminalSessionId);
    }
    catch (Exception ex)
    {
      _logger.LogError(ex, "Error while closing terminal session.");
    }
  }

  public async Task<HubResult> CreateTerminalSession(
    Guid deviceId,
    Guid terminalSessionId)
  {
    try
    {
      if (await TryAuthorizeAgainstDevice(deviceId, DeviceResourcePolicies.TerminalUse) is not { IsSuccess: true } authResult)
      {
        return HubResult.Fail("Forbidden.");
      }

      var createResult = await _agentHub.Clients
        .Client(authResult.Value.ConnectionId)
        .CreateTerminalSession(terminalSessionId, Context.ConnectionId);

      _logger.LogInformation("Create terminal session.  Success: {IsSuccess}", createResult.IsSuccess);

      return createResult;
    }
    catch (Exception ex)
    {
      _logger.LogError(ex, "Error while creating terminal session.");
      return HubResult.Fail("An error occurred.");
    }
  }

  public Task DisposeDeviceAccessActivity()
  {
    SessionActivity?.Dispose();
    SessionActivity = null;
    return Task.CompletedTask;
  }

  public async Task<DesktopSession[]> GetActiveDesktopSessions(Guid deviceId)
  {
    try
    {
      if (await TryAuthorizeAgainstDevice(deviceId, DeviceResourcePolicies.RemoteControlConnect) is not { IsSuccess: true } authResult)
      {
        return [];
      }

      var device = authResult.Value;
      var principal = Context.User is null
        ? null
        : PrincipalDescriptorBuilder.FromClaims(Context.User);
      if (principal is null)
      {
        return [];
      }

      var sessions = await _agentHub.Clients.Client(device.ConnectionId).GetActiveDesktopSessions();
      return sessions
        .Where(x => _desktopSessionAccessAuthorizer.CanUse(principal, deviceId, x.SystemSessionId))
        .ToArray();
    }
    catch (Exception ex)
    {
      _logger.LogError(ex, "Error while getting Windows sessions from agent.");
      return [];
    }
  }

  public async Task<HubResult<DeviceAccessPermissionsDto>> GetDeviceAccessPermissions(Guid deviceId)
  {
    try
    {
      var device = await _appDb.Devices
        .AsNoTracking()
        .FirstOrDefaultAsync(x => x.Id == deviceId);

      if (device is null)
      {
        return HubResult.Fail<DeviceAccessPermissionsDto>("Device not found.");
      }

      if (!await CanAccessDevice(device, DeviceResourcePolicies.Read))
      {
        return HubResult.Fail<DeviceAccessPermissionsDto>("Unauthorized.");
      }

      var permissions = new DeviceAccessPermissionsDto(
        await CanAccessDevice(device, DeviceResourcePolicies.OverviewRead),
        await CanAccessDevice(device, DeviceResourcePolicies.RemoteControlConnect),
        await CanAccessDevice(device, DeviceResourcePolicies.TerminalUse),
        await CanAccessDevice(device, DeviceResourcePolicies.ChatSend),
        await CanAccessDevice(device, DeviceResourcePolicies.FileSystemRead),
        await CanAccessDevice(device, DeviceResourcePolicies.LogsRead),
        await CanAccessDevice(device, DeviceResourcePolicies.VncRelayConnect),
        await CanAccessDevice(device, DeviceResourcePolicies.RemoteControlInteract),
        await CanAccessDevice(device, DeviceResourcePolicies.RemoteControlBlockInput),
        await CanAccessDevice(device, DeviceResourcePolicies.ClipboardRead),
        await CanAccessDevice(device, DeviceResourcePolicies.ClipboardWrite),
        await CanAccessDevice(device, DeviceResourcePolicies.CtrlAltDelSend));

      return HubResult.Ok(permissions);
    }
    catch (Exception ex)
    {
      _logger.LogError(ex, "Error while resolving device-access permissions for device {DeviceId}.", deviceId);
      return HubResult.Fail<DeviceAccessPermissionsDto>("An error occurred while resolving device permissions.");
    }
  }

  public async Task<HubResult<PwshCompletionsResponseDto>> GetPwshCompletions(PwshCompletionsRequestDto request)
  {
    try
    {
      if (await TryAuthorizeAgainstDevice(request.DeviceId, DeviceResourcePolicies.TerminalUse) is not { IsSuccess: true } authResult)
      {
        return HubResult.Fail<PwshCompletionsResponseDto>("Forbidden.");
      }

      // Create a new request with ViewerConnectionId
      var requestWithViewerConnection = request with { ViewerConnectionId = Context.ConnectionId };

      return await _agentHub.Clients
        .Client(authResult.Value.ConnectionId)
        .GetPwshCompletions(requestWithViewerConnection);
    }
    catch (Exception ex)
    {
      _logger.LogError(ex, "Error while getting PowerShell command completions.");
      return HubResult.Fail<PwshCompletionsResponseDto>("An error occurred.");
    }
  }

  public async Task<HubResult> InvokeCtrlAltDel(Guid deviceId, int targetDesktopProcessId, DesktopSessionType desktopSessionType)
  {
    try
    {
      _logger.LogInformation(
        "Invoking CtrlAltDel for device {DeviceId} and process {ProcessId}.  User: {UserId}",
        deviceId,
        targetDesktopProcessId,
        Context.UserIdentifier);

      if (await TryAuthorizeAgainstDevice(deviceId, DeviceResourcePolicies.CtrlAltDelSend) is not { IsSuccess: true } authResult)
      {
        return HubResult.Fail("Unauthorized.");
      }

      if (!TryGetUserId(out var userId))
      {
        _logger.LogError("Failed to get user ID for CtrlAltDel invocation.");
        return HubResult.Fail("Failed to get user ID.");
      }

      var displayNameResult = await GetDisplayName(userId);
      if (!displayNameResult.IsSuccess)
      {
        return HubResult.Fail(displayNameResult.Reason ?? "Failed to resolve display name.");
      }

      var dto = new InvokeCtrlAltDelRequestDto(
        targetDesktopProcessId,
        Context.User?.Identity?.Name ?? "Unknown",
        desktopSessionType);

      return await _agentHub.Clients
        .Client(authResult.Value.ConnectionId)
        .InvokeCtrlAltDel(dto);
    }
    catch (Exception ex)
    {
      _logger.LogError(ex, "An error occurred while invoking CtrlAltDel.");
      return HubResult.Fail("An error occurred while invoking CtrlAltDel.");
    }
  }

  public override async Task OnConnectedAsync()
  {
    try
    {
      await base.OnConnectedAsync();

      if (Context.User?.TryGetUserId(out var userId) != true)
      {
        _logger.LogCritical("User is null on connect. Client is trying to connect to ViewerHub from an authenticated but invalid context.");
        return;
      }

      var user = await _appDb.Users.FirstOrDefaultAsync(x => x.Id == userId);
      if (user is null)
      {
        _logger.LogCritical("Failed to find user from UserManager.");
        return;
      }

      user.IsOnline = true;
      user.LastLogin = _timeProvider.GetUtcNow();
      await _appDb.SaveChangesAsync();

      await JoinServerTopics();
    }
    catch (Exception ex)
    {
      _logger.LogError(ex, "Error during viewer connect.");
    }
  }

  public override async Task OnDisconnectedAsync(Exception? exception)
  {
    try
    {
      await base.OnDisconnectedAsync(exception);

      SessionActivity?.Dispose();
      SessionActivity = null;

      if (Context.User is null)
      {
        _logger.LogCritical("User is null on disconnect. The principal may have been invalidated during the connection lifetime.");
        return;
      }

      var user = await _userManager.GetUserAsync(Context.User);

      if (user is null)
      {
        _logger.LogCritical("Failed to find user from UserManager.");
        return;
      }

      user.IsOnline = false;
      await _userManager.UpdateAsync(user);
    }
    catch (Exception ex)
    {
      _logger.LogError(ex, "Error during viewer disconnect.");
    }
  }

  public async Task RefreshDeviceInfo(Guid deviceId)
  {
    try
    {
      if (await TryAuthorizeAgainstDevice(deviceId, DeviceResourcePolicies.Read) is not { IsSuccess: true } authResult)
      {
        return;
      }

      await _agentHub.Clients
        .Client(authResult.Value.ConnectionId)
        .RefreshDeviceInfo();
    }
    catch (Exception ex)
    {
      _logger.LogError(ex, "Error while refreshing device info.");
    }
  }

  public async Task<HubResult> RequestRemoteControlPermission(Guid deviceId, int targetProcessId)
  {
    try
    {
      if (await TryAuthorizeAgainstDevice(deviceId, DeviceResourcePolicies.RemoteControlConnect) is not { IsSuccess: true } authResult)
      {
        return HubResult.Fail("Unauthorized.");
      }

      return await _agentHub.Clients
        .Client(authResult.Value.ConnectionId)
        .RequestRemoteControlPermission(targetProcessId);
    }
    catch (Exception ex)
    {
      _logger.LogError(ex, "Error while requesting remote control permission.");
      return HubResult.Fail("An error occurred while requesting remote control permission.");
    }
  }

  public async Task<HubResult> RequestRemoteControlSession(
    Guid deviceId,
    RemoteControlSessionRequestDto sessionRequestDto)
  {
    try
    {
      if (!TryGetUserId(out var userId))
      {
        return HubResult.Fail("Failed to get user ID.");
      }

      var remoteIp = Context.GetHttpContext()?.Connection.RemoteIpAddress?.ToString();

      var displayNameResult = await GetDisplayName(userId);
      if (!displayNameResult.IsSuccess)
      {
        return HubResult.Fail(displayNameResult.Reason ?? "Failed to resolve display name.");
      }

      var displayName = displayNameResult.Value;

      _logger.LogInformation(
        "Starting streaming session requested by user {DisplayName} ({UserId}) for device {DeviceId} from IP {RemoteIp}.",
        displayName,
        userId,
        deviceId,
        remoteIp);

      if (await TryAuthorizeAgainstDevice(deviceId, DeviceResourcePolicies.RemoteControlConnect) is not { IsSuccess: true } authResult)
      {
        return HubResult.Fail("Unauthorized.");
      }

      if (!CanUseDesktopSession(deviceId, sessionRequestDto.TargetSystemSession))
      {
        return HubResult.Fail("The requested desktop session is not authorized.");
      }

      var device = authResult.Value;
      var notifyUser = await _effectiveUserPreferencesResolver.GetNotifyUserOnSessionStart(
        device.TenantId,
        userId,
        Context.ConnectionAborted);

      sessionRequestDto = sessionRequestDto with
      {
        NotifyUserOnSessionStart = notifyUser,
        ViewerName = displayName,
        ViewerConnectionId = Context.ConnectionId
      };

      var result = await _agentHub.Clients
        .Client(device.ConnectionId)
        .CreateRemoteControlSession(sessionRequestDto);

      return result;
    }
    catch (Exception ex)
    {
      const string reason = "An error occurred while requesting the remote control session.";
      _logger.LogError(ex, reason);
      return HubResult.Fail(reason);
    }
  }

  public async Task<HubResult> RequestVncSession(Guid deviceId, VncSessionRequestDto sessionRequestDto)
  {
    try
    {
      if (await TryAuthorizeAgainstDevice(deviceId, DeviceResourcePolicies.VncRelayConnect) is not { IsSuccess: true } authResult)
      {
        return HubResult.Fail("Unauthorized.");
      }

      if (Context.User is null)
      {
        return HubResult.Fail("User is null.");
      }

      if (!TryGetUserId(out var userId))
      {
        return HubResult.Fail("Failed to get user ID.");
      }

      var user = await _userManager.Users
        .AsNoTracking()
        .Include(x => x.UserPreferences)
        .FirstOrDefaultAsync(x => x.Id == userId);

      if (user is null)
      {
        return HubResult.Fail("User not found.");
      }

      var notifyUser = await _effectiveUserPreferencesResolver.GetNotifyUserOnSessionStart(
        authResult.Value.TenantId,
        userId,
        Context.ConnectionAborted);

      var displayNameResult = await GetDisplayName(userId);
      if (!displayNameResult.IsSuccess)
      {
        return HubResult.Fail(displayNameResult.Reason ?? "Failed to resolve display name.");
      }

      var displayName = displayNameResult.Value;
      
      var remoteIp = Context.GetHttpContext()?.Connection.RemoteIpAddress?.ToString();

      _logger.LogInformation(
        "Starting VNC session requested by user {DisplayName} ({UserId}) for device {DeviceId} from IP {RemoteIp}.",
        displayName,
        userId,
        deviceId,
        remoteIp);

      var device = authResult.Value;

      if (string.IsNullOrWhiteSpace(displayName))
      {
        displayName = user.UserName ?? "";
      }

      sessionRequestDto = sessionRequestDto with
      {
        NotifyUserOnSessionStart = notifyUser,
        ViewerConnectionId = Context.ConnectionId,
        ViewerName = displayName,
      };

      return await _agentHub.Clients
        .Client(device.ConnectionId)
        .CreateVncSession(sessionRequestDto);
    }
    catch (Exception ex)
    {
      const string reason = "An error occurred while requesting the VNC session.";
      _logger.LogError(ex, reason);
      return HubResult.Fail(reason);
    }
  }

  public async Task SendAgentUpdateTrigger(Guid deviceId)
  {
    try
    {
      if (await TryAuthorizeAgainstDevice(deviceId, DeviceResourcePolicies.AgentUpdate) is not { IsSuccess: true } authResult)
      {
        return;
      }

      await _agentHub.Clients
        .Client(authResult.Value.ConnectionId)
        .ReceiveAgentUpdateTrigger();
    }
    catch (Exception ex)
    {
      _logger.LogError(ex, "Error while sending agent update trigger.");
    }
  }

  public async Task<HubResult> SendChatMessage(Guid deviceId, ChatMessageHubDto dto)
  {
    try
    {
      if (await TryAuthorizeAgainstDevice(deviceId, DeviceResourcePolicies.ChatSend) is not { IsSuccess: true } authResult)
      {
        return HubResult.Fail("Unauthorized.");
      }

      if (!CanUseDesktopSession(deviceId, dto.TargetSystemSession))
      {
        return HubResult.Fail("The requested desktop session is not authorized.");
      }

      var user = await GetRequiredUser(q => q.Include(u => u.UserPreferences));
      var displayName = await GetDisplayName(user);

      // Log the chat message being sent
      _logger.LogInformation(
        "Chat message sent by user {SenderName} ({SenderEmail}) to device {DeviceId} for session {SessionId}",
        displayName,
        user.Email,
        deviceId,
        dto.SessionId);

      dto = dto with
      {
        ViewerConnectionId = Context.ConnectionId,
        SenderName = displayName,
        SenderEmail = $"{user.Email}"
      };

      var sendResult = await _agentHub.Clients
        .Client(authResult.Value.ConnectionId)
        .SendChatMessage(dto);

      return sendResult;
    }
    catch (Exception ex)
    {
      _logger.LogError(ex, "Error while sending chat message to agent.");
      return HubResult.Fail("Agent could not be reached.");
    }
  }

  // Intentionally general-purpose and currently unused by any client. Will be
  // exercised by an upcoming refactor that routes generic DTOs to the agent.
  public async Task SendDtoToAgent(Guid deviceId, DtoWrapper wrapper)
  {
    try
    {
      using var scope = _logger.BeginMemberScope();

      if (await TryAuthorizeAgainstDevice(deviceId) is not { IsSuccess: true } authResult)
      {
        return;
      }

      await _agentHub.Clients
        .Client(authResult.Value.ConnectionId)
        .ReceiveDto(wrapper);
    }
    catch (Exception ex)
    {
      _logger.LogError(ex, "Error while sending DTO to agent.");
    }
  }

  public async Task SendPowerStateChange(Guid deviceId, PowerStateChangeType changeType)
  {
    try
    {
      if (await TryAuthorizeAgainstDevice(deviceId, DeviceResourcePolicies.PowerManage) is not { IsSuccess: true } authResult)
      {
        return;
      }

      await _agentHub.Clients
        .Client(authResult.Value.ConnectionId)
        .ReceivePowerStateChange(changeType);
    }
    catch (Exception ex)
    {
      _logger.LogError(ex, "Error while sending power state change.");
    }
  }

  public async Task<HubResult> SendTerminalInput(Guid deviceId, TerminalInputDto dto)
  {
    try
    {
      if (await TryAuthorizeAgainstDevice(deviceId, DeviceResourcePolicies.TerminalUse) is not { IsSuccess: true } authResult)
      {
        return HubResult.Fail("Unauthorized.");
      }

      // Create a new DTO with ViewerConnectionId
      var dtoWithViewerConnection = dto with { ViewerConnectionId = Context.ConnectionId };

      var sendResult = await _agentHub.Clients
        .Client(authResult.Value.ConnectionId)
        .ReceiveTerminalInput(dtoWithViewerConnection);

      _logger.LogInformation("Terminal input sent to agent. Success: {Success}", sendResult.IsSuccess);

      return sendResult;
    }
    catch (Exception ex)
    {
      _logger.LogError(ex, "Error while sending terminal input.");
      return HubResult.Fail("Agent could not be reached.");
    }
  }

  public async Task<HubResult<string>> SendWakeDevice(Guid deviceId, string[] macAddresses)
  {
    try
    {
      if (await TryAuthorizeAgainstDevice(deviceId, DeviceResourcePolicies.WakeSend) is not { IsSuccess: true } authResult)
      {
        return HubResult.Fail<string>("Unauthorized.");
      }

      var target = authResult.Value;

      // A magic packet only reaches the target's LAN if an online neighbor emits it there,
      // so fan out only to online devices that share the target's network (same public IP).
      // Device group/tag membership is organizational, not spatial, and is not a proximity signal.
      if (string.IsNullOrWhiteSpace(target.PublicIpV4))
      {
        return HubResult.Ok($"The target device has no known public IP, so no network neighbors could be found to broadcast the magic packet.");
      }

      var connectionIds = await _appDb.Devices
        .Where(device => device.Id != deviceId &&
                         device.TenantId == target.TenantId &&
                         device.CustomerId == target.CustomerId &&
                         device.PublicIpV4 == target.PublicIpV4 &&
                         device.IsOnline &&
                         device.ConnectionId != string.Empty)
        .Select(device => device.ConnectionId)
        .ToListAsync();

      if (connectionIds.Count == 0)
      {
        return HubResult.Ok($"No online devices sharing public IP {target.PublicIpV4} were found. The target may need an online agent on the same network to be woken.");
      }

      var dto = new WakeDeviceDto(macAddresses);
      await _agentHub.Clients
        .Clients(connectionIds)
        .InvokeWakeDevice(dto);

      return HubResult.Ok($"Magic packet broadcast by {connectionIds.Count} devic{(connectionIds.Count == 1 ? "e" : "es")} with public IP {target.PublicIpV4}.");
    }
    catch (Exception ex)
    {
      _logger.LogError(ex, "Error while sending wake device command.");
      return HubResult.Fail<string>("An error occurred while sending the wake command.");
    }
  }

  public async Task<HubResult> StartDeviceAccessActivity(Guid deviceId)
  {
    if (Context.User is null)
    {
      _logger.LogCritical("Failed to get user ID when starting remote access session.");
      return HubResult.Fail("Unauthorized.");
    }

    var authResult = await TryAuthorizeAgainstDevice(deviceId);
    if (!authResult.IsSuccess)
    {
      return HubResult.Fail("Unauthorized.");
    }

    var user = await _userManager.GetUserAsync(Context.User);

    if (user?.UserName is null)
    {
      _logger.LogCritical("Failed to get user name when starting remote access session.");
      return HubResult.Fail("Unauthorized.");
    }

    SessionActivity = DefaultActivitySource.StartDeviceAccessActivity(
      userName: user.UserName, 
      userId: user.Id, 
      deviceId: deviceId);

    if (Context.User.FindFirstValue(UserClaimTypes.SessionCorrelationId) is {} sessionCorrelationId)
    {
      SessionActivity?.SetTag(ActivityTagKeys.SessionCorrelationId, sessionCorrelationId);
    }

    return HubResult.Ok();
  }

  public async Task<HubResult> SubscribeToDeviceHeartbeats(Guid[] deviceIds)
  {
    if (Context.User is null)
    {
      return HubResult.Fail("Not authenticated.");
    }

    if (deviceIds is not { Length: > 0 })
    {
      return HubResult.Ok();
    }

    if (deviceIds.Length > MaxHeartbeatSubscriptionBatch)
    {
      return HubResult.Fail(
        $"Too many device IDs ({deviceIds.Length}). Subscribe at most {MaxHeartbeatSubscriptionBatch} devices per call.");
    }

    var distinctIds = deviceIds.Distinct().ToArray();

    var devices = await _appDb.Devices.AsNoTracking()
      .Where(x => distinctIds.Contains(x.Id))
      .ToListAsync();

    foreach (var device in devices)
    {
      var authResult = await _authorizationService.AuthorizeAsync(
        Context.User, device, DeviceResourcePolicies.Read);

      if (authResult.Succeeded)
      {
        await Groups.AddToGroupAsync(Context.ConnectionId, HubGroupNames.DeviceHeartbeat(device.Id));
      }
    }

    return HubResult.Ok();
  }

  public async Task<HubResult> TestVncConnection(Guid guid, int port)
  {
    try
    {
      if (await TryAuthorizeAgainstDevice(guid, DeviceResourcePolicies.VncRelayConnect) is not { IsSuccess: true } authResult)
      {
        return HubResult.Fail("Unauthorized.");
      }

      return await _agentHub.Clients
        .Client(authResult.Value.ConnectionId)
        .TestVncConnection(port);
    }
    catch (Exception ex)
    {
      _logger.LogError(ex, "Error while testing VNC connection.");
      return HubResult.Fail("An error occurred while testing the VNC connection.");
    }
  }

  public async Task UninstallAgent(Guid deviceId, string reason)
  {
    try
    {
      // Uninstalling removes the agent from the machine, so it requires delete authority
      // rather than the catch-all read policy.
      if (await TryAuthorizeAgainstDevice(deviceId, DeviceResourcePolicies.Delete) is not { IsSuccess: true } authResult)
      {
        return;
      }

      _logger.LogInformation(
        "Agent uninstall command sent by user: {UserName}.  Device: {DeviceId}",
        Context.UserIdentifier,
        deviceId);

      await _agentHub.Clients
        .Client(authResult.Value.ConnectionId)
        .UninstallAgent(reason);
    }
    catch (Exception ex)
    {
      _logger.LogError(ex, "Error while uninstalling agent.");
    }
  }

  public async Task UnsubscribeFromDeviceHeartbeats(Guid[] deviceIds)
  {
    if (deviceIds is not { Length: > 0 })
    {
      return;
    }

    foreach (var deviceId in deviceIds.Distinct())
    {
      await Groups.RemoveFromGroupAsync(Context.ConnectionId, HubGroupNames.DeviceHeartbeat(deviceId));
    }
  }

  public async Task<HubResult> UploadFile(
    FileUploadMetadata fileUploadMetadata,
    ChannelReader<byte[]> fileStream)
  {
    try
    {

      var deviceId = fileUploadMetadata.DeviceId;

      if (await TryAuthorizeAgainstDevice(deviceId, DeviceResourcePolicies.FileSystemWrite) is not { IsSuccess: true } authResult)
      {
        return HubResult.Fail("Unauthorized.");
      }

      var maxUploadSize = _appOptions.CurrentValue.MaxFileTransferSize;
      if (maxUploadSize > 0 && fileUploadMetadata.FileSize > maxUploadSize)
      {
        return HubResult.Fail($"File size exceeds the maximum allowed size of {maxUploadSize} bytes.");
      }

      var device = authResult.Value;
      if (string.IsNullOrWhiteSpace(device.ConnectionId))
      {
        _logger.LogWarning("Device {DeviceId} is not connected (no ConnectionId).", deviceId);
        return HubResult.Fail("Device is not currently connected.");
      }

      var streamId = Guid.NewGuid();
      using var signaler = _hubStreamStore.GetOrCreate<byte[]>(streamId, TimeSpan.FromMinutes(30));

      var uploadRequest = new FileUploadHubDto(
        streamId,
        fileUploadMetadata.TargetDirectory,
        fileUploadMetadata.FileName,
        fileUploadMetadata.FileSize,
        fileUploadMetadata.Overwrite);

      // Asynchronously write the client's stream to the channel.
      var writeTask = signaler.WriteFromChannelReader(fileStream, Context.ConnectionAborted);

      // Notify the agent about the incoming upload
      var receiveResult = await _agentHub.Clients
        .Client(device.ConnectionId)
        .DownloadFileFromViewer(uploadRequest)
        .WaitAsync(Context.ConnectionAborted);

      if (receiveResult is null || !receiveResult.IsSuccess)
      {
        var reason = receiveResult?.Reason ?? "Agent did not respond.";
        _logger.LogWarning("Device {DeviceId} failed to download file {FileName}.  Reason: {Reason}",
          deviceId,
          fileUploadMetadata.FileName,
          reason);
        return HubResult.Fail($"Agent failed to download file: {reason}");
      }

      // Await the write task to ensure all data is sent or an error occurs.
      try
      {
        await writeTask;
      }
      catch (Exception ex)
      {
        _logger.LogError(ex, "Error writing file stream for {FileName} to device {DeviceId}",
          fileUploadMetadata.FileName, fileUploadMetadata.DeviceId);
        return HubResult.Fail("An error occurred while writing the file stream.");
      }

      return HubResult.Ok();
    }
    catch (OperationCanceledException)
    {
      _logger.LogInformation("File upload was canceled by the user for file {FileName} to device {DeviceId}",
        fileUploadMetadata.FileName,
        fileUploadMetadata.DeviceId);
      return HubResult.Fail("File upload was canceled.");
    }
    catch (Exception ex)
    {
      _logger.LogError(ex, "Error uploading file {FileName} to device {DeviceId}",
        fileUploadMetadata.FileName, fileUploadMetadata.DeviceId);
      return HubResult.Fail("An error occurred during file upload.");
    }
  }

  private static Task<string> GetDisplayName(AppUser user, string fallbackName = "Admin")
  {
    var displayName = user.UserPreferences
      ?.FirstOrDefault(x => x.Name == UserPreferenceNames.UserDisplayName)
      ?.Value;

    if (string.IsNullOrWhiteSpace(displayName))
    {
      displayName = user.UserName ?? fallbackName;
    }

    return displayName.AsTaskResult();
  }

  private async Task<bool> CanAccessDevice(Device device, string policyName)
  {
    if (Context.User is not { } user)
    {
      return false;
    }

    var result = await _authorizationService.AuthorizeAsync(user, device, policyName);
    return result.Succeeded;
  }

  private bool CanUseDesktopSession(Guid deviceId, int systemSessionId)
  {
    var principal = Context.User is null
      ? null
      : PrincipalDescriptorBuilder.FromClaims(Context.User);
    return principal is not null &&
      _desktopSessionAccessAuthorizer.CanUse(principal, deviceId, systemSessionId);
  }

  private async Task<HubResult<string>> GetDisplayName(Guid userId)
  {
    var user = await _userManager.Users
      .AsNoTracking()
      .Include(x => x.UserPreferences)
      .FirstOrDefaultAsync(x => x.Id == userId);

    if (user is null)
    {
      _logger.LogError("User not found.");
      return HubResult.Fail<string>("User not found.");
    }

    var displayName = user.UserPreferences
      ?.FirstOrDefault(x => x.Name == UserPreferenceNames.UserDisplayName)
      ?.Value;

    if (string.IsNullOrWhiteSpace(displayName))
    {
      displayName = user.UserName ?? "";
    }
    return HubResult.Ok(displayName);
  }

  private async Task<AppUser> GetRequiredUser(Func<IQueryable<AppUser>, IQueryable<AppUser>>? includeBuilder = null)
  {
    if (!TryGetUserId(out var userId))
    {
      throw new UnauthorizedAccessException("Failed to get user ID.");
    }

    var query = _userManager.Users.AsNoTracking();

    if (includeBuilder is not null)
    {
      query = includeBuilder.Invoke(query);
    }

    var user = await query.FirstOrDefaultAsync(x => x.Id == userId);

    Guard.IsNotNull(user);
    return user;
  }

  private async Task JoinServerTopics()
  {
    if (Context.User is null)
    {
      return;
    }

    var principal = Context.User is null
      ? null
      : PrincipalDescriptorBuilder.FromClaims(Context.User);
    if (principal is null)
    {
      return;
    }

    // Evaluate against a server resource so credential scoping is honored. GetEffectivePermissionNames
    // returns the underlying user's full name-level set and could let a scoped credential subscribe.
    var serverResource = new ResourceDescriptor(PermissionScopeKind.Server);

    var canReadAlerts = await _permissionEvaluator.Evaluate(
      principal, PermissionNames.ServerAlertsRead, serverResource, Context.ConnectionAborted);
    if (canReadAlerts.Allowed)
    {
      await Groups.AddToGroupAsync(Context.ConnectionId, HubGroupNames.ServerAlerts());
    }

    var canReadTelemetry = await _permissionEvaluator.Evaluate(
      principal, PermissionNames.ServerTelemetryRead, serverResource, Context.ConnectionAborted);
    if (canReadTelemetry.Allowed)
    {
      await Groups.AddToGroupAsync(Context.ConnectionId, HubGroupNames.ServerTelemetry());
    }
  }

  private async Task<HubResult<Device>> TryAuthorizeAgainstDevice(
    Guid deviceId,
    string? policyName = null,
    [CallerMemberName] string? callerName = null)
  {
    if (Context.User is null)
    {
      _logger.LogCritical("User is null.  Authorize tag should have prevented this.");
      return HubResult.Fail<Device>("User is null.  Authorize tag should have prevented this.");
    }

    var device = await _appDb.Devices
      .AsNoTracking()
      .FirstOrDefaultAsync(x => x.Id == deviceId);

    if (device is null)
    {
      _logger.LogWarning("Device {DeviceId} not found.", deviceId);
      return HubResult.Fail<Device>("Device not found.");
    }

    var authResult = await _authorizationService.AuthorizeAsync(
      Context.User,
      device,
      policyName ?? DeviceResourcePolicies.Read);

    if (authResult.Succeeded)
    {
      return HubResult.Ok(device);
    }

    _logger.LogCritical(
      "Unauthorized agent access attempted by user: {UserName}.  Device: {DeviceId}.  Method: {MemberName}.",
      Context.UserIdentifier,
      deviceId,
      callerName);

    return HubResult.Fail<Device>("Unauthorized.");
  }

  private bool TryGetTenantId(
    out Guid tenantId,
    [CallerMemberName] string callerName = "")
  {
    tenantId = Guid.Empty;
    if (Context.User?.TryGetTenantId(out tenantId) == true)
    {
      return true;
    }

    _logger.LogError("TenantId claim is unexpected missing when calling {MemberName}.", callerName);
    return false;
  }

  private bool TryGetUserId(
    out Guid userId,
    [CallerMemberName] string callerName = "")
  {
    userId = Guid.Empty;
    if (Context.User?.TryGetUserId(out userId) == true)
    {
      return true;
    }

    _logger.LogError("UserId claim is unexpected missing when calling {MemberName}.", callerName);
    return false;
  }
}
