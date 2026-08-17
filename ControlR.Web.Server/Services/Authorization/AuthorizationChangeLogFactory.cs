using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ControlR.Web.Server.Services.Authorization;

/// <summary>
/// Creates <see cref="AuthorizationChangeLog"/> entries with typed, properly-serialized
/// before/after snapshots. Eliminates hand-interpolated JSON strings. The returned entity is
/// NOT saved by the factory: callers add it to their own <c>DbContext</c> so the audit row is
/// committed in the same transaction as the mutation it records.
/// </summary>
public interface IAuthorizationChangeLogFactory
{
  AuthorizationChangeLog Create(
    string actionType,
    string actorPrincipalType,
    Guid? actorPrincipalId,
    string targetType,
    Guid? targetId,
    Guid? owningTenantId,
    object? before = null,
    object? after = null);
}

public class AuthorizationChangeLogFactory(IHttpContextAccessor httpContextAccessor) : IAuthorizationChangeLogFactory
{
  private static readonly JsonSerializerOptions _serializerOptions = new()
  {
    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    Converters = { new JsonStringEnumConverter() }
  };

  private readonly IHttpContextAccessor _httpContextAccessor = httpContextAccessor;

  public AuthorizationChangeLog Create(
    string actionType,
    string actorPrincipalType,
    Guid? actorPrincipalId,
    string targetType,
    Guid? targetId,
    Guid? owningTenantId,
    object? before = null,
    object? after = null)
  {
    return new AuthorizationChangeLog
    {
      ActionType = actionType,
      ActorPrincipalType = actorPrincipalType,
      ActorPrincipalId = NormalizeEmptyGuid(actorPrincipalId),
      TargetType = targetType,
      TargetId = NormalizeEmptyGuid(targetId),
      OwningTenantId = owningTenantId,
      BeforeJson = before is not null ? JsonSerializer.Serialize(before, _serializerOptions) : null,
      AfterJson = after is not null ? JsonSerializer.Serialize(after, _serializerOptions) : null,
      IpAddress = ResolveIpAddress(),
      CorrelationId = ResolveCorrelationId()
    };
  }

  /// <summary>
  /// Normalizes a <see cref="Guid.Empty"/> to <see langword="null"/> so an unresolved
  /// (e.g. pre-save) entity ID can never be written to the audit log as a literal
  /// <c>00000000-0000-0000-0000-000000000000</c>.
  /// </summary>
  private static Guid? NormalizeEmptyGuid(Guid? value) =>
    value is { } nonNull && nonNull != Guid.Empty ? nonNull : null;

  /// <summary>
  /// Resolves the W3C trace id of the current activity, when one is active. The trace id is
  /// stable across the whole request chain (including upstream callers propagating trace
  /// context), unlike SpanId, which changes per child activity. Background services have no
  /// ambient activity and get <see langword="null"/>.
  /// </summary>
  private static string? ResolveCorrelationId()
  {
    var traceId = Activity.Current?.TraceId;
    return traceId is { } id && id != default ? id.ToString() : null;
  }

  /// <summary>
  /// Resolves the caller's IP address from the ambient HTTP context. Background services and
  /// other non-HTTP callers have no <see cref="HttpContext"/> and get <see langword="null"/>.
  /// </summary>
  private string? ResolveIpAddress()
  {
    var remoteIp = _httpContextAccessor.HttpContext?.Connection.RemoteIpAddress;
    if (remoteIp is null)
    {
      return null;
    }

    var ipString = remoteIp.IsIPv4MappedToIPv6
      ? remoteIp.MapToIPv4().ToString()
      : remoteIp.ToString();

    return ipString.Length <= 64 ? ipString : ipString[..64];
  }
}
