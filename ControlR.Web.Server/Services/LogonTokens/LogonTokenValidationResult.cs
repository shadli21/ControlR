using System.Diagnostics.CodeAnalysis;

namespace ControlR.Web.Server.Services.LogonTokens;

public class LogonTokenValidationResult
{
  public string? ErrorMessage { get; set; }
  [MemberNotNullWhen(true, nameof(UserId), nameof(TenantId), nameof(TokenId))]
  public bool IsValid { get; set; }
  public string? SessionCorrelationId { get; set; }
  public Guid? TenantId { get; set; }
  public Guid? TokenId { get; set; }

  public Guid? UserId { get; set; }

  public static LogonTokenValidationResult Failure(string errorMessage)
  {
    return new LogonTokenValidationResult
    {
      IsValid = false,
      ErrorMessage = errorMessage
    };
  }

  public static LogonTokenValidationResult Success(
    Guid tokenId,
    Guid userId,
    Guid tenantId,
    string? sessionCorrelationId = null)
  {
    return new LogonTokenValidationResult
    {
      IsValid = true,
      TokenId = tokenId,
      UserId = userId,
      TenantId = tenantId,
      SessionCorrelationId = sessionCorrelationId
    };
  }
}
