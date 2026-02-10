using System.Diagnostics.CodeAnalysis;

namespace ControlR.Web.Server.Services;

public class PersonalAccessTokenValidationResult
{
  public string? ErrorMessage { get; set; }
  [MemberNotNullWhen(true, nameof(UserId))]
  public bool IsValid { get; set; }

  public Guid? UserId { get; set; }

  public static PersonalAccessTokenValidationResult Failure(string errorMessage)
  {
    return new PersonalAccessTokenValidationResult
    {
      IsValid = false,
      ErrorMessage = errorMessage
    };
  }

  public static PersonalAccessTokenValidationResult Success(Guid userId)
  {
    return new PersonalAccessTokenValidationResult
    {
      IsValid = true,
      UserId = userId
    };
  }
}
