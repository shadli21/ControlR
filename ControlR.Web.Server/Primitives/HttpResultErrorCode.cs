namespace ControlR.Web.Server.Primitives;

/// <summary>
/// Defines HTTP-specific error codes for mapping to HTTP status codes.
/// </summary>
public enum HttpResultErrorCode
{
  /// <summary>
  /// No error occurred.
  /// </summary>
  None = 0,

  /// <summary>
  /// The requested resource was not found.
  /// </summary>
  NotFound,

  /// <summary>
  /// The request conflicts with an existing resource.
  /// </summary>
  Conflict,

  /// <summary>
  /// The request is invalid or malformed.
  /// </summary>
  BadRequest,

  /// <summary>
  /// The user is not authorized to perform the action.
  /// </summary>
  Unauthorized,

  /// <summary>
  /// The user is authenticated but lacks permission.
  /// </summary>
  Forbidden,

  /// <summary>
  /// An unexpected server error occurred.
  /// </summary>
  InternalServerError,

  /// <summary>
  /// The operation is not implemented.
  /// </summary>
  NotImplemented,

  /// <summary>
  /// The service is temporarily unavailable.
  /// </summary>
  ServiceUnavailable,

  /// <summary>
  /// The request data failed validation.
  /// </summary>
  ValidationFailed
}
