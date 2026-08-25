using ControlR.Libraries.Api.Contracts.Settings;

namespace ControlR.Web.Client.Services;

public interface ITenantSettingsProvider
{
  Task<bool> GetAppendInstanceId();
  Task<string?> GetInstanceId();
  Task<bool?> GetNotifyUserOnSessionStart();
  Task<TenantSettingsDto> GetSettings();
  Task<bool> SetAppendInstanceId(bool value);
  Task<bool> SetInstanceId(string? value);
  Task<bool> SetNotifyUserOnSessionStart(bool? value);
}

internal class TenantSettingsProvider(
  IControlrApi controlrApi,
  IEffectiveUserPreferences effectiveUserPreferences,
  ISnackbar snackbar,
  ILogger<TenantSettingsProvider> logger) : ITenantSettingsProvider
{
  private readonly IControlrApi _controlrApi = controlrApi;
  private readonly IEffectiveUserPreferences _effectiveUserPreferences = effectiveUserPreferences;
  private readonly ILogger<TenantSettingsProvider> _logger = logger;
  private readonly ISnackbar _snackbar = snackbar;

  private TenantSettingsDto? _settings;

  public async Task<bool> GetAppendInstanceId()
  {
    var settings = await GetSettings();
    return settings.AppendInstanceId ?? false;
  }

  public async Task<string?> GetInstanceId()
  {
    var settings = await GetSettings();
    return settings.InstanceId;
  }

  public async Task<bool?> GetNotifyUserOnSessionStart()
  {
    var settings = await GetSettings();
    return settings.NotifyUserOnSessionStart;
  }

  public async Task<TenantSettingsDto> GetSettings()
  {
    if (_settings is not null)
    {
      return _settings;
    }

    var getResult = await _controlrApi.Internal.TenantSettings.GetTenantSettings();
    if (!getResult.IsSuccess)
    {
      _snackbar.Add(getResult.Reason, Severity.Error);
      return CreateDefaultSettings();
    }

    _settings = getResult.Value;
    return _settings ?? CreateDefaultSettings();
  }

  public async Task<bool> SetAppendInstanceId(bool value)
  {
    return await SetSetting(TenantSettingNames.AppendInstanceId, value);
  }

  public async Task<bool> SetInstanceId(string? value)
  {
    var normalizedValue = string.IsNullOrWhiteSpace(value)
      ? null
      : value.Trim();

    if (!string.IsNullOrWhiteSpace(normalizedValue))
    {
      var normalizationResult = TenantSettingDefinitions.Normalize(TenantSettingNames.InstanceId, normalizedValue);
      if (!normalizationResult.IsSuccess)
      {
        _logger.LogWarning("Rejected invalid instance ID. Reason: {ValidationError}", normalizationResult.ErrorMessage);
        _snackbar.Add(normalizationResult.ErrorMessage ?? "Invalid instance ID.", Severity.Error);
        return false;
      }

      normalizedValue = normalizationResult.Value;
    }

    return await SetSetting(TenantSettingNames.InstanceId, normalizedValue);
  }

  public async Task<bool> SetNotifyUserOnSessionStart(bool? value)
  {
    return await SetSetting(TenantSettingNames.NotifyUserOnSessionStart, value);
  }

  private static TenantSettingsDto CreateDefaultSettings()
  {
    Dictionary<string, string> values = [];
    return TenantSettingDefinitions.CreateDto(values);
  }

  private async Task<bool> SetSetting<T>(string settingName, T newValue)
  {
    try
    {
      if (newValue is null)
      {
        var deleteResult = await _controlrApi.Internal.TenantSettings.DeleteTenantSetting(settingName);
        if (!deleteResult.IsSuccess)
        {
          _logger.LogError("Failed to delete setting.  Reason: {Reason}, StatusCode: {StatusCode}",
            deleteResult.Reason,
            deleteResult.StatusCode);

          _snackbar.Add(deleteResult.Reason, Severity.Error);
          return false;
        }

        _settings = null;
        _effectiveUserPreferences.InvalidateCache();
        return true;
      }
      
      var stringValue = TenantSettingDefinitions.FormatValue(settingName, newValue)?.Trim();
      Guard.IsNotNull(stringValue);
      var normalizationResult = TenantSettingDefinitions.Normalize(settingName, stringValue);
      if (!normalizationResult.IsSuccess)
      {
        _logger.LogWarning("Failed to normalize setting {SettingName}. Reason: {Reason}", settingName, normalizationResult.ErrorMessage);
        _snackbar.Add(normalizationResult.ErrorMessage ?? "Setting value is invalid.", Severity.Error);
        return false;
      }

      var request = new TenantSettingRequestDto(settingName, normalizationResult.Value ?? string.Empty);
      var setResult = await _controlrApi.Internal.TenantSettings.SetTenantSetting(request);

      if (!setResult.IsSuccess)
      {
        _logger.LogError("Failed to set setting.  Reason: {Reason}, StatusCode: {StatusCode}",
          setResult.Reason,
          setResult.StatusCode);
          
        _snackbar.Add(setResult.Reason, Severity.Error);
        return false;
      }

      _settings = null;
      _effectiveUserPreferences.InvalidateCache();
      return true;
    }
    catch (Exception ex)
    {
      _logger.LogError(ex, "Error while setting setting for {SettingName}.", settingName);
      _snackbar.Add("Error while setting setting", Severity.Error);
      return false;
    }
  }
}
