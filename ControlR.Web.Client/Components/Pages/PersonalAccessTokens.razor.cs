using ControlR.Web.Client.Components.Shared;
using Microsoft.AspNetCore.Components.Web;

namespace ControlR.Web.Client.Components.Pages;

public partial class PersonalAccessTokens
{
  private readonly List<CredentialScopeDto> _initialScopes = [];
  private bool _isLoading = false;
  private string _newTokenName = string.Empty;
  private PersonalAccessTokenPermissionMode _newTokenMode = PersonalAccessTokenPermissionMode.Restricted;
  private PersonalAccessTokenResponseDto[] _personalAccessTokens = [];

  [Inject]
  public required IControlrApi ControlrApi { get; init; }

  [Inject]
  public required IDialogService DialogService { get; init; }

  [Inject]
  public required ISnackbar Snackbar { get; init; }

  private bool CanCreatePersonalAccessToken =>
    !string.IsNullOrWhiteSpace(_newTokenName) &&
    !_isLoading &&
    (_newTokenMode == PersonalAccessTokenPermissionMode.InheritOwner || _initialScopes.Count > 0);

  protected override async Task OnInitializedAsync()
  {
    await LoadPersonalAccessTokens();
  }

  private async Task AddInitialScope()
  {
    var dialogRef = await DialogService.ShowAsync<CredentialScopeEditDialog>(
      "Add Scope", CredentialScopeEditDialog.DefaultOptions);
    var result = await dialogRef.Result;

    if (result is null || result.Canceled || result.Data is not CredentialScopeEditDialogResult dialogResult)
    {
      return;
    }

    var duplicate = _initialScopes.Any(x =>
      x.PermissionName == dialogResult.Scope.PermissionName &&
      x.ScopeKind == dialogResult.Scope.ScopeKind &&
      x.ScopeId == dialogResult.Scope.ScopeId);

    if (duplicate)
    {
      Snackbar.Add("That scope is already on the list", Severity.Warning);
      return;
    }

    _initialScopes.Add(dialogResult.Scope);
  }

  private void RemoveInitialScope(CredentialScopeDto scope)
  {
    _initialScopes.Remove(scope);
  }

  private static string ScopeCellText(CredentialScopeDto scope)
  {
    return scope.ScopeId is { } scopeId
      ? $"{scope.ScopeKind}: {scopeId.ToString()[..8]}..."
      : scope.ScopeKind.ToString();
  }

  private async Task CreatePersonalAccessToken()
  {
    if (!CanCreatePersonalAccessToken)
      return;

    _isLoading = true;
    try
    {
      var scopes = _newTokenMode == PersonalAccessTokenPermissionMode.Restricted
        ? _initialScopes.AsReadOnly()
        : null;
      var request = new CreatePersonalAccessTokenRequestDto(
        _newTokenName.Trim(),
        _newTokenMode,
        scopes is null ? null : [.. scopes]);
      var result = await ControlrApi.Internal.PersonalAccessTokens.CreatePersonalAccessToken(request);

      if (result.IsSuccess)
      {
        var createdToken = result.Value.PersonalAccessToken;

        var parameters = new DialogParameters<SecretDisplayDialog>
        {
          { x => x.Title, "Personal Access Token Created" },
          { x => x.Secret, result.Value.PlainTextToken },
          { x => x.SecretLabel, "Personal Access Token" },
          { x => x.Subtitle, createdToken.Name },
          { x => x.SubtitleLabel, "Token Name" }
        };

        var dialogOptions = SecretDisplayDialog.DefaultOptions;

        var dialogRef = await DialogService.ShowAsync<SecretDisplayDialog>("Personal Access Token Created", parameters, dialogOptions);
        await dialogRef.Result;

        await LoadPersonalAccessTokens();
        _newTokenName = string.Empty;
        _initialScopes.Clear();
        Snackbar.Add("Personal access token created successfully", Severity.Success);

        await ManagePermissions(createdToken);
      }
      else
      {
        Snackbar.Add($"Failed to create personal access token: {result.Reason}", Severity.Error);
      }
    }
    catch (Exception ex)
    {
      Snackbar.Add($"Error creating personal access token: {ex.Message}", Severity.Error);
    }
    finally
    {
      _isLoading = false;
    }
  }

  private async Task DeletePersonalAccessToken(PersonalAccessTokenResponseDto personalAccessToken)
  {
    var confirmed = await DialogService.ShowMessageBoxAsync(
      "Confirm Delete",
      $"Are you sure you want to delete the personal access token '{personalAccessToken.Name}'?",
      yesText: "Delete",
      cancelText: "Cancel");

    if (confirmed == true)
    {
      try
      {
        var result = await ControlrApi.Internal.PersonalAccessTokens.DeletePersonalAccessToken(personalAccessToken.Id);
        if (result.IsSuccess)
        {
          await LoadPersonalAccessTokens();
          Snackbar.Add("Personal access token deleted successfully", Severity.Success);
        }
        else
        {
          Snackbar.Add($"Failed to delete personal access token: {result.Reason}", Severity.Error);
        }
      }
      catch (Exception ex)
      {
        Snackbar.Add($"Error deleting personal access token: {ex.Message}", Severity.Error);
      }
    }
  }

  private async Task LoadPersonalAccessTokens()
  {
    _isLoading = true;
    try
    {
      var result = await ControlrApi.Internal.PersonalAccessTokens.GetPersonalAccessTokens();
      if (result.IsSuccess)
      {
        _personalAccessTokens = result.Value;
      }
      else
      {
        Snackbar.Add($"Failed to load personal access tokens: {result.Reason}", Severity.Error);
      }
    }
    catch (Exception ex)
    {
      Snackbar.Add($"Error loading personal access tokens: {ex.Message}", Severity.Error);
    }
    finally
    {
      _isLoading = false;
    }
  }

  private async Task ManagePermissions(PersonalAccessTokenResponseDto personalAccessToken)
  {
    var parameters = new DialogParameters<PermissionAssignmentPanelDialog>
    {
      { x => x.PrincipalKind, PermissionPrincipalKind.PersonalAccessToken },
      { x => x.PrincipalId, personalAccessToken.Id }
    };

    var dialogRef = await DialogService.ShowAsync<PermissionAssignmentPanelDialog>(
      $"Permissions: {personalAccessToken.Name}",
      parameters,
      PermissionAssignmentPanelDialog.DefaultOptions);
    await dialogRef.Result;

    await LoadPersonalAccessTokens();
  }

  private async Task OnKeyDown(KeyboardEventArgs e)
  {
    if (e.Key == "Enter" && !string.IsNullOrWhiteSpace(_newTokenName))
    {
      await CreatePersonalAccessToken();
    }
  }

  private async Task Refresh()
  {
    await LoadPersonalAccessTokens();
    Snackbar.Add("Personal access tokens refreshed", Severity.Success);
  }

  private async Task RenamePersonalAccessToken(PersonalAccessTokenResponseDto personalAccessToken)
  {
    var parameters = new DialogParameters
    {
      { "CurrentName", personalAccessToken.Name }
    };
    var dialogOptions = new DialogOptions
    {
      CloseButton = true,
      FullWidth = true,
      MaxWidth = MaxWidth.ExtraSmall
    };
    var newTokenName = await DialogService.ShowPrompt(
      title: "Rename Personal Access Token", 
      subtitle: $"Rename the '{personalAccessToken.Name}' token by providing a new name.",
      inputLabel: "New Name",
      inputHintText: "Enter a new name for the personal access token.");

    if (string.IsNullOrWhiteSpace(newTokenName))
    {
      return;
    }

    try
    {
      var updateRequest = new UpdatePersonalAccessTokenRequestDto(newTokenName.Trim());
      var updateResult = await ControlrApi.Internal.PersonalAccessTokens.UpdatePersonalAccessToken(personalAccessToken.Id, updateRequest);
      if (updateResult.IsSuccess)
      {
        await LoadPersonalAccessTokens();
        Snackbar.Add("Personal access token renamed successfully", Severity.Success);
      }
      else
      {
        Snackbar.Add($"Failed to rename personal access token: {updateResult.Reason}", Severity.Error);
      }
    }
    catch (Exception ex)
    {
      Snackbar.Add($"Error renaming personal access token: {ex.Message}", Severity.Error);
    }
  }
}
