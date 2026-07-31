using ControlR.Web.Client.Components.Shared;
using ControlR.Web.Client.Services;
using InternalDtos = ControlR.Libraries.Api.Contracts.Dtos.ServerApi.Internal;

namespace ControlR.Web.Client.Components.Pages;

public partial class ServerServiceAccounts : ComponentBase
{
  private IEnumerable<InternalDtos.ServerServiceAccountDto> _accounts = [];
  private bool _loading;
  private string _searchString = string.Empty;

  [Inject]
  public required IClipboardManager ClipboardManager { get; init; }

  [Inject]
  public required IControlrApi ControlrApi { get; init; }

  [Inject]
  public required IDialogService DialogService { get; init; }

  [Inject]
  public required ISnackbar Snackbar { get; init; }

  private Func<InternalDtos.ServerServiceAccountDto, bool> _quickFilter => account =>
  {
    if (string.IsNullOrWhiteSpace(_searchString))
    {
      return true;
    }

    return account.Name.Contains(_searchString, StringComparison.OrdinalIgnoreCase) ||
           (account.Description?.Contains(_searchString, StringComparison.OrdinalIgnoreCase) ?? false);
  };

  protected override async Task OnInitializedAsync()
  {
    await Refresh();
  }

  private async Task AddCredential(InternalDtos.ServerServiceAccountDto account)
  {
    var name = await DialogService.ShowPrompt(
      "Add Credential",
      $"Enter a name for the new credential on \"{account.Name}\".",
      "Credential name");

    if (string.IsNullOrWhiteSpace(name))
    {
      return;
    }

    var result = await ControlrApi.Internal.ServerServiceAccounts.AddCredential(
      account.Id, new InternalDtos.CreateServerServiceAccountCredentialRequestDto(name));

    if (!result.IsSuccess)
    {
      Snackbar.Add(result.Reason, Severity.Error);
      return;
    }

    await ShowSecretDialog("Credential Created", result.Value.PlainTextSecretKey, result.Value.Credential.Name);
    await Refresh();
  }

  private async Task CopyId(Guid id)
  {
    await ClipboardManager.SetText(id.ToString());
    Snackbar.Add("Copied to clipboard", Severity.Success);
  }

  private async Task CreateAccount()
  {
    var name = await DialogService.ShowPrompt(
      "Create Server Service Account",
      "Enter a name for the new server service account.",
      "Account name");

    if (string.IsNullOrWhiteSpace(name))
    {
      return;
    }

    var result = await ControlrApi.Internal.ServerServiceAccounts.Create(
      new InternalDtos.CreateServerServiceAccountRequestDto(name, null));

    if (!result.IsSuccess)
    {
      Snackbar.Add(result.Reason, Severity.Error);
      return;
    }

    await ShowSecretDialog("Server Service Account Created", result.Value.PlainTextSecretKey, result.Value.ServiceAccount.Name);
    await Refresh();
  }

  private async Task DeleteAccount(InternalDtos.ServerServiceAccountDto account)
  {
    var confirmed = await DialogService.ShowMessageBoxAsync(
      "Delete Server Service Account",
      $"Are you sure you want to delete \"{account.Name}\"? All credentials will be revoked.",
      "Delete", "Cancel");

    if (!confirmed.GetValueOrDefault())
    {
      return;
    }

    var result = await ControlrApi.Internal.ServerServiceAccounts.Delete(account.Id);
    if (!result.IsSuccess)
    {
      Snackbar.Add(result.Reason, Severity.Error);
      return;
    }

    Snackbar.Add("Server service account deleted", Severity.Success);
    await Refresh();
  }

  private async Task Refresh()
  {
    _loading = true;
    StateHasChanged();

    try
    {
      var result = await ControlrApi.Internal.ServerServiceAccounts.GetAll();
      if (result.IsSuccess)
      {
        _accounts = result.Value;
      }
      else
      {
        Snackbar.Add(result.Reason, Severity.Error);
      }
    }
    finally
    {
      _loading = false;
      StateHasChanged();
    }
  }

  private async Task ShowSecretDialog(string title, string secret, string subtitle)
  {
    var parameters = new DialogParameters<SecretDisplayDialog>
    {
      { x => x.Title, title },
      { x => x.Secret, secret },
      { x => x.SecretLabel, "Secret Key" },
      { x => x.Subtitle, subtitle },
      { x => x.SubtitleLabel, "Name" }
    };

    var options = SecretDisplayDialog.DefaultOptions;

    await DialogService.ShowAsync<SecretDisplayDialog>(title, parameters, options);
  }

  private string TruncateId(Guid id)
  {
    return $"{id.ToString()[..8]}...";
  }
}
