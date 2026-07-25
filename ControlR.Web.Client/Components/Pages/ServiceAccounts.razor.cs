using ControlR.Web.Client.Components.Shared;
using ControlR.Web.Client.Services;
using InternalDtos = ControlR.Libraries.Api.Contracts.Dtos.ServerApi.Internal;

namespace ControlR.Web.Client.Components.Pages;

public partial class ServiceAccounts : ComponentBase
{
  private IEnumerable<InternalDtos.TenantServiceAccountDto> _accounts = [];
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

  private Func<InternalDtos.TenantServiceAccountDto, bool> _quickFilter => account =>
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

  private async Task AddCredential(InternalDtos.TenantServiceAccountDto account)
  {
    var name = await DialogService.ShowPrompt(
      "Add Credential",
      $"Enter a name for the new credential on \"{account.Name}\".",
      "Credential name");

    if (string.IsNullOrWhiteSpace(name))
    {
      return;
    }

    var result = await ControlrApi.Internal.ServiceAccounts.AddCredential(
      account.Id, new InternalDtos.CreateTenantServiceAccountCredentialRequestDto(name));

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
      "Create Service Account",
      "Enter a name for the new service account.",
      "Account name");

    if (string.IsNullOrWhiteSpace(name))
    {
      return;
    }

    var result = await ControlrApi.Internal.ServiceAccounts.Create(
      new InternalDtos.CreateTenantServiceAccountRequestDto(name, null));

    if (!result.IsSuccess)
    {
      Snackbar.Add(result.Reason, Severity.Error);
      return;
    }

    await ShowSecretDialog("Service Account Created", result.Value.PlainTextSecretKey, result.Value.ServiceAccount.Name);
    await Refresh();
  }

  private async Task DeleteAccount(InternalDtos.TenantServiceAccountDto account)
  {
    var confirmed = await DialogService.ShowMessageBoxAsync(
      "Delete Service Account",
      $"Are you sure you want to delete \"{account.Name}\"? All credentials will be revoked.",
      "Delete", "Cancel");

    if (!confirmed.GetValueOrDefault())
    {
      return;
    }

    var result = await ControlrApi.Internal.ServiceAccounts.Delete(account.Id);
    if (!result.IsSuccess)
    {
      Snackbar.Add(result.Reason, Severity.Error);
      return;
    }

    Snackbar.Add("Service account deleted", Severity.Success);
    await Refresh();
  }

  private async Task Refresh()
  {
    _loading = true;
    StateHasChanged();

    try
    {
      var result = await ControlrApi.Internal.ServiceAccounts.GetAll();
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

    var options = new DialogOptions
    {
      BackdropClick = false,
      FullWidth = true,
      MaxWidth = MaxWidth.Small
    };

    await DialogService.ShowAsync<SecretDisplayDialog>(title, parameters, options);
  }
}
