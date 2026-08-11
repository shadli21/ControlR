namespace ControlR.Web.Client.Components.Dialogs;

public sealed record CreateServiceAccountCredentialDialogResult(string Name, DateTimeOffset? ExpiresAt);

public partial class CreateServiceAccountCredentialDialog : ComponentBase
{
  private const int CustomValue = -1;
  private const int NeverValue = 0;

  private DateTime? _customDate;
  private TimeSpan? _customTime;
  private int _expirationDays = NeverValue;
  private string _name = string.Empty;

  [CascadingParameter]
  public required IMudDialogInstance MudDialog { get; init; }

  [Inject]
  public required TimeProvider TimeProvider { get; init; }

  private bool CanSave =>
    !string.IsNullOrWhiteSpace(_name) &&
    (_expirationDays != CustomValue || (_customDate is not null && _customTime is not null));
  private DateTime MinDate => TimeProvider.GetLocalNow().Date;

  private void Cancel() => MudDialog.Cancel();

  private DateTimeOffset GetCustomExpiration()
  {
    var date = _customDate ?? throw new InvalidOperationException("Custom expiration date is required.");
    var local = date.Date + (_customTime ?? TimeSpan.Zero);
    var offset = TimeProvider.LocalTimeZone.GetUtcOffset(local);
    return new DateTimeOffset(local, offset);
  }

  private void Save()
  {
    DateTimeOffset? expiresAt = _expirationDays switch
    {
      NeverValue => null,
      CustomValue => GetCustomExpiration(),
      _ => TimeProvider.GetUtcNow().AddDays(_expirationDays)
    };

    MudDialog.Close(DialogResult.Ok(new CreateServiceAccountCredentialDialogResult(_name.Trim(), expiresAt)));
  }
}
