namespace ControlR.Web.Client.Components.Shared;

public partial class SecretDisplayDialog
{
  [Inject]
  public required IClipboardManager ClipboardManager { get; set; }

  [CascadingParameter]
  public required IMudDialogInstance MudDialog { get; init; }

  [Parameter]
  public required string Secret { get; set; }

  [Parameter]
  public string SecretLabel { get; set; } = "Secret Key";

  [Inject]
  public required ISnackbar Snackbar { get; set; }

  [Parameter]
  public string? Subtitle { get; set; }

  [Parameter]
  public string SubtitleLabel { get; set; } = "Name";

  [Parameter]
  public required string Title { get; set; }

  private void Close()
  {
    MudDialog.Close(DialogResult.Ok(true));
  }

  private async Task CopyToClipboard()
  {
    try
    {
      await ClipboardManager.SetText(Secret);
      Snackbar.Add("Copied to clipboard", Severity.Success);
    }
    catch (Exception ex)
    {
      Snackbar.Add($"Failed to copy to clipboard: {ex.Message}", Severity.Error);
    }
  }
}
