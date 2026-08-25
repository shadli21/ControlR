namespace ControlR.Web.Client.Components.Dialogs;

public partial class PermissionAssignmentPanelDialog : ComponentBase
{
  public static DialogOptions DefaultOptions => new()
  {
    CloseButton = true,
    FullWidth = true,
    MaxWidth = MaxWidth.Large,
    BackdropClick = false
  };

  [Parameter]
  public ServiceAccountKind AccountKind { get; set; } = ServiceAccountKind.Tenant;

  [CascadingParameter]
  public required IMudDialogInstance MudDialog { get; init; }

  [Parameter]
  public required Guid PrincipalId { get; set; }

  [Parameter]
  public required PermissionPrincipalKind PrincipalKind { get; set; }

  private void Close() => MudDialog.Close();
}
