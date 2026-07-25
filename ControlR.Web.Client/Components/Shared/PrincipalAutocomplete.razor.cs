using ControlR.Libraries.Api.Contracts.Enums;

namespace ControlR.Web.Client.Components.Shared;

public sealed record PrincipalOption(Guid Id, string DisplayName, PermissionPrincipalKind Kind);

public partial class PrincipalAutocomplete
{
  private PrincipalOption? _selected;

  [Inject]
  public required IControlrApi ControlrApi { get; init; }

  [Parameter]
  public string Label { get; set; } = "Principal";

  [Parameter]
  public PermissionPrincipalKind PrincipalKind { get; set; } = PermissionPrincipalKind.User;

  [Parameter]
  public Guid? SelectedId { get; set; }

  [Parameter]
  public EventCallback<Guid?> SelectedIdChanged { get; set; }

  private async Task HandleValueChanged(PrincipalOption? value)
  {
    _selected = value;
    SelectedId = value?.Id;
    await SelectedIdChanged.InvokeAsync(SelectedId);
  }

  private async Task<IEnumerable<PrincipalOption>> Search(string query, CancellationToken cancellationToken)
  {
    if (string.IsNullOrWhiteSpace(query) || query.Length < 2)
    {
      return [];
    }

    return PrincipalKind switch
    {
      PermissionPrincipalKind.User => await SearchUsers(query, cancellationToken),
      PermissionPrincipalKind.UserGroup => await SearchUserGroups(query, cancellationToken),
      PermissionPrincipalKind.ServiceAccount => await SearchServiceAccounts(query, cancellationToken),
      _ => []
    };
  }

  private async Task<IEnumerable<PrincipalOption>> SearchServiceAccounts(string query, CancellationToken cancellationToken)
  {
    var result = await ControlrApi.Internal.ServiceAccounts.GetAll(cancellationToken);
    if (!result.IsSuccess)
    {
      return [];
    }

    return result.Value
      .Where(x => x.Name.Contains(query, StringComparison.OrdinalIgnoreCase))
      .Select(x => new PrincipalOption(x.Id, x.Name, PermissionPrincipalKind.ServiceAccount));
  }

  private async Task<IEnumerable<PrincipalOption>> SearchUserGroups(string query, CancellationToken cancellationToken)
  {
    var result = await ControlrApi.Internal.UserGroups.GetAll(cancellationToken);
    if (!result.IsSuccess)
    {
      return [];
    }

    return result.Value
      .Where(x => x.Name.Contains(query, StringComparison.OrdinalIgnoreCase))
      .Select(x => new PrincipalOption(x.Id, x.Name, PermissionPrincipalKind.UserGroup));
  }

  private async Task<IEnumerable<PrincipalOption>> SearchUsers(string query, CancellationToken cancellationToken)
  {
    var result = await ControlrApi.Internal.Users.GetAllUsers(cancellationToken);
    if (!result.IsSuccess)
    {
      return [];
    }

    return result.Value
      .Where(x => (x.UserName?.Contains(query, StringComparison.OrdinalIgnoreCase) ?? false) ||
                  (x.Email?.Contains(query, StringComparison.OrdinalIgnoreCase) ?? false))
      .Select(x => new PrincipalOption(x.Id, x.UserName ?? x.Email ?? x.Id.ToString(), PermissionPrincipalKind.User));
  }
}
