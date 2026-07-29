namespace ControlR.Web.Client.Components.Shared;

public sealed record PrincipalOption(Guid Id, string DisplayName, PermissionPrincipalKind Kind);

public partial class PrincipalAutocomplete
{
  private PrincipalOption? _selected;

  [Parameter]
  public string? Class { get; set; }

  [Inject]
  public required IControlrApi ControlrApi { get; init; }

  [Parameter]
  public bool Disabled { get; set; }

  [Parameter]
  public string Label { get; set; } = "Principal";

  [Parameter]
  public PermissionPrincipalKind PrincipalKind { get; set; } = PermissionPrincipalKind.User;

  [Parameter]
  public Guid? SelectedId { get; set; }

  [Parameter]
  public EventCallback<Guid?> SelectedIdChanged { get; set; }

  protected override async Task OnParametersSetAsync()
  {
    if (SelectedId is { } id && _selected?.Id != id)
    {
      _selected = await ResolveSelectedAsync(id);
    }
    else if (SelectedId is null)
    {
      _selected = null;
    }

    await base.OnParametersSetAsync();
  }

  private async Task HandleValueChanged(PrincipalOption? value)
  {
    _selected = value;
    SelectedId = value?.Id;
    await SelectedIdChanged.InvokeAsync(SelectedId);
  }

  private async Task<PrincipalOption?> ResolveSelectedAsync(Guid id)
  {
    return PrincipalKind switch
    {
      PermissionPrincipalKind.User => await ResolveUser(id),
      PermissionPrincipalKind.UserGroup => await ResolveUserGroup(id),
      PermissionPrincipalKind.ServiceAccount => await ResolveServiceAccount(id),
      PermissionPrincipalKind.PersonalAccessToken => await ResolvePersonalAccessToken(id),
      _ => null
    };
  }

  private async Task<PrincipalOption?> ResolvePersonalAccessToken(Guid id)
  {
    var result = await ControlrApi.Internal.PersonalAccessTokens.GetPersonalAccessTokens();
    if (!result.IsSuccess)
    {
      return null;
    }

    var match = result.Value.FirstOrDefault(x => x.Id == id);
    return match is null ? null : new PrincipalOption(match.Id, $"[PAT] {match.Name}", PermissionPrincipalKind.PersonalAccessToken);
  }

  private async Task<PrincipalOption?> ResolveServiceAccount(Guid id)
  {
    var result = await ControlrApi.Internal.ServiceAccounts.GetAll();
    if (!result.IsSuccess)
    {
      return null;
    }

    var match = result.Value.FirstOrDefault(x => x.Id == id);
    return match is null ? null : new PrincipalOption(match.Id, match.Name, PermissionPrincipalKind.ServiceAccount);
  }

  private async Task<PrincipalOption?> ResolveUserGroup(Guid id)
  {
    var result = await ControlrApi.Internal.UserGroups.GetAll();
    if (!result.IsSuccess)
    {
      return null;
    }

    var match = result.Value.FirstOrDefault(x => x.Id == id);
    return match is null ? null : new PrincipalOption(match.Id, match.Name, PermissionPrincipalKind.UserGroup);
  }

  private async Task<PrincipalOption?> ResolveUser(Guid id)
  {
    var result = await ControlrApi.Internal.Users.GetAllUsers();
    if (!result.IsSuccess)
    {
      return null;
    }

    var match = result.Value.FirstOrDefault(x => x.Id == id);
    return match is null ? null : new PrincipalOption(match.Id, match.UserName ?? match.Email ?? match.Id.ToString(), PermissionPrincipalKind.User);
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
      PermissionPrincipalKind.PersonalAccessToken => await SearchPersonalAccessTokens(query, cancellationToken),
      _ => []
    };
  }

  private async Task<IEnumerable<PrincipalOption>> SearchPersonalAccessTokens(string query, CancellationToken cancellationToken)
  {
    var result = await ControlrApi.Internal.PersonalAccessTokens.GetPersonalAccessTokens(cancellationToken);
    if (!result.IsSuccess)
    {
      return [];
    }

    return result.Value
      .Where(x => x.Name.Contains(query, StringComparison.OrdinalIgnoreCase))
      .Select(x => new PrincipalOption(x.Id, $"[PAT] {x.Name}", PermissionPrincipalKind.PersonalAccessToken));
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
