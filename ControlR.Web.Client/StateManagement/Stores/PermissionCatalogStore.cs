namespace ControlR.Web.Client.StateManagement.Stores;

public interface IPermissionCatalogStore : IStoreBase<PermissionCatalogEntryDto>
{
}

public class PermissionCatalogStore(
  IControlrApi controlrApi,
  ISnackbar snackbar,
  ILogger<PermissionCatalogStore> logger) : StoreBase<PermissionCatalogEntryDto>(controlrApi, snackbar, logger), IPermissionCatalogStore
{
  protected override Guid GetItemId(PermissionCatalogEntryDto dto)
  {
    return StableId(dto.Name);
  }

  protected override IEnumerable<PermissionCatalogEntryDto> OrderItems(IEnumerable<PermissionCatalogEntryDto> items)
  {
    return items.OrderBy(x => x.DisplayName, StringComparer.OrdinalIgnoreCase);
  }

  protected override async Task RefreshImpl()
  {
    var result = await ControlrApi.Internal.PermissionAssignments.GetCatalog();
    if (!result.IsSuccess)
    {
      Snackbar.Add(result.Reason, Severity.Error);
      return;
    }

    SetItems(result.Value);
  }

  private static Guid StableId(string name)
  {
    var bytes = System.Text.Encoding.UTF8.GetBytes(name);
    var hash = System.Security.Cryptography.SHA256.HashData(bytes);
    return new Guid([.. hash[..16]]);
  }
}
