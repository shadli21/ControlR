using System.Linq.Expressions;
using Microsoft.EntityFrameworkCore.Metadata;

namespace ControlR.Web.Server.Extensions.Database;

public static class AppDbExtensions
{
  public static async Task<TEntity> AddOrUpdate<TEntity>(
    this DbContext db,
    TEntity entity,
    Expression<Func<TEntity, bool>> match,
    CancellationToken cancellationToken)
    where TEntity : class
  {
    ArgumentNullException.ThrowIfNull(db);
    ArgumentNullException.ThrowIfNull(entity);
    ArgumentNullException.ThrowIfNull(match);

    var compiled = match.Compile();
    var set = db.Set<TEntity>();

    // IgnoreQueryFilters: this upsert must see rows owned by any principal.
    var existing = set.Local.FirstOrDefault(compiled)
      ?? await set.IgnoreQueryFilters().FirstOrDefaultAsync(match, cancellationToken);

    if (existing is null)
    {
      set.Add(entity);

      var saveResult = await db.SaveChangesOrConfirmConflictAsync(match, cancellationToken);

      if (saveResult == SaveChangesResult.Saved)
        return entity;

      // Lost the race; another thread inserted. Reload and update.
      db.Entry(entity).State = EntityState.Detached;
      existing = await set.IgnoreQueryFilters().FirstOrDefaultAsync(match, cancellationToken)
        ?? throw new InvalidOperationException("Expected conflicting entity after SaveChangesOrConfirmConflictAsync.");
    }

    var entry = db.Entry(existing);
    var pkProps = entry.Metadata.FindPrimaryKey()?.Properties ?? [];

    foreach (var prop in entry.Properties)
    {
      if (pkProps.Contains(prop.Metadata))
        continue;

      if (prop.Metadata.ValueGenerated != ValueGenerated.Never)
        continue;

      var propertyInfo = prop.Metadata.PropertyInfo
        ?? throw new InvalidOperationException($"Property {prop.Metadata.Name} has no CLR PropertyInfo.");

      prop.CurrentValue = propertyInfo.GetValue(entity);
    }

    await db.SaveChangesAsync(cancellationToken);

    return existing;
  }

  public static async Task ExecuteInTransaction(
    this DbContext db,
    Func<Task> operation,
    CancellationToken cancellationToken = default)
  {
    ArgumentNullException.ThrowIfNull(db);
    ArgumentNullException.ThrowIfNull(operation);

    if (!db.Database.IsRelational() || db.Database.CurrentTransaction is not null)
    {
      await operation();
      return;
    }

    await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
    await operation();
    await transaction.CommitAsync(cancellationToken);
  }

  /// <summary>
  /// Saves, or returns <see cref="SaveChangesResult.ConflictDetected"/> when a
  /// <see cref="DbUpdateException"/> is confirmed by <paramref name="conflictPredicate"/>.
  /// Other update exceptions are rethrown.
  /// </summary>
  public static async Task<SaveChangesResult> SaveChangesOrConfirmConflictAsync<TEntity>(
    this DbContext db,
    Expression<Func<TEntity, bool>> conflictPredicate,
    CancellationToken cancellationToken = default)
    where TEntity : class
  {
    try
    {
      await db.SaveChangesAsync(cancellationToken);
      return SaveChangesResult.Saved;
    }
    catch (DbUpdateException)
    {
      var isConflict = await db.Set<TEntity>()
        .IgnoreQueryFilters()
        .AsNoTracking()
        .AnyAsync(conflictPredicate, cancellationToken);

      if (!isConflict)
      {
        throw;
      }

      return SaveChangesResult.ConflictDetected;
    }
  }
}

public enum SaveChangesResult
{
  Saved,
  ConflictDetected
}
