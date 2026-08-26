using Azure.Core;
using Azure.Identity;
using ControlR.Web.Server.Data.Configuration;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Npgsql;

namespace ControlR.Web.Server.Startup;

public static class DatabaseRegistrationExtensions
{
  public static void AddControlrInMemoryDb(
    this IHostApplicationBuilder hostBuilder,
    AppOptions appOptions)
  {
    hostBuilder.Services.AddDbContextFactory<AppDb>((sp, options) =>
      {
        var dbName = string.IsNullOrWhiteSpace(appOptions.InMemoryDatabaseName)
          ? Guid.NewGuid().ToString("N")
          : appOptions.InMemoryDatabaseName;

        options.UseInMemoryDatabase(dbName);

        options.EnableDetailedErrors(appOptions.EnableDatabaseDetailedErrors);
        options.AddInterceptors(new ServiceAccountInvariantInterceptor());

        // Always attach the claims extension so every AppDb shares the same in-memory store
        // and service provider, while each request still gets its own claims-filtered model.
        // When no user is authenticated, the extension carries no claims, keeping the context
        // unfiltered like production server/service contexts.
        var accessor = sp.GetRequiredService<IHttpContextAccessor>();
        var claimsOptions = new ClaimsDbContextOptions();
        if (accessor.HttpContext?.User is { Identity.IsAuthenticated: true } user &&
            user.TryGetTenantId(out var tenantId) &&
            user.TryGetUserId(out var userId))
        {
          claimsOptions = new ClaimsDbContextOptions { TenantId = tenantId, UserId = userId };
        }

        if (options is not IDbContextOptionsBuilderInfrastructure builderInfrastructure)
        {
          throw new ArgumentException(
              $"Expected {nameof(options)} to be of type {nameof(IDbContextOptionsBuilderInfrastructure)}");
        }

        builderInfrastructure.AddOrUpdateExtension(new ClaimsDbContextOptionsExtension(claimsOptions));

      }, lifetime: ServiceLifetime.Transient);
  }

  public static void AddControlrPostgresDb(
    this IHostApplicationBuilder hostBuilder,
    AppOptions appOptions)
  {
    var pgUser = hostBuilder.Configuration.GetValue<string>("POSTGRES_USER");
    var pgPass = hostBuilder.Configuration.GetValue<string>("POSTGRES_PASSWORD");
    var pgHost = hostBuilder.Configuration.GetValue<string>("POSTGRES_HOST");
    var pgDb = hostBuilder.Configuration.GetValue<string>("POSTGRES_DB");
    var pgPortRaw = hostBuilder.Configuration.GetValue<string>("POSTGRES_PORT");
    var useEntraId = hostBuilder.Configuration.GetValue<bool>("POSTGRES_USE_ENTRA_ID");
    var pgPort = 5432;

    ArgumentException.ThrowIfNullOrWhiteSpace(pgUser);
    ArgumentException.ThrowIfNullOrWhiteSpace(pgHost);

    if (!useEntraId)
    {
      ArgumentException.ThrowIfNullOrWhiteSpace(pgPass);
    }

    if (string.IsNullOrWhiteSpace(pgDb))
    {
      pgDb = "controlr";
    }

    if (int.TryParse(pgPortRaw, out var parsedPort))
    {
      pgPort = parsedPort;
    }

    if (Uri.TryCreate(pgHost, UriKind.Absolute, out var pgHostUri))
    {
      pgHost = pgHostUri.Host;
      if (pgHostUri.Port > 0)
      {
        pgPort = pgHostUri.Port;
      }
    }

    var pgBuilder = new NpgsqlConnectionStringBuilder
    {
      Database = pgDb,
      Username = pgUser,
      Host = pgHost,
      Port = pgPort
    };

    if (useEntraId)
    {
      AddPostgresWithEntraId(hostBuilder, pgBuilder, appOptions);
    }
    else
    {
      AddPostgresWithPassword(hostBuilder, pgBuilder, pgPass, appOptions);
    }
  }

  private static void AddPostgresWithEntraId(
    IHostApplicationBuilder hostBuilder,
    NpgsqlConnectionStringBuilder pgBuilder,
    AppOptions appOptions)
  {
    pgBuilder.SslMode = SslMode.Require;

    var credential = new DefaultAzureCredential();

    var dataSourceBuilder = new NpgsqlDataSourceBuilder(pgBuilder.ConnectionString);
    dataSourceBuilder.UsePeriodicPasswordProvider(
      passwordProvider: async (_, cancellationToken) =>
      {
        var tokenContext = new TokenRequestContext(["https://ossrdbms-aad.database.windows.net/.default"]);
        var accessToken = await credential.GetTokenAsync(tokenContext, cancellationToken);
        return accessToken.Token;
      },
      successRefreshInterval: TimeSpan.FromMinutes(55),
      failureRefreshInterval: TimeSpan.FromSeconds(10));

    var dataSource = dataSourceBuilder.Build();

    hostBuilder.Services.AddDbContextFactory<AppDb>(
      (sp, options) =>
      {
        options.UseNpgsql(dataSource);
        ConfigureDbContextOptions(sp, options, appOptions);
      },
      lifetime: ServiceLifetime.Transient);
  }

  private static void AddPostgresWithPassword(
    IHostApplicationBuilder hostBuilder,
    NpgsqlConnectionStringBuilder pgBuilder,
    string? pgPass,
    AppOptions appOptions)
  {
    pgBuilder.Password = pgPass;

    hostBuilder.Services.AddDbContextFactory<AppDb>(
      (sp, options) =>
      {
        options.UseNpgsql(pgBuilder.ConnectionString);
        ConfigureDbContextOptions(sp, options, appOptions);
      }, 
      lifetime: ServiceLifetime.Transient);
  }

  private static void ConfigureDbContextOptions(
    IServiceProvider sp,
    DbContextOptionsBuilder options,
    AppOptions appOptions)
  {
    options.EnableDetailedErrors(appOptions.EnableDatabaseDetailedErrors);
    options.AddInterceptors(new ServiceAccountInvariantInterceptor());

    var accessor = sp.GetRequiredService<IHttpContextAccessor>();
    if (accessor.HttpContext?.User is { Identity.IsAuthenticated: true } user)
    {
      options.UseUserClaims(user);
    }
  }
}