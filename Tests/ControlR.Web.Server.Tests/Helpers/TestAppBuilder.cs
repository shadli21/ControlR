using System.Runtime.CompilerServices;
using ControlR.Tests.TestingUtilities;
using ControlR.Web.Server.Startup;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;
using Microsoft.AspNetCore.Components;
using Xunit.Abstractions;

namespace ControlR.Web.Server.Tests.Helpers;

/// <summary>
/// Creates <see cref="TestApp"/> for service-only integration/functional tests.
/// Use <see cref="TestWebServerBuilder"/> for full end-to-end tests involving HTTP requests.
/// </summary>
internal static class TestAppBuilder
{
  public static async Task<TestApp> CreateTestApp(
    ITestOutputHelper testOutput,
    Dictionary<string, string?>? extraConfiguration = null,
    [CallerMemberName] string testDatabaseName = "")
  {
    var timeProvider = new FakeTimeProvider(DateTimeOffset.Now);

    var connectionInfo = await PostgresTestContainer.GetConnectionInfo();
    var databaseName = await PostgresTestContainer.CreateDatabase($"{testDatabaseName}-{Guid.NewGuid():N}");

    var builder = WebApplication.CreateBuilder();
    builder.Environment.EnvironmentName = "Testing";
    _ = builder.Configuration.AddInMemoryCollection(
    [
      new KeyValuePair<string, string?>("AppOptions:UseInMemoryDatabase", "false"),
      new KeyValuePair<string, string?>("POSTGRES_USER", connectionInfo.Username),
      new KeyValuePair<string, string?>("POSTGRES_PASSWORD", connectionInfo.Password),
      new KeyValuePair<string, string?>("POSTGRES_HOST", connectionInfo.Host),
      new KeyValuePair<string, string?>("POSTGRES_PORT", $"{connectionInfo.Port}"),
      new KeyValuePair<string, string?>("POSTGRES_DB", databaseName)
    ]);

    if (extraConfiguration is not null)
    {
      builder.Configuration.AddInMemoryCollection(extraConfiguration);
    }

    _ = await builder.AddControlrServer(false);

    _ = builder.Services.ReplaceImplementation<NavigationManager, FakeNavigationManager>(ServiceLifetime.Scoped);

    _ = builder.Services.ReplaceSingleton<TimeProvider, FakeTimeProvider>(timeProvider);
    _ = builder.Logging.ClearProviders();
    _ = builder.Logging.AddProvider(new XunitLoggerProvider(testOutput));

    // Build the app
    var app = builder.Build();
    await app.ApplyMigrations();

    return new TestApp(timeProvider, app);
  }
}