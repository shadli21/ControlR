using ControlR.Tests.TestingUtilities;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;
using System.Runtime.CompilerServices;
using Xunit.Abstractions;

namespace ControlR.Web.Server.Tests.Helpers;

/// <summary>
/// Creates a TestServer for full end-to-end integration/functional tests.
/// Use <see cref="TestAppBuilder"/> for service-only tests.
/// </summary>
internal static class TestWebServerBuilder
{
  public static async Task<TestWebServer> CreateTestServer(
    ITestOutputHelper testOutput,
    [CallerMemberName] string testDatabaseName = "")
  {
    var timeProvider = new FakeTimeProvider(DateTimeOffset.Now);
    var uniqueDatabaseName = $"{testDatabaseName}-{Guid.NewGuid()}";

    var connectionInfo = await PostgresTestContainer.GetConnectionInfo();
    var databaseName = await PostgresTestContainer.CreateDatabase($"{uniqueDatabaseName}-server");

    // Get the TestServer for integration/functional tests
    var factory = new WebApplicationFactory<Program>()
      .WithWebHostBuilder(builder =>
      {
        builder.UseEnvironment("Testing");
        builder.UseSetting("AppOptions:UseInMemoryDatabase", "false");
        builder.UseSetting("POSTGRES_USER", connectionInfo.Username);
        builder.UseSetting("POSTGRES_PASSWORD", connectionInfo.Password);
        builder.UseSetting("POSTGRES_HOST", connectionInfo.Host);
        builder.UseSetting("POSTGRES_PORT", $"{connectionInfo.Port}");
        builder.UseSetting("POSTGRES_DB", databaseName);

        builder.ConfigureServices(services =>
        {
          // Replace TimeProvider with FakeTimeProvider in the test server
          _ = services.ReplaceSingleton<TimeProvider, FakeTimeProvider>(timeProvider);
        });

        builder.ConfigureLogging(logging =>
        {
          logging.ClearProviders();
          logging.AddProvider(new XunitLoggerProvider(testOutput));
        });
      });

    return new TestWebServer(timeProvider, factory);
  }
}