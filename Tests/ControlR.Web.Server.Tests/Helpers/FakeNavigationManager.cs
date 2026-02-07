using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Routing;

namespace ControlR.Web.Server.Tests.Helpers;

internal sealed class FakeNavigationManager : NavigationManager
{
  public FakeNavigationManager()
  {
    Initialize("http://localhost/", "http://localhost/");
  }

  protected override void NavigateToCore(string uri, NavigationOptions options)
  {
    Uri = ToAbsoluteUri(uri).ToString();
  }
}
