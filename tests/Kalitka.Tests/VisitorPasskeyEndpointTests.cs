using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace Kalitka.Tests;

/// <summary>The visitor passkey endpoints: login begins for a guarded host, and registration refuses
/// anyone who has not just been approved (no session for the host).</summary>
public class VisitorPasskeyEndpointTests : IClassFixture<GateFactory>
{
    private readonly GateFactory _f;
    public VisitorPasskeyEndpointTests(GateFactory f) => _f = f;

    private HttpClient Client() =>
        _f.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = false });

    [Fact]
    public async Task Login_begins_for_a_guarded_host()
    {
        // app.example.com is armed in the test factory.
        var res = await Client().PostAsync("/passkey/login/begin?target=app.example.com", null);
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        var body = await res.Content.ReadAsStringAsync();
        Assert.Contains("\"challenge\"", body);
        Assert.Contains("\"state\"", body);
    }

    [Fact]
    public async Task Login_begin_refuses_an_unguarded_host()
    {
        var res = await Client().PostAsync("/passkey/login/begin?target=not-guarded.example.com", null);
        Assert.Equal(HttpStatusCode.BadRequest, res.StatusCode);
    }

    [Fact]
    public async Task Registration_requires_a_just_approved_session()
    {
        // No visitor session cookie for the host → cannot remember a device (not an IdP).
        var res = await Client().PostAsync("/passkey/register/begin?target=app.example.com&label=x", null);
        Assert.Equal(HttpStatusCode.Forbidden, res.StatusCode);
    }
}
