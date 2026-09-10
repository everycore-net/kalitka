using System.Net;
using System.Text.RegularExpressions;
using Kalitka;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Kalitka.Tests;

/// <summary>The e-mail approval links: GET confirms without consuming, POST
/// consumes once and resolves the request.</summary>
public class ActionEndpointTests : IClassFixture<GateFactory>
{
    private readonly GateFactory _f;
    public ActionEndpointTests(GateFactory f) => _f = f;

    // HandleCookies=false: the approved /wait/status sets a Domain=.example.com
    // cookie the localhost CookieContainer would reject.
    private HttpClient Client() =>
        _f.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            HandleCookies = false
        });

    private string Mint(string requestId, string action) =>
        _f.Services.GetRequiredService<OneTimeTokenService>()
            .Mint("approve", "web:app.example.com", requestId, action, 15);

    private async Task<string> RaiseRequest(string clientIp)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, "/request")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["target"] = "app.example.com",
                ["input"] = "someone@example.com"
            })
        };
        req.Headers.Add("X-Test-Peer", "10.0.0.5");
        req.Headers.Add("X-Forwarded-For", clientIp);
        var html = await (await Client().SendAsync(req)).Content.ReadAsStringAsync();
        return Regex.Match(html, "var id=\"([0-9A-Fa-f]+)\"").Groups[1].Value;
    }

    private static FormUrlEncodedContent Form(string token) =>
        new(new Dictionary<string, string> { ["t"] = token });

    private async Task<string> Status(string id) =>
        await (await Client().GetAsync($"/wait/status?id={id}")).Content.ReadAsStringAsync();

    [Fact]
    public async Task Invalid_token_is_refused()
    {
        var res = await Client().GetAsync("/action?t=not-a-token");
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        Assert.Contains("Link invalid", await res.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Get_confirms_without_consuming()
    {
        var id = await RaiseRequest("203.0.113.60");
        var token = Mint(id, "a");

        var page = await (await Client().GetAsync($"/action?t={Uri.EscapeDataString(token)}")).Content.ReadAsStringAsync();
        Assert.Contains("Approve access", page);

        // GET consumed nothing: the request is still waiting, and the POST works.
        Assert.Contains("\"waiting\"", await Status(id));

        var post = await Client().PostAsync("/action", Form(token));
        Assert.Contains("Approved", await post.Content.ReadAsStringAsync());
        Assert.Contains("\"approved\"", await Status(id));
    }

    [Fact]
    public async Task A_link_works_only_once()
    {
        var id = await RaiseRequest("203.0.113.61");
        var token = Mint(id, "a");

        Assert.Contains("Approved", await (await Client().PostAsync("/action", Form(token))).Content.ReadAsStringAsync());
        Assert.Contains("Already used", await (await Client().PostAsync("/action", Form(token))).Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Deny_link_denies()
    {
        var id = await RaiseRequest("203.0.113.62");
        var token = Mint(id, "d");

        Assert.Contains("Denied", await (await Client().PostAsync("/action", Form(token))).Content.ReadAsStringAsync());
        Assert.Contains("\"denied\"", await Status(id));
    }
}
