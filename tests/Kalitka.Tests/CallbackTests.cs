using System.Net;
using System.Net.Http.Json;
using System.Text.RegularExpressions;
using Xunit;

namespace Kalitka.Tests;

public class CallbackTests : IClassFixture<GateFactory>
{
    private readonly GateFactory _f;
    public CallbackTests(GateFactory f) => _f = f;

    private const string Path = "/tg/secret-path";

    private HttpClient Redirectless() =>
        _f.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

    /// <summary>Raises a pending request from a fresh client IP and returns its id.</summary>
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
        req.Headers.Add("X-Test-Peer", "10.0.0.5");        // trusted proxy
        req.Headers.Add("X-Forwarded-For", clientIp);      // the real caller
        var res = await Redirectless().SendAsync(req);
        var html = await res.Content.ReadAsStringAsync();

        var m = Regex.Match(html, "var id=\"([0-9A-Fa-f]+)\"");
        Assert.True(m.Success, "waiting page should carry the request id");
        return m.Groups[1].Value;
    }

    private Task<HttpResponseMessage> Approve(string id, long adminId = 111)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, Path)
        {
            Content = JsonContent.Create(new
            {
                callback_query = new
                {
                    id = "cb-" + Guid.NewGuid().ToString("N")[..6],
                    from = new { id = adminId },
                    data = "ok|" + id,
                    message = new { chat = new { id = 1 }, message_id = 1 }
                }
            })
        };
        req.Headers.Add("X-Telegram-Bot-Api-Secret-Token", "webhook-secret");
        return Redirectless().SendAsync(req);
    }

    [Fact]
    public async Task Approving_twice_only_counts_once()
    {
        var id = await RaiseRequest("203.0.113.20");

        await Approve(id);
        _f.Telegram.Callbacks.Clear();

        await Approve(id);   // the stale button, pressed again

        Assert.Contains(_f.Telegram.Callbacks, c => c.Text == "already handled");
    }

    [Fact]
    public async Task Approving_an_expired_request_does_nothing()
    {
        var id = await RaiseRequest("203.0.113.21");

        // Let the pending request age past its lifetime (default 5 minutes).
        _f.Clock.Advance(TimeSpan.FromMinutes(6));

        await Approve(id);

        Assert.Contains(_f.Telegram.Callbacks, c => c.Text == "expired");
    }

    [Fact]
    public async Task Status_of_an_unknown_request_is_gone()
    {
        var res = await Redirectless().GetAsync("/wait/status?id=deadbeefdeadbeef");
        var body = await res.Content.ReadAsStringAsync();
        Assert.Contains("\"gone\"", body);
    }
}
