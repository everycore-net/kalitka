using System.Net;
using System.Net.Http.Json;
using System.Text.RegularExpressions;
using Xunit;

namespace Kalitka.Tests;

public class WebhookTests : IClassFixture<GateFactory>
{
    private readonly GateFactory _f;
    public WebhookTests(GateFactory f) => _f = f;

    private const string Path = "/tg/secret-path";
    private const long Admin = 111;      // in AdminIds via config? set below
    private HttpClient Client() => _f.CreateClient();

    // Note: AdminIds is configured through the factory below via UseSetting.

    [Fact]
    public async Task Webhook_with_wrong_secret_is_403()
    {
        var req = new HttpRequestMessage(HttpMethod.Post, Path)
        {
            Content = JsonContent.Create(new { message = new { } })
        };
        req.Headers.Add("X-Telegram-Bot-Api-Secret-Token", "wrong");
        var res = await Client().SendAsync(req);
        Assert.Equal(HttpStatusCode.Forbidden, res.StatusCode);
    }

    [Fact]
    public async Task Webhook_with_right_secret_is_accepted()
    {
        var req = new HttpRequestMessage(HttpMethod.Post, Path)
        {
            Content = JsonContent.Create(new
            {
                message = new { from = new { id = 999 }, chat = new { id = 999 }, text = "/hosts" }
            })
        };
        req.Headers.Add("X-Telegram-Bot-Api-Secret-Token", "webhook-secret");
        var res = await Client().SendAsync(req);
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
    }

    [Fact]
    public async Task Non_admin_callback_is_refused()
    {
        var req = new HttpRequestMessage(HttpMethod.Post, Path)
        {
            Content = JsonContent.Create(new
            {
                callback_query = new
                {
                    id = "cb1",
                    from = new { id = 424242 },     // not an admin
                    data = "ok|deadbeef",
                    message = new { chat = new { id = 1 }, message_id = 1 }
                }
            })
        };
        req.Headers.Add("X-Telegram-Bot-Api-Secret-Token", "webhook-secret");
        await Client().SendAsync(req);

        Assert.Contains(_f.Telegram.Callbacks, c => c.Text == "Not permitted");
    }
}
