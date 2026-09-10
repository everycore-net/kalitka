using System.Net;
using System.Text.Json;
using Kalitka;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// The same grant → session lifecycle as <see cref="GrantFlowTests"/>, but with
/// the app wired to a SQLite <c>StateDbPath</c>. It proves the DI factories select
/// the durable stores and that the state really lands on disk — a fresh store on
/// the same file, standing in for another instance or a restart, sees the closed
/// session. That is the single-node "durable + shared" claim, end to end.
/// </summary>
public sealed class DurableStoreIntegrationTests : IClassFixture<DurableStoreIntegrationTests.DurableFactory>
{
    private readonly DurableFactory _f;
    public DurableStoreIntegrationTests(DurableFactory f) => _f = f;

    public sealed class DurableFactory : GateFactory
    {
        public string StateDb { get; } =
            Path.Combine(Path.GetTempPath(), "kalitka-durable-" + Guid.NewGuid().ToString("N"), "state.db");

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);
            Directory.CreateDirectory(Path.GetDirectoryName(StateDb)!);
            builder.UseSetting("Kalitka:StateDbPath", StateDb);
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            try
            {
                Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
                Directory.Delete(Path.GetDirectoryName(StateDb)!, true);
            }
            catch { }
        }
    }

    private HttpClient Client() =>
        _f.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = false });

    private HttpRequestMessage Agent(HttpMethod m, string url, Dictionary<string, string>? form = null)
    {
        var req = new HttpRequestMessage(m, url);
        if (form is not null) req.Content = new FormUrlEncodedContent(form);
        req.Headers.Add("X-Kalitka-Agent", "agent-secret");
        return req;
    }

    private static string? Field(string json, string name)
    {
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.TryGetProperty(name, out var v) && v.ValueKind != JsonValueKind.Null
            ? v.GetString() : null;
    }

    [Fact]
    public async Task Grant_lifecycle_persists_to_the_state_file()
    {
        var raise = await Client().SendAsync(Agent(HttpMethod.Post, "/agent/request",
            new() { ["host"] = "prod-01", ["user"] = "sergej", ["ip"] = "203.0.113.90" }));
        var id = Field(await raise.Content.ReadAsStringAsync(), "id")!;

        var auth = _f.Services.GetRequiredService<AdminAuth>();
        var who = new AdminIdentity("sub-test", "admin@example.com");
        var decide = new HttpRequestMessage(HttpMethod.Post, "/admin/requests/decide")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            { ["id"] = id, ["verb"] = "ok", ["csrf"] = auth.IssueCsrf(who.Sub) })
        };
        decide.Headers.Add("Cookie", $"{AdminAuth.CookieName}={auth.IssueCookie(who)}");
        await Client().SendAsync(decide);

        var status = await (await Client().SendAsync(Agent(HttpMethod.Get, $"/agent/status?id={id}"))).Content.ReadAsStringAsync();
        var grant = Field(status, "grant");
        Assert.False(string.IsNullOrEmpty(grant));

        var redeem = await Client().SendAsync(Agent(HttpMethod.Post, "/agent/redeem",
            new() { ["grant"] = grant!, ["agent"] = "linux-prod-03" }));
        Assert.Equal(HttpStatusCode.OK, redeem.StatusCode);
        var sessionId = Field(await redeem.Content.ReadAsStringAsync(), "session_id")!;

        // Replay is refused by the durable single-use store, not an in-memory set.
        var again = await Client().SendAsync(Agent(HttpMethod.Post, "/agent/redeem",
            new() { ["grant"] = grant!, ["agent"] = "linux-prod-03" }));
        Assert.Equal(HttpStatusCode.Conflict, again.StatusCode);

        var end = await Client().SendAsync(Agent(HttpMethod.Post, "/agent/session/end",
            new() { ["session_id"] = sessionId, ["outcome"] = "ok" }));
        Assert.Equal(HttpStatusCode.OK, end.StatusCode);

        // Stand in for another instance: open the same file directly and read the
        // closed session the app wrote. If state were still in memory this is empty.
        Assert.True(File.Exists(_f.StateDb));
        var external = new SqliteSessionStore(_f.StateDb).Get(sessionId);
        Assert.NotNull(external);
        Assert.Equal("ssh:prod-01", external!.Resource);
        Assert.Equal("ok", external.Outcome);
        Assert.NotNull(external.EndedAt);
    }
}
