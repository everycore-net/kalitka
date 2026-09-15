using System.Net;
using Kalitka;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Kalitka.Tests;

/// <summary>A gate with one integration key (scope rdp:*) for the request API. A generous rate so the
/// shared-fixture tests don't interfere (the clock is frozen, so the window never rolls); the
/// rate-limit test uses its own low-limit factory.</summary>
public sealed class RequestApiFactory : GateFactory
{
    public const string Token = "jira-bearer-token-secret";

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.UseSetting("Kalitka:IntegrationClients:0:Id", "jira");
        builder.UseSetting("Kalitka:IntegrationClients:0:Token", Token);
        builder.UseSetting("Kalitka:IntegrationClients:0:Scope:0", "rdp:*");
        builder.UseSetting("Kalitka:IntegrationClients:0:MaxRequestsPerMinute", "100");
    }
}

/// <summary>Its own gate with a tiny per-minute budget, so the rate-limit test's counter is isolated.</summary>
public sealed class RateLimitedApiFactory : GateFactory
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.UseSetting("Kalitka:IntegrationClients:0:Id", "jira");
        builder.UseSetting("Kalitka:IntegrationClients:0:Token", RequestApiFactory.Token);
        builder.UseSetting("Kalitka:IntegrationClients:0:Scope:0", "rdp:*");
        builder.UseSetting("Kalitka:IntegrationClients:0:MaxRequestsPerMinute", "2");
    }
}

/// <summary>
/// The REST request API for integrations: bearer auth, scope enforcement, one-ticket-one-request
/// idempotency, rate limit, and the status vocabulary — an integration raises on behalf of a person,
/// never approves.
/// </summary>
public class IntegrationApiTests : IClassFixture<RequestApiFactory>
{
    private readonly RequestApiFactory _f;
    public IntegrationApiTests(RequestApiFactory f) => _f = f;

    private HttpClient Client() => _f.CreateClient(new WebApplicationFactoryClientOptions
    {
        AllowAutoRedirect = false,
        HandleCookies = false,
    });

    private HttpRequestMessage Raise(string token, string resource, string subject, string? externalId = null)
    {
        var form = new Dictionary<string, string> { ["resource"] = resource, ["subject"] = subject };
        if (externalId is not null) form["external_id"] = externalId;
        var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/requests") { Content = new FormUrlEncodedContent(form) };
        req.Headers.Add("Authorization", "Bearer " + token);
        req.Headers.Add("X-Test-Peer", "10.0.0.5");
        req.Headers.Add("X-Forwarded-For", "203.0.113.9");
        return req;
    }

    private static async Task<(HttpStatusCode code, string body)> Send(HttpClient c, HttpRequestMessage req)
    {
        var res = await c.SendAsync(req);
        return (res.StatusCode, await res.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task An_in_scope_request_is_raised_pending()
    {
        var (code, body) = await Send(Client(), Raise(RequestApiFactory.Token, "rdp:WIN-01", "os:contoso\\anna"));
        Assert.Equal(HttpStatusCode.Accepted, code);
        Assert.Contains("\"status\":\"pending\"", body);

        var gate = _f.Services.GetRequiredService<GateService>();
        Assert.Contains(gate.PendingSnapshot(), r => r.Target == "rdp:WIN-01" && r.State == "waiting");
    }

    [Fact]
    public async Task A_bad_or_missing_token_is_unauthorized()
    {
        Assert.Equal(HttpStatusCode.Unauthorized, (await Send(Client(), Raise("wrong", "rdp:WIN-02", "os:x"))).code);

        var noAuth = new HttpRequestMessage(HttpMethod.Post, "/api/v1/requests")
        { Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["resource"] = "rdp:WIN-02", ["subject"] = "os:x" }) };
        Assert.Equal(HttpStatusCode.Unauthorized, (await Client().SendAsync(noAuth)).StatusCode);
    }

    [Fact]
    public async Task An_out_of_scope_resource_is_refused()
    {
        var (code, _) = await Send(Client(), Raise(RequestApiFactory.Token, "db:secret", "os:contoso\\bob"));
        Assert.Equal(HttpStatusCode.Forbidden, code);   // scope is rdp:* only
    }

    [Fact]
    public async Task The_same_ticket_maps_to_one_request()
    {
        var c = Client();
        var (_, first) = await Send(c, Raise(RequestApiFactory.Token, "rdp:WIN-03", "os:contoso\\carol", externalId: "TICKET-1"));
        var id1 = System.Text.Json.JsonDocument.Parse(first).RootElement.GetProperty("request_id").GetString();

        var (code2, second) = await Send(c, Raise(RequestApiFactory.Token, "rdp:WIN-03", "os:contoso\\carol", externalId: "TICKET-1"));
        var id2 = System.Text.Json.JsonDocument.Parse(second).RootElement.GetProperty("request_id").GetString();

        Assert.Equal(HttpStatusCode.OK, code2);   // idempotent hit, not a fresh 202
        Assert.Equal(id1, id2);
        var gate = _f.Services.GetRequiredService<GateService>();
        Assert.Single(gate.PendingSnapshot(), r => r.Target == "rdp:WIN-03");
    }

    [Fact]
    public async Task Status_can_be_read_and_reflects_a_decision()
    {
        var c = Client();
        var (_, body) = await Send(c, Raise(RequestApiFactory.Token, "rdp:WIN-04", "os:contoso\\dave"));
        var id = System.Text.Json.JsonDocument.Parse(body).RootElement.GetProperty("request_id").GetString()!;

        var get = new HttpRequestMessage(HttpMethod.Get, "/api/v1/requests/" + id);
        get.Headers.Add("Authorization", "Bearer " + RequestApiFactory.Token);
        Assert.Contains("\"status\":\"pending\"", await (await c.SendAsync(get)).Content.ReadAsStringAsync());

        await _f.Services.GetRequiredService<GateService>().Decide(id, "ok", "telegram:1");

        var get2 = new HttpRequestMessage(HttpMethod.Get, "/api/v1/requests/" + id);
        get2.Headers.Add("Authorization", "Bearer " + RequestApiFactory.Token);
        Assert.Contains("\"status\":\"approved\"", await (await c.SendAsync(get2)).Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task A_json_body_is_accepted_like_a_form()
    {
        var json = "{\"resource\":\"rdp:WIN-05\",\"subject\":\"os:contoso\\\\erin\",\"external_id\":\"JIRA-5\"}";
        var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/requests")
        { Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json") };
        req.Headers.Add("Authorization", "Bearer " + RequestApiFactory.Token);

        var (code, body) = await Send(Client(), req);
        Assert.Equal(HttpStatusCode.Accepted, code);
        Assert.Contains("\"status\":\"pending\"", body);

        var gate = _f.Services.GetRequiredService<GateService>();
        Assert.Contains(gate.PendingSnapshot(), r => r.Target == "rdp:WIN-05" && r.State == "waiting");
    }

    [Fact]
    public async Task A_malformed_json_body_is_a_client_error_not_a_crash()
    {
        var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/requests")
        { Content = new StringContent("{not json", System.Text.Encoding.UTF8, "application/json") };
        req.Headers.Add("Authorization", "Bearer " + RequestApiFactory.Token);
        Assert.Equal(HttpStatusCode.BadRequest, (await Send(Client(), req)).code);
    }

    [Fact]
    public async Task Concurrent_first_calls_for_one_ticket_raise_a_single_request()
    {
        var c = Client();
        // Fire the same ticket twice at once: one wins the reservation and raises, the other waits for
        // it to settle and returns the same id. Never two requests.
        var (r1, r2) = (Send(c, Raise(RequestApiFactory.Token, "rdp:WIN-06", "os:contoso\\finn", externalId: "TICKET-C")),
                        Send(c, Raise(RequestApiFactory.Token, "rdp:WIN-06", "os:contoso\\finn", externalId: "TICKET-C")));
        var results = await Task.WhenAll(r1, r2);

        string Id(string b) => System.Text.Json.JsonDocument.Parse(b).RootElement.GetProperty("request_id").GetString()!;
        Assert.Equal(Id(results[0].body), Id(results[1].body));
        Assert.All(results, r => Assert.True(r.code is HttpStatusCode.Accepted or HttpStatusCode.OK));

        var gate = _f.Services.GetRequiredService<GateService>();
        Assert.Single(gate.PendingSnapshot(), r => r.Target == "rdp:WIN-06");
    }

    [Fact]
    public async Task The_integration_is_rate_limited()
    {
        using var f = new RateLimitedApiFactory();   // isolated counter, budget 2/min
        var c = f.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = false });

        Assert.Equal(HttpStatusCode.Accepted, (await Send(c, Raise(RequestApiFactory.Token, "rdp:R1", "os:contoso\\u1"))).code);
        Assert.Equal(HttpStatusCode.Accepted, (await Send(c, Raise(RequestApiFactory.Token, "rdp:R2", "os:contoso\\u2"))).code);
        Assert.Equal((HttpStatusCode)429, (await Send(c, Raise(RequestApiFactory.Token, "rdp:R3", "os:contoso\\u3"))).code);
    }
}
