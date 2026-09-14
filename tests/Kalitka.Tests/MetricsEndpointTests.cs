using System.Net;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// The /metrics scrape endpoint. Traefik routes the whole host, so it must be guarded — but a stock
/// Prometheus must be able to reach it, via the internal header or a bearer token.
/// </summary>
public class MetricsEndpointTests : IClassFixture<GateFactory>
{
    private const string Secret = "internal-secret";
    private readonly GateFactory _f;
    public MetricsEndpointTests(GateFactory f) => _f = f;

    private HttpClient Client() =>
        _f.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

    [Fact]
    public async Task Without_the_secret_it_is_forbidden()
    {
        var res = await Client().GetAsync("/metrics");
        Assert.Equal(HttpStatusCode.Forbidden, res.StatusCode);
    }

    [Fact]
    public async Task The_internal_header_is_accepted_and_the_families_are_present()
    {
        var req = new HttpRequestMessage(HttpMethod.Get, "/metrics");
        req.Headers.Add("X-Kalitka-Internal", Secret);
        var res = await Client().SendAsync(req);

        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        var body = await res.Content.ReadAsStringAsync();
        Assert.Contains("kalitka_decisions_total", body);
        Assert.Contains("kalitka_notify_fallback_total", body);
        Assert.Contains("kalitka_pending_requests", body);
        Assert.Contains("kalitka_time_to_approval_seconds", body);
    }

    [Fact]
    public async Task A_bearer_token_with_the_same_secret_is_accepted()
    {
        var req = new HttpRequestMessage(HttpMethod.Get, "/metrics");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Secret);
        var res = await Client().SendAsync(req);
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
    }

    [Fact]
    public async Task A_wrong_bearer_token_is_forbidden()
    {
        var req = new HttpRequestMessage(HttpMethod.Get, "/metrics");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "not-the-secret");
        var res = await Client().SendAsync(req);
        Assert.Equal(HttpStatusCode.Forbidden, res.StatusCode);
    }
}
