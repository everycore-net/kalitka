using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Kalitka;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// The device-signed approval channel through the real HTTP pipeline: an admin registers a passkey,
/// a request is raised, and the admin approves it with a device signature — verified server-side and
/// recorded, with the proof committed to the audit event.
/// </summary>
public class WebAuthnEndpointTests : IClassFixture<GateFactory>
{
    private const string RpId = "gate.example.com";
    private const string Origin = "https://gate.example.com";
    private readonly GateFactory _f;
    public WebAuthnEndpointTests(GateFactory f) => _f = f;

    private HttpClient Client() =>
        _f.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = false });

    private (string cookie, string csrf) AdminSession()
    {
        var a = _f.Services.GetRequiredService<AdminAuth>();
        var who = new AdminIdentity("sub-test", "admin@example.com");
        return (a.IssueCookie(who), a.IssueCsrf(who.Sub));
    }

    [Fact]
    public async Task Devices_page_requires_an_admin_session()
    {
        var res = await Client().GetAsync("/admin/devices");
        Assert.Equal(HttpStatusCode.Redirect, res.StatusCode);
        Assert.Contains("/admin/login", res.Headers.Location!.ToString());
    }

    [Fact]
    public async Task Register_a_device_then_approve_a_request_with_a_signature()
    {
        var (cookie, csrf) = AdminSession();
        var auth = new SoftAuthenticator();

        // 1. Register the device.
        var regBegin = await PostJson("/admin/devices/register/begin", cookie, csrf, null);
        var (regOptions, regState) = BeginParts(regBegin);
        var (att, regCdj) = auth.Register(RpId, Origin, ChallengeOf(regOptions));
        var regFinish = await PostJson("/admin/devices/register/finish", cookie, null, JsonSerializer.Serialize(new
        {
            state = regState, credentialId = auth.CredentialIdB64u, attestationObject = att,
            clientDataJson = regCdj, displayName = "test device", csrf,
        }));
        Assert.Equal(HttpStatusCode.OK, regFinish.StatusCode);
        Assert.Contains("\"ok\":true", await regFinish.Content.ReadAsStringAsync());

        // 2. Raise a request through the agent endpoint.
        var id = await RaiseAgentRequest("prod-01", "sergej");

        // 3. Begin the signed approval, sign the challenge, and submit the decision.
        var apBegin = await PostJson($"/admin/requests/{id}/approve/begin?verb=ok", cookie, csrf, null);
        Assert.Equal(HttpStatusCode.OK, apBegin.StatusCode);
        var (apOptions, apState) = BeginParts(apBegin);
        var (cid, ad, cdj, sig) = auth.Sign(RpId, Origin, ChallengeOf(apOptions), 1);
        var decide = await PostJson("/admin/requests/decide-signed", cookie, null, JsonSerializer.Serialize(new
        {
            id, verb = "ok", state = apState, credentialId = cid, authenticatorData = ad,
            clientDataJson = cdj, signature = sig, csrf,
        }));
        Assert.Equal(HttpStatusCode.OK, decide.StatusCode);
        Assert.Contains("\"ok\":true", await decide.Content.ReadAsStringAsync());

        // 4. The request is approved, and the approval event carries a device proof, bound to the
        //    device identity, with the proof committed into the (hashed) metadata.
        Assert.Equal("approved", await AgentStatus(id));
        var audit = _f.Services.GetRequiredService<IAuditStore>();
        var events = await audit.Query(new AuditQuery(EventType: AuditEvents.AccessApproved, Limit: 100), default);
        var approved = Assert.Single(events, e => e.RequestId == id);
        Assert.StartsWith("wa1:", approved.Proof);
        Assert.StartsWith("app:", approved.Actor);
        Assert.Contains("p=", approved.Metadata);

        // 5. The chain still verifies with the proof-bearing event in it.
        Assert.True((await audit.VerifyChain(default)).Intact);
    }

    // ---- helpers -----------------------------------------------------------

    private async Task<HttpResponseMessage> PostJson(string url, string cookie, string? csrfHeader, string? json)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, url);
        req.Headers.Add("Cookie", $"{AdminAuth.CookieName}={cookie}");
        if (csrfHeader is not null) req.Headers.Add("X-Csrf", csrfHeader);
        if (json is not null) req.Content = new StringContent(json, Encoding.UTF8, "application/json");
        return await Client().SendAsync(req);
    }

    private static (string options, string state) BeginParts(HttpResponseMessage res)
    {
        var body = res.Content.ReadAsStringAsync().Result;
        using var doc = JsonDocument.Parse(body);
        return (doc.RootElement.GetProperty("options").GetRawText(), doc.RootElement.GetProperty("state").GetString()!);
    }

    private static string ChallengeOf(string optionsJson) =>
        JsonDocument.Parse(optionsJson).RootElement.GetProperty("challenge").GetString()!;

    private async Task<string> RaiseAgentRequest(string host, string user)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, "/agent/request")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["host"] = host, ["user"] = user, ["ip"] = "203.0.113.9" }),
        };
        req.Headers.Add("X-Kalitka-Agent", "agent-secret");
        var json = await (await Client().SendAsync(req)).Content.ReadAsStringAsync();
        return JsonDocument.Parse(json).RootElement.GetProperty("id").GetString()!;
    }

    private async Task<string> AgentStatus(string id)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, $"/agent/status?id={id}");
        req.Headers.Add("X-Kalitka-Agent", "agent-secret");
        var json = await (await Client().SendAsync(req)).Content.ReadAsStringAsync();
        return JsonDocument.Parse(json).RootElement.GetProperty("state").GetString()!;
    }
}
