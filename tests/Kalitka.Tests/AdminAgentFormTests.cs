using System.Net;
using Kalitka;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// The structured "New agent" form: capabilities come from a closed checkbox set (no silent typos),
/// the platform from a dropdown, and lower-case fields carry the mobile input attributes so a phone
/// keyboard cannot quietly capitalise a resource. subject.assert is presented apart as sudo-grade.
/// </summary>
public class AdminAgentFormTests : IClassFixture<GateFactory>
{
    private readonly GateFactory _f;
    public AdminAgentFormTests(GateFactory f) => _f = f;

    private HttpClient Client() => _f.CreateClient(new WebApplicationFactoryClientOptions
    {
        AllowAutoRedirect = false,
        HandleCookies = false,
    });

    private (string cookie, string csrf) Admin()
    {
        var a = _f.Services.GetRequiredService<AdminAuth>();
        var who = new AdminIdentity("sub-test", "admin@example.com");
        return (a.IssueCookie(who), a.IssueCsrf(who.Sub));
    }

    [Fact]
    public async Task Create_reads_capabilities_from_the_checkbox_set()
    {
        var (cookie, csrf) = Admin();
        // Form posts a repeated "cap" field per checked box.
        var body = "csrf=" + Uri.EscapeDataString(csrf)
            + "&mode=create&display_name=form-agent&platform=linux"
            + "&cap=access.request&cap=grant.redeem&cap=subject.assert"
            + "&allowed_resources=" + Uri.EscapeDataString("rdp:OLDEV ssh:prod-01");
        var req = new HttpRequestMessage(HttpMethod.Post, "/admin/agents/create")
        {
            Content = new StringContent(body, System.Text.Encoding.UTF8, "application/x-www-form-urlencoded"),
        };
        req.Headers.Add("Cookie", $"{AdminAuth.CookieName}={cookie}");
        var res = await Client().SendAsync(req);
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);   // the "secret shown once" page

        var agent = _f.Services.GetRequiredService<AgentService>().All().FirstOrDefault(a => a.DisplayName == "form-agent");
        Assert.NotNull(agent);
        Assert.Equal("linux", agent!.Platform);
        Assert.Contains("access.request", agent.Capabilities);
        Assert.Contains("grant.redeem", agent.Capabilities);
        Assert.Contains("subject.assert", agent.Capabilities);   // the privileged one, still just a checked box server-side
        Assert.Contains("rdp:OLDEV", agent.AllowedResources);    // preserved verbatim, not lower-cased by us
    }

    [Fact]
    public async Task The_form_marks_lower_case_fields_and_leads_with_the_enrollment_token()
    {
        var (cookie, _) = Admin();
        var req = new HttpRequestMessage(HttpMethod.Get, "/admin/agents");
        req.Headers.Add("Cookie", $"{AdminAuth.CookieName}={cookie}");
        var html = await (await Client().SendAsync(req)).Content.ReadAsStringAsync();

        Assert.Contains("autocapitalize=\"off\"", html);                 // mobile hygiene present
        Assert.Contains("name=\"cap\"", html);                            // capability checkboxes
        Assert.Contains("Create enrollment token", html);                // the primary path
        Assert.Contains("Legacy: create with a shared secret", html);    // the demoted one
        // The privileged capability carries its warning, not a bare checkbox.
        Assert.Contains("sudo-grade", html);
    }
}
