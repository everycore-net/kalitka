using Kalitka;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Kalitka.Tests;

public class CookieTests
{
    private static GateService Gate(string secret, FakeTimeProvider clock, string? statePath = null,
        SessionScope scope = SessionScope.Application)
    {
        var opts = new GateOptions
        {
            HmacSecret = secret,
            GateHost = "gate.example.com",
            SessionMinutes = 60,
            SessionScope = scope,
            ListsPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".json"),
            EnforcedPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".json"),
            SettingsPath = statePath ?? Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".json"),
            GeoUrl = ""
        };
        var io = Options.Create(opts);
        var geo = new HttpGeoLookup(new HttpClient(), io, NullLogger<HttpGeoLookup>.Instance);
        var lists = new AccessLists(io, NullLogger<AccessLists>.Instance);
        return new GateService(new FakeTelegram(), geo, lists, io, NullLogger<GateService>.Instance, clock);
    }

    private static FakeTimeProvider ClockAt() => new(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero));

    [Fact]
    public void Valid_cookie_is_accepted_for_its_host()
    {
        var clock = ClockAt();
        var gate = Gate("key-aaaaaaaaaaaaaaaaaaaaaaaa", clock);
        var cookie = gate.BuildCookie("app.example.com");
        Assert.True(gate.IsCookieValid(cookie, "app.example.com"));
    }

    [Fact]
    public void Tampered_cookie_is_rejected()
    {
        var clock = ClockAt();
        var gate = Gate("key-aaaaaaaaaaaaaaaaaaaaaaaa", clock);
        var cookie = gate.BuildCookie("app.example.com");
        var tampered = cookie[..^1] + (cookie[^1] == 'a' ? 'b' : 'a');   // flip last sig char
        Assert.False(gate.IsCookieValid(tampered, "app.example.com"));
    }

    [Fact]
    public void Expired_cookie_is_rejected()
    {
        var clock = ClockAt();
        var gate = Gate("key-aaaaaaaaaaaaaaaaaaaaaaaa", clock);
        var cookie = gate.BuildCookie("app.example.com");   // valid for 60 min
        clock.Advance(TimeSpan.FromMinutes(61));
        Assert.False(gate.IsCookieValid(cookie, "app.example.com"));
    }

    [Fact]
    public void Cookie_signed_with_a_previous_secret_is_rejected()
    {
        var clock = ClockAt();
        var old = Gate("old-secret-aaaaaaaaaaaaaaaaaaaa", clock);
        var rotated = Gate("new-secret-bbbbbbbbbbbbbbbbbbbb", clock);

        var cookie = old.BuildCookie("app.example.com");
        Assert.True(old.IsCookieValid(cookie, "app.example.com"));      // sanity
        Assert.False(rotated.IsCookieValid(cookie, "app.example.com")); // rotation logs everyone out
    }

    [Fact]
    public void Per_host_cookie_does_not_open_a_sibling_but_global_does()
    {
        var clock = ClockAt();
        var gate = Gate("key-aaaaaaaaaaaaaaaaaaaaaaaa", clock);

        var perHost = gate.BuildCookie("app.example.com");
        Assert.False(gate.IsCookieValid(perHost, "other.example.com"));

        var global = gate.BuildGlobalCookie();
        Assert.True(gate.IsCookieValid(global, "app.example.com"));
        Assert.True(gate.IsCookieValid(global, "other.example.com"));
    }

    [Fact]
    public void Google_identity_session_is_per_host_by_default()
    {
        var clock = ClockAt();
        var gate = Gate("key-aaaaaaaaaaaaaaaaaaaaaaaa", clock);   // SessionScope.Application

        var cookie = gate.BuildIdentitySession("app.example.com");
        Assert.True(gate.IsCookieValid(cookie, "app.example.com"));
        Assert.False(gate.IsCookieValid(cookie, "other.example.com"));   // no longer opens a sibling
    }

    [Fact]
    public void Google_identity_session_is_domain_wide_when_opted_in()
    {
        var clock = ClockAt();
        var gate = Gate("key-aaaaaaaaaaaaaaaaaaaaaaaa", clock, scope: SessionScope.Domain);

        var cookie = gate.BuildIdentitySession("app.example.com");
        Assert.True(gate.IsCookieValid(cookie, "app.example.com"));
        Assert.True(gate.IsCookieValid(cookie, "other.example.com"));
    }
}
