using Kalitka;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// Startup refuses to come up half-configured, but Telegram is no longer mandatory: any one approval
/// channel is enough. This is the fix that lets a Telegram-banned corporate install run on the web
/// console (Google/Microsoft) or email alone.
/// </summary>
public class StartupChecksTests
{
    // A base with the always-required secrets set and no channel yet.
    private static GateOptions Base() => new() { HmacSecret = "x", GateHost = "gate.example" };

    private static void Validate(GateOptions o) => StartupChecks.ValidateChannels(o);

    [Fact]
    public void HmacSecret_and_GateHost_are_always_required()
    {
        Assert.Throws<InvalidOperationException>(() => Validate(new GateOptions { GateHost = "g", GoogleClientId = "id" }));
        Assert.Throws<InvalidOperationException>(() => Validate(new GateOptions { HmacSecret = "x", GoogleClientId = "id" }));
    }

    [Fact]
    public void At_least_one_approval_channel_is_required()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => Validate(Base()));   // secrets only, no channel
        Assert.Contains("approval channel", ex.Message);
    }

    [Fact]
    public void A_console_login_provider_alone_is_enough()
    {
        var google = Base(); google.GoogleClientId = "id";
        Validate(google);   // no throw

        var microsoft = Base(); microsoft.MicrosoftClientId = "id";
        Validate(microsoft);
    }

    [Fact]
    public void Email_alone_is_enough()
    {
        var smtp = Base(); smtp.SmtpHost = "smtp.example";
        Validate(smtp);
    }

    [Fact]
    public void Fully_configured_telegram_alone_is_enough()
    {
        var tg = Base();
        tg.BotToken = "t"; tg.WebhookPath = "/hook"; tg.WebhookSecret = "s";
        Validate(tg);
    }

    [Fact]
    public void Half_configured_telegram_is_refused()
    {
        var noPath = Base(); noPath.BotToken = "t"; noPath.WebhookSecret = "s";
        Assert.Throws<InvalidOperationException>(() => Validate(noPath));

        var noSecret = Base(); noSecret.BotToken = "t"; noSecret.WebhookPath = "/hook";
        Assert.Throws<InvalidOperationException>(() => Validate(noSecret));

        var badPath = Base(); badPath.BotToken = "t"; badPath.WebhookPath = "hook"; badPath.WebhookSecret = "s";
        Assert.Throws<InvalidOperationException>(() => Validate(badPath));
    }

    [Fact]
    public void A_google_provider_does_not_require_any_telegram_settings()
    {
        // The regression this fixes: previously BotToken/WebhookPath/WebhookSecret were mandatory even
        // with a working web console.
        var o = Base(); o.GoogleClientId = "id"; o.GoogleClientSecret = "secret";
        Validate(o);   // no throw, no Telegram anywhere
    }
}
