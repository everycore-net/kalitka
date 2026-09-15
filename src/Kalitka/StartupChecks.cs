namespace Kalitka;

/// <summary>
/// Startup configuration guards: refuse to come up half-configured, because a silently mis-set gate
/// is worse than one that does not start. Kept pure (a static over <see cref="GateOptions"/>) so the
/// rules are unit-tested without booting a host.
/// </summary>
public static class StartupChecks
{
    /// <summary>
    /// Validate the secrets and approval channels. <see cref="GateOptions.HmacSecret"/> and
    /// <see cref="GateOptions.GateHost"/> are always required (an unsigned cookie or no base URL is a
    /// non-starter). Telegram is optional now — but if <see cref="GateOptions.BotToken"/> is set it
    /// must be set <i>fully</i>. And there must be at least one channel that can actually reach a human
    /// to approve: Telegram, a console login provider (Google or Microsoft — which also backs the push
    /// PWA), or email. Throws <see cref="InvalidOperationException"/> naming the missing setting.
    /// </summary>
    public static void ValidateChannels(GateOptions o)
    {
        foreach (var (value, name) in new[] { (o.HmacSecret, nameof(o.HmacSecret)), (o.GateHost, nameof(o.GateHost)) })
            if (string.IsNullOrWhiteSpace(value))
                throw new InvalidOperationException($"Kalitka__{name} must be set.");

        var telegram = !string.IsNullOrWhiteSpace(o.BotToken);
        if (telegram)
        {
            // Half-configured Telegram (a token but no signed webhook) would accept an unauthenticated
            // webhook — worse than not having it at all.
            foreach (var (value, name) in new[] { (o.WebhookPath, nameof(o.WebhookPath)), (o.WebhookSecret, nameof(o.WebhookSecret)) })
                if (string.IsNullOrWhiteSpace(value))
                    throw new InvalidOperationException($"Kalitka__{name} must be set when Kalitka__BotToken is (Telegram is half-configured).");
            if (!o.WebhookPath.StartsWith('/'))
                throw new InvalidOperationException("Kalitka__WebhookPath must start with '/'.");
        }

        var consoleProvider = !string.IsNullOrWhiteSpace(o.GoogleClientId) || !string.IsNullOrWhiteSpace(o.MicrosoftClientId);
        var email = !string.IsNullOrWhiteSpace(o.SmtpHost);
        if (!(telegram || consoleProvider || email))
            throw new InvalidOperationException(
                "No approval channel is configured. Set at least one of: Kalitka__BotToken (Telegram), "
                + "Kalitka__GoogleClientId or Kalitka__MicrosoftClientId (web console + push app), or "
                + "Kalitka__SmtpHost (email). Kalitka__HmacSecret and Kalitka__GateHost are always required.");
    }
}
