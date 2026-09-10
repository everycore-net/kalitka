using Microsoft.Extensions.Options;

namespace Kalitka;

/// <summary>
/// The e-mail approval channel: a second <see cref="INotifier"/> beside Telegram.
/// On a new request it mails the operators an approve and a deny link — one-time
/// capabilities that open a confirmation page (see the <c>/action</c> endpoints).
/// Nothing here approves anything; it only hands out links.
/// </summary>
public sealed class EmailNotifier : INotifier
{
    private readonly OneTimeTokenService _tokens;
    private readonly IEmailSender _email;
    private readonly GateOptions _o;

    public EmailNotifier(OneTimeTokenService tokens, IEmailSender email, IOptions<GateOptions> options)
    {
        _tokens = tokens;
        _email = email;
        _o = options.Value;
    }

    public bool Ready => _email.Enabled && _o.AdminEmails.Length > 0;

    public async Task Announce(PendingRequest r, CancellationToken ct)
    {
        if (!Ready) return;

        var resource = "web:" + r.Target;
        var approve = Link(_tokens.Mint("approve", resource, r.Id, "a", _o.OneTimeMinutes));
        var deny = Link(_tokens.Mint("approve", resource, r.Id, "d", _o.OneTimeMinutes));

        var body =
            $"Someone is asking to reach {r.Target}.\n\n"
          + $"Says: {r.Input}\n"
          + $"IP:   {r.Ip}\n\n"
          + $"Approve: {approve}\n"
          + $"Deny:    {deny}\n\n"
          + $"Each link opens a confirmation page — nothing happens until you confirm there. "
          + $"They work once and expire in {_o.OneTimeMinutes} minutes.";

        await _email.Send(_o.AdminEmails, $"kalitka: access request for {r.Target}", body, ct);
    }

    private string Link(string token) => $"https://{_o.GateHost}/action?t={Uri.EscapeDataString(token)}";
}
