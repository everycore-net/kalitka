using System.Net;
using System.Net.Mail;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Kalitka;

/// <summary>Sends the approval e-mails. Behind an interface so tests can watch it.</summary>
public interface IEmailSender
{
    bool Enabled { get; }
    Task Send(IReadOnlyList<string> to, string subject, string body, CancellationToken ct);
}

/// <summary>
/// SMTP via the framework's own client — no extra dependency, in keeping with the
/// product's no-heavy-deps line. A send failure is logged, not thrown: a request
/// still reaches Telegram even if the mail server is down.
/// </summary>
public sealed class SmtpEmailSender : IEmailSender
{
    private readonly GateOptions _o;
    private readonly ILogger<SmtpEmailSender> _log;

    public SmtpEmailSender(IOptions<GateOptions> options, ILogger<SmtpEmailSender> log)
    {
        _o = options.Value;
        _log = log;
    }

    public bool Enabled => !string.IsNullOrEmpty(_o.SmtpHost) && !string.IsNullOrEmpty(_o.SmtpFrom);

    public async Task Send(IReadOnlyList<string> to, string subject, string body, CancellationToken ct)
    {
        if (!Enabled || to.Count == 0) return;

        try
        {
            using var client = new SmtpClient(_o.SmtpHost, _o.SmtpPort) { EnableSsl = _o.SmtpStartTls };
            if (!string.IsNullOrEmpty(_o.SmtpUser))
                client.Credentials = new NetworkCredential(_o.SmtpUser, _o.SmtpPassword);

            using var msg = new MailMessage { From = new MailAddress(_o.SmtpFrom), Subject = subject, Body = body };
            foreach (var r in to) msg.To.Add(r);

            await client.SendMailAsync(msg, ct);
        }
        catch (Exception e)
        {
            _log.LogWarning("Email send failed: {Message}", e.Message);
        }
    }
}
