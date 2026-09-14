using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Kalitka;

/// <summary>The VAPID key pair for this instance, generated once and kept in the shared config store
/// so every node (and a restart) uses the same application-server identity — a browser's subscription
/// is bound to it.</summary>
public sealed class VapidKeyProvider
{
    private const string Key = "vapid-keys";
    private readonly IConfigStore _config;
    private readonly object _lock = new();
    private VapidKeys? _cached;

    public VapidKeyProvider(IConfigStore config) => _config = config;

    public VapidKeys Keys()
    {
        lock (_lock)
        {
            if (_cached is not null) return _cached;
            var blob = _config.Get(Key);
            if (!string.IsNullOrWhiteSpace(blob))
                return _cached = JsonSerializer.Deserialize<VapidKeys>(blob)!;
            var fresh = VapidKeys.Generate();
            _config.Mutate(Key, cur => string.IsNullOrWhiteSpace(cur) ? JsonSerializer.Serialize(fresh) : cur);
            // Re-read: another node may have won the race and written its own pair.
            return _cached = JsonSerializer.Deserialize<VapidKeys>(_config.Get(Key)!)!;
        }
    }

    public string PublicKey => Keys().PublicKey;
}

/// <summary>A browser's push subscription, bound to the operator principal that registered it.</summary>
public sealed record PushSubscription(string Endpoint, string P256dh, string Auth, string PrincipalId, string CreatedAt);

/// <summary>Where push subscriptions live — one JSON blob in the shared config store, like operator
/// principals and passkeys. Keyed by endpoint (a browser re-subscribing replaces its own).</summary>
public sealed class PushSubscriptionStore
{
    private const string Key = "push-subscriptions";
    private readonly IConfigStore _config;

    public PushSubscriptionStore(IConfigStore config) => _config = config;

    public IReadOnlyList<PushSubscription> All() => Parse(_config.Get(Key));

    public IReadOnlyList<PushSubscription> ForPrincipal(string principalId) =>
        All().Where(s => string.Equals(s.PrincipalId, principalId, StringComparison.OrdinalIgnoreCase)).ToList();

    public void Add(PushSubscription sub)
    {
        _config.Mutate(Key, cur =>
        {
            var list = Parse(cur).Where(s => s.Endpoint != sub.Endpoint).ToList();
            list.Add(sub);
            return JsonSerializer.Serialize(list);
        });
    }

    public bool RemoveByEndpoint(string endpoint)
    {
        var removed = false;
        _config.Mutate(Key, cur =>
        {
            var list = Parse(cur);
            removed = list.RemoveAll(s => s.Endpoint == endpoint) > 0;
            return JsonSerializer.Serialize(list);
        });
        return removed;
    }

    private static List<PushSubscription> Parse(string? blob) =>
        string.IsNullOrWhiteSpace(blob) ? new() : (JsonSerializer.Deserialize<List<PushSubscription>>(blob) ?? new());
}

public enum PushResult { Ok, Gone, Failed }

/// <summary>Sends one encrypted push to a subscription's endpoint.</summary>
public interface IWebPushSender
{
    Task<PushResult> Send(PushSubscription sub, byte[] payload, CancellationToken ct);
}

/// <summary>
/// The HTTP side of Web Push: encrypt the payload for the subscription (RFC 8291), attach a VAPID
/// authorization (RFC 8292), POST it to the endpoint. A <c>404</c>/<c>410</c> means the browser
/// dropped the subscription, so the caller prunes it.
/// </summary>
public sealed class WebPushSender : IWebPushSender
{
    private readonly IHttpClientFactory _http;
    private readonly VapidKeyProvider _vapid;
    private readonly GateOptions _options;
    private readonly TimeProvider _clock;
    private readonly ILogger<WebPushSender> _log;

    public WebPushSender(IHttpClientFactory http, VapidKeyProvider vapid, IOptions<GateOptions> options,
        TimeProvider clock, ILogger<WebPushSender> log)
    {
        _http = http;
        _vapid = vapid;
        _options = options.Value;
        _clock = clock;
        _log = log;
    }

    private string Subject() =>
        !string.IsNullOrWhiteSpace(_options.VapidSubject) ? _options.VapidSubject
        : _options.AdminEmails.Length > 0 ? "mailto:" + _options.AdminEmails[0]
        : "https://" + _options.GateHost;

    public async Task<PushResult> Send(PushSubscription sub, byte[] payload, CancellationToken ct)
    {
        try
        {
            var body = WebPushCrypto.Encrypt(sub.P256dh, sub.Auth, payload);
            using var req = new HttpRequestMessage(HttpMethod.Post, sub.Endpoint);
            req.Headers.TryAddWithoutValidation("Authorization", Vapid.Authorization(sub.Endpoint, Subject(), _vapid.Keys(), _clock.GetUtcNow()));
            req.Headers.TryAddWithoutValidation("TTL", _options.PushTtlSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture));
            req.Content = new ByteArrayContent(body);
            req.Content.Headers.TryAddWithoutValidation("Content-Encoding", "aes128gcm");
            req.Content.Headers.TryAddWithoutValidation("Content-Type", "application/octet-stream");

            using var client = _http.CreateClient("webpush");
            using var res = await client.SendAsync(req, ct);
            if (res.IsSuccessStatusCode) return PushResult.Ok;
            if (res.StatusCode is System.Net.HttpStatusCode.NotFound or System.Net.HttpStatusCode.Gone)
                return PushResult.Gone;
            _log.LogWarning("Push to {Endpoint} failed: {Status}", Origin(sub.Endpoint), (int)res.StatusCode);
            return PushResult.Failed;
        }
        catch (Exception e)
        {
            _log.LogWarning("Push to {Endpoint} threw: {Message}", Origin(sub.Endpoint), e.Message);
            return PushResult.Failed;
        }
    }

    private static string Origin(string endpoint)
    {
        try { return new Uri(endpoint).GetLeftPart(UriPartial.Authority); } catch { return "?"; }
    }
}

/// <summary>
/// The push channel as another <see cref="INotifier"/> — the enterprise/solo alternative to Telegram,
/// and the receiver a device-signed approval is answered from. On a new request it notifies the
/// resolved operator's devices (and every registered device when the routing asks the admins), then
/// prunes any subscription the push service reports as gone. The payload is deliberately thin: a
/// request id and a one-line context, deep-linking into the signing UI.
/// </summary>
public sealed class PushNotifier : INotifier
{
    private readonly PushSubscriptionStore _subs;
    private readonly PrincipalService _principals;
    private readonly IWebPushSender _sender;
    private readonly ILogger<PushNotifier> _log;

    public PushNotifier(PushSubscriptionStore subs, PrincipalService principals, IWebPushSender sender, ILogger<PushNotifier> log)
    {
        _subs = subs;
        _principals = principals;
        _sender = sender;
        _log = log;
    }

    public bool Ready => true;   // VAPID keys are always available (generated on demand)

    public async Task Announce(PendingRequest request, NotifyRouting routing, CancellationToken ct)
    {
        var targets = Targets(routing).ToList();
        if (targets.Count == 0) return;

        var payload = JsonSerializer.SerializeToUtf8Bytes(new
        {
            id = request.Id,
            title = "kalitka · access request",
            body = Describe(request),
            url = "/admin/requests/" + request.Id,
        });

        foreach (var sub in targets)
            if (await _sender.Send(sub, payload, ct) == PushResult.Gone)
                _subs.RemoveByEndpoint(sub.Endpoint);   // the browser dropped it — stop trying
    }

    // Who to push to: the resolved operators' devices, plus every registered device when the routing
    // falls back to the admins (an ordinary request). De-duplicated by endpoint.
    private IEnumerable<PushSubscription> Targets(NotifyRouting routing)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        IEnumerable<PushSubscription> pool = routing.IncludeAdmins
            ? _subs.All()
            : routing.OperatorIdentities
                .Select(_principals.Resolve).Where(p => p is not null)
                .SelectMany(p => _subs.ForPrincipal(p!));
        foreach (var s in pool)
            if (seen.Add(s.Endpoint)) yield return s;
    }

    private static string Describe(PendingRequest r)
    {
        var who = string.IsNullOrWhiteSpace(r.Input) ? "" : r.Input + " → ";
        var what = string.IsNullOrWhiteSpace(r.Command) ? r.Target : r.Command;
        return who + what;
    }
}
