using System.Net.Sockets;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Kalitka;

/// <summary>
/// The RADIUS listener: a UDP socket that answers a gateway's Access-Request through
/// <see cref="RadiusApproval"/>. Runs only when configured (enabled + a shared secret); otherwise it
/// is a no-op, so it ships dormant. The listener is not exposed publicly by default — a deployment
/// that wants it maps the port and points a gateway (NPS/VPN/Citrix/Wi-Fi) at it.
///
/// Each datagram is handled off the receive loop, and every response carries the same identifier and
/// authenticator binding the RADIUS codec requires; a handler fault never takes down the socket.
/// </summary>
public sealed class RadiusServer : BackgroundService
{
    private readonly RadiusApproval _approval;
    private readonly RadiusClientRegistry _clients;
    private readonly GateOptions _options;
    private readonly ILogger<RadiusServer> _log;

    public RadiusServer(RadiusApproval approval, RadiusClientRegistry clients, IOptions<GateOptions> options, ILogger<RadiusServer> log)
    {
        _approval = approval;
        _clients = clients;
        _options = options.Value;
        _log = log;
    }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        if (!_options.RadiusEnabled || !_clients.HasAny)
            return;   // dormant unless enabled with at least one client (legacy secret or registry)

        using var udp = new UdpClient(_options.RadiusPort);
        _log.LogInformation("RADIUS listening on udp/{Port}", _options.RadiusPort);

        while (!ct.IsCancellationRequested)
        {
            UdpReceiveResult received;
            try { received = await udp.ReceiveAsync(ct); }
            catch (OperationCanceledException) { break; }
            catch (Exception e) { _log.LogWarning("RADIUS receive error: {Message}", e.Message); continue; }

            _ = HandleDatagram(udp, received, ct);   // off the receive loop; the wait is held via Challenge
        }
    }

    private async Task HandleDatagram(UdpClient udp, UdpReceiveResult received, CancellationToken ct)
    {
        try
        {
            var packet = RadiusPacket.Parse(received.Buffer);
            if (packet is null || packet.Code != RadiusCode.AccessRequest) return;   // ignore non-requests

            var response = await _approval.Handle(packet, received.Buffer, received.RemoteEndPoint.Address.ToString(), ct);
            if (response is { Length: > 0 })   // null = unknown client, answer nothing
                await udp.SendAsync(response, response.Length, received.RemoteEndPoint);
        }
        catch (Exception e)
        {
            _log.LogWarning("RADIUS handler error from {Peer}: {Message}", received.RemoteEndPoint, e.Message);
        }
    }
}
