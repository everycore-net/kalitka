using KalitkaAgent;

var builder = Host.CreateApplicationBuilder(args);

// Run as a Windows Service in production; a plain console when launched directly (dev loop).
builder.Services.AddWindowsService(o => o.ServiceName = "KalitkaAgent");

builder.Services.Configure<AgentConfig>(builder.Configuration.GetSection("Kalitka"));

// One platform key for the process lifetime — opened (or created) once from the configured
// name. The private half stays in the CNG provider; this handle only signs and exports SPKI.
builder.Services.AddSingleton(sp =>
{
    var cfg = sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<AgentConfig>>().Value;
    return PlatformKey.OpenOrCreate(cfg.KeyName);
});

builder.Services.AddHttpClient<CoreClient>((sp, http) =>
{
    var cfg = sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<AgentConfig>>().Value;
    http.BaseAddress = new Uri(cfg.CoreUrl);
    http.Timeout = TimeSpan.FromSeconds(30);
});

// RDP JIT enforcement: a durable lease journal, session teardown, and the enforcer that grants on
// redeem / denies on expiry. How access is toggled is the IRdpAccess strategy, chosen by mode:
// soft (add to Remote Desktop Users) or hard (lift out of a deny group carrying the deny-logon
// right). Both need the agent to run with local-admin rights; hard mode also touches local policy.
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<ISessionKiller, WtsSessionKiller>();
builder.Services.AddSingleton<ISessionLiveness, CoreSessionLiveness>();
builder.Services.AddSingleton<ILsaPolicy, WindowsLsaPolicy>();
builder.Services.AddSingleton<IRdpAccess>(sp =>
{
    var cfg = sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<AgentConfig>>().Value;
    if (!cfg.RdpHardMode)
        return new AllowListAccess(WindowsLocalGroup.RemoteDesktopUsers());
    var denyGroup = WindowsLocalGroup.Named(cfg.DenyGroupName, "Kalitka default-deny RDP (managed)");
    return new DenyListAccess(denyGroup, sp.GetRequiredService<ILsaPolicy>(),
        sp.GetRequiredService<ILogger<DenyListAccess>>());
});
builder.Services.AddSingleton(sp =>
    new RdpJournal(sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<AgentConfig>>().Value.RdpJournalPath));
builder.Services.AddSingleton<RdpEnforcer>();

// The enrolled id is handed from Worker to the logoff watcher; the activator turns a Core grant into
// local access (redeem + beneficiary check + enable) for the pipe request path.
builder.Services.AddSingleton<AgentIdentity>();
builder.Services.AddSingleton<RdpActivator>();

builder.Services.AddHostedService<Worker>();
builder.Services.AddHostedService<RdpSweeper>();

// The logoff watcher is opt-in: it needs rights to read the Security log and is only useful once RDP
// gating enforces on the box. It ends a lease early on logoff (4634) and reports the session closed to
// Core. (The 4625 "denied-logon" auto-trigger was withdrawn: on a TLS listener the refusal is not
// written server-side as 4625 at all — see docs/design/rdp-signal-measured.md — so it never fired.)
if (builder.Configuration.GetSection("Kalitka").Get<AgentConfig>()?.RdpWatch == true)
{
    builder.Services.AddHostedService<RdpLogoffWatcher>();
}

builder.Build().Run();
