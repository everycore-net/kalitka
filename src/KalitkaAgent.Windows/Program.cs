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

// The enrolled id is handed from Worker to the log watcher; the activator turns a Core grant into
// local access (redeem + beneficiary check + enable), shared by the pipe path and the watcher.
builder.Services.AddSingleton<AgentIdentity>();
builder.Services.AddSingleton<RdpActivator>();
builder.Services.AddSingleton<IRdpActivator>(sp => sp.GetRequiredService<RdpActivator>());

builder.Services.AddHostedService<Worker>();
builder.Services.AddHostedService<RdpSweeper>();

// The Security-log watchers are opt-in: they need rights to read the Security log and are only
// useful once RDP gating enforces on the box. One raises on a denied logon (4625), the other ends a
// lease early on logoff (4634) and reports the session closed to Core.
if (builder.Configuration.GetSection("Kalitka").Get<AgentConfig>()?.RdpWatch == true)
{
    builder.Services.AddHostedService<SecurityLogWatcher>();
    builder.Services.AddHostedService<RdpLogoffWatcher>();
}

builder.Build().Run();
