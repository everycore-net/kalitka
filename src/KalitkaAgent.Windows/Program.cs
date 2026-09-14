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

builder.Services.AddHostedService<Worker>();

builder.Build().Run();
