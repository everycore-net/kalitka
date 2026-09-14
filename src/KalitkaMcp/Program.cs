using KalitkaMcp;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

// The control-plane MCP server: an AI talks to Kalitka itself (request access, poll, end a
// session) — never approve. stdio is the first transport, not an architectural boundary: the
// tools and the Core client are transport-agnostic, so an HTTP/OAuth transport slots in later.
var builder = Host.CreateApplicationBuilder(args);

// The stdio transport owns stdout for JSON-RPC framing — any log line on stdout corrupts the
// protocol, so send every log to stderr instead.
builder.Logging.ClearProviders();
builder.Logging.AddConsole(o => o.LogToStandardErrorThreshold = LogLevel.Trace);

builder.Services.Configure<McpConfig>(builder.Configuration.GetSection("Kalitka"));

// One signing key for the process — loaded (or created) once from the configured path.
builder.Services.AddSingleton(sp =>
    SigningKey.LoadOrCreate(sp.GetRequiredService<IOptions<McpConfig>>().Value.KeyPath));

builder.Services.AddHttpClient<CoreClient>((sp, http) =>
{
    http.BaseAddress = new Uri(sp.GetRequiredService<IOptions<McpConfig>>().Value.CoreUrl);
    http.Timeout = TimeSpan.FromSeconds(30);
});

builder.Services
    .AddMcpServer()
    .WithStdioServerTransport()
    .WithTools<KalitkaTools>();

await builder.Build().RunAsync();
