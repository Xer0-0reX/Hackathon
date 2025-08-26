using System.Web;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Builder;
using VulnerableWebApplication.VLAController;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpLogging;
using Microsoft.AspNetCore.HttpOverrides;
using VulnerableWebApplication.VLAModel;
using VulnerableWebApplication.VLAIdentity;
using VulnerableWebApplication.MidlWare;
using VulnerableWebApplication.TestCpu;
using VulnerableWebApplication.SecurityAnalysis;
using Microsoft.AspNetCore.OpenApi;
using GraphQL.Types;
using GraphQL;
using System.Net.Sockets;
using Microsoft.AspNetCore.Hosting;
using NLog;
using NLog.Web;


// Configuration du service 

var builder = WebApplication.CreateBuilder(args);

builder.Configuration
    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
    .AddJsonFile($"appsettings{builder.Environment.EnvironmentName}.json", optional: true, reloadOnChange: true)
    .AddEnvironmentVariables();

// Configuration de NLog
builder.Logging.ClearProviders();
builder.Logging.SetMinimumLevel(Microsoft.Extensions.Logging.LogLevel.Trace);
builder.Host.UseNLog();


// Swagger

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddAntiforgery();

// GraphQL

builder.Services.AddSingleton<IClientService, ClientService>();
builder.Services.AddSingleton<ClientDetailsType>();
builder.Services.AddSingleton<ClientQuery>();
builder.Services.AddSingleton<ISchema, ClientDetailsSchema>();
builder.Services.AddGraphQL(b => b.AddAutoSchema<ClientQuery>().AddSystemTextJson());

// Journalisation

builder.Configuration.AddJsonFile("appsettings.json", optional: false, reloadOnChange: true).AddJsonFile($"appsettings.{builder.Environment.EnvironmentName}.json", optional: true, reloadOnChange: true).AddEnvironmentVariables();
builder.Services.AddHttpLogging(logging =>
{
    logging.LoggingFields = HttpLoggingFields.All;
    logging.RequestHeaders.Add("X-Real-IP");
    logging.RequestBodyLogLimit = 4096;
    logging.ResponseBodyLogLimit = 4096;
    logging.CombineLogs = true;
});

// Configuration de l'application :

var app = builder.Build();
app.UseAntiforgery();
app.UseMiddleware<XRealIPMiddleware>();
app.UseMiddleware<ValidateJwtMiddleware>();
app.UseHttpLogging();
app.UseSwagger();
app.UseSwaggerUI();


// Variables :

VLAIdentity.SetSecret(app.Configuration["Secret"]);
VLAIdentity.SetLogFile(app.Configuration["LogFile"]);
VLAController.SetLogFile(app.Configuration["LogFile"]);


// Endpoints :

app.MapGet("/", async (string? lang) => await Task.FromResult(VLAController.VulnerableHelloWorld(HttpUtility.UrlDecode(lang))));

app.MapGet("/Contract", async (string i) => await Task.FromResult(VLAController.VulnerableXmlParser(HttpUtility.UrlDecode(i)))).WithOpenApi();

app.MapGet("/LocalWebQuery", async (string? i) => await VLAController.VulnerableWebRequest(i)).WithOpenApi();

app.MapGet("/Employee", async (string i) => await Task.FromResult(VLAController.VulnerableObjectReference(i))).WithOpenApi();

app.MapGet("/NewEmployee", async (string i) => await Task.FromResult(VLAController.VulnerableDeserialize(HttpUtility.UrlDecode(i)))).WithOpenApi();

app.MapGet("/LocalDNSResolver", async (string i) => await Task.FromResult(VLAController.VulnerableCmd(HttpUtility.UrlDecode(i)))).WithOpenApi();

app.MapPost("/Login", [ProducesResponseType(StatusCodes.Status200OK)] async (HttpRequest request, [FromBody] Creds login) => await Task.FromResult(VLAIdentity.VulnerableQuery(login.User, login.Passwd)).Result).WithOpenApi();

app.MapPost("/Invoice", async (Invoice request) => await Task.FromResult(VLAController.VulnerableLogic(request.Price, request.Qty, request.Owner, request.Client, request.Activity)).Result).WithOpenApi();

app.MapPatch("/Patch", async ([FromHeader(Name="X-Forwarded-For")] string h, [FromForm] IFormFile file) => await VLAController.VulnerableHandleFileUpload(file, h)).DisableAntiforgery().WithOpenApi();

// Security Analysis endpoint
app.MapGet("/SecurityAnalysis", async () => 
{
    try
    {
        var projectPath = Directory.GetCurrentDirectory();
        var vulnerabilities = SecurityAnalyzer.AnalyzeProject(projectPath);
        
        return Results.Ok(new 
        {
            TotalVulnerabilities = vulnerabilities.Count,
            Critical = vulnerabilities.Count(v => v.Severity.ToUpper() == "CRITICAL"),
            High = vulnerabilities.Count(v => v.Severity.ToUpper() == "HIGH"),
            Medium = vulnerabilities.Count(v => v.Severity.ToUpper() == "MEDIUM"),
            Low = vulnerabilities.Count(v => v.Severity.ToUpper() == "LOW"),
            Vulnerabilities = vulnerabilities
        });
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { Error = "Security analysis failed", Message = ex.Message });
    }
}).WithOpenApi();

// Security Analysis Web UI endpoint
app.MapGet("/SecurityAnalysisUI", async (HttpContext context) =>
{
    try
    {
        var projectPath = Directory.GetCurrentDirectory();
        var vulnerabilities = SecurityAnalyzer.AnalyzeProject(projectPath);
        
        var html = GenerateSecurityAnalysisHTML(vulnerabilities);
        
        context.Response.ContentType = "text/html; charset=utf-8";
        await context.Response.WriteAsync(html);
    }
    catch (Exception ex)
    {
        var errorHtml = $@"
        <html>
        <head><title>Security Analysis Error</title></head>
        <body>
            <h1>Error</h1>
            <p>Security analysis failed: {ex.Message}</p>
        </body>
        </html>";
        
        context.Response.ContentType = "text/html; charset=utf-8";
        await context.Response.WriteAsync(errorHtml);
    }
}).WithOpenApi();

app.UseGraphQL<ISchema>("/Client");

app.UseGraphQLPlayground("/GraphQLUI", new GraphQL.Server.Ui.Playground.PlaygroundOptions{GraphQLEndPoint="/Client",SubscriptionsEndPoint="/Client"});


// Arguments :

string url = args.FirstOrDefault(arg => arg.StartsWith("--url="));
string test = args.FirstOrDefault(arg => arg.StartsWith("--test"));

if(!string.IsNullOrEmpty(test))
{
    Console.WriteLine("Start CPU Testing");
    TestCpu.TestAffinity();
}

if (string.IsNullOrEmpty(url))
{
    app.Urls.Add("http://localhost:4000");
    app.Urls.Add("https://localhost:3000");
}
else app.Urls.Add(url.Substring("--url=".Length));

// Función para generar HTML del análisis de seguridad
string GenerateSecurityAnalysisHTML(List<SecurityVulnerability> vulnerabilities)
{
    var critical = vulnerabilities.Count(v => v.Severity.ToUpper() == "CRITICAL");
    var high = vulnerabilities.Count(v => v.Severity.ToUpper() == "HIGH");
    var medium = vulnerabilities.Count(v => v.Severity.ToUpper() == "MEDIUM");
    var low = vulnerabilities.Count(v => v.Severity.ToUpper() == "LOW");
    var total = vulnerabilities.Count;

    var vulnerabilityItems = string.Join("", vulnerabilities.Select(v => $@"
        <div class=""vulnerability-item severity-{v.Severity.ToLower()}"">
            <div class=""vulnerability-header"">
                <span class=""vulnerability-type"">{v.Type}</span>
                <span class=""severity-badge"" style=""background-color: {SecurityAnalyzer.GetSeverityColor(v.Severity)}"">
                    {v.Severity}
                </span>
            </div>
            <div class=""vulnerability-description"">
                <strong>Description:</strong> {v.Description}
            </div>
            <div class=""vulnerability-location"">
                <strong>File:</strong> {v.File} | <strong>Line:</strong> {v.LineNumber} | <strong>CWE:</strong> {v.CweId}
            </div>
            {(!string.IsNullOrEmpty(v.CodeSnippet) ? $@"<div class=""vulnerability-code"">Code: {System.Web.HttpUtility.HtmlEncode(v.CodeSnippet)}</div>" : "")}
            <div class=""vulnerability-recommendation"">
                <strong>Recommendation:</strong> {v.Recommendation}
            </div>
        </div>"));

    return $@"
<!DOCTYPE html>
<html lang=""en"">
<head>
    <meta charset=""UTF-8"">
    <meta name=""viewport"" content=""width=device-width, initial-scale=1.0"">
    <title>VLA Security Analysis</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .analysis-header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 8px; margin-bottom: 30px; text-align: center; }}
        .analysis-title {{ font-size: 2.5em; margin-bottom: 10px; font-weight: bold; }}
        .analysis-subtitle {{ font-size: 1.2em; opacity: 0.9; }}
        .stats-container {{ display: flex; gap: 20px; margin: 20px 0; flex-wrap: wrap; }}
        .stat-item {{ background: white; padding: 20px; border-radius: 8px; text-align: center; flex: 1; min-width: 150px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .stat-number {{ font-size: 2em; font-weight: bold; margin-bottom: 5px; }}
        .stat-label {{ color: #6b7280; font-size: 0.9em; }}
        .vulnerability-container {{ margin: 20px 0; background: #f8f9fa; border-radius: 8px; padding: 20px; }}
        .vulnerability-item {{ background: white; border-left: 5px solid #ccc; margin: 15px 0; padding: 15px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .severity-critical {{ border-left-color: #DC2626; }}
        .severity-high {{ border-left-color: #EA580C; }}
        .severity-medium {{ border-left-color: #D97706; }}
        .severity-low {{ border-left-color: #65A30D; }}
        .vulnerability-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }}
        .vulnerability-type {{ font-weight: bold; font-size: 1.1em; color: #1f2937; }}
        .severity-badge {{ padding: 4px 12px; border-radius: 20px; color: white; font-weight: bold; font-size: 0.85em; text-transform: uppercase; }}
        .vulnerability-description, .vulnerability-location, .vulnerability-recommendation {{ margin: 10px 0; }}
        .vulnerability-code {{ background: #1f2937; color: #f9fafb; padding: 12px; border-radius: 4px; font-family: monospace; margin: 10px 0; overflow-x: auto; }}
        .vulnerability-recommendation {{ background: #ecfdf5; border: 1px solid #a7f3d0; padding: 12px; border-radius: 4px; }}
        .refresh-btn {{ background: #3b82f6; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; font-size: 1em; margin-bottom: 20px; text-decoration: none; display: inline-block; }}
        .refresh-btn:hover {{ background: #2563eb; }}
    </style>
</head>
<body>
    <div class=""container"">
        <div class=""analysis-header"">
            <div class=""analysis-title"">VLA Security Analysis</div>
            <div class=""analysis-subtitle"">Vulnerability Detection & Code Analysis</div>
        </div>

        <a href=""/SecurityAnalysisUI"" class=""refresh-btn"">Refresh Analysis</a>

        <div class=""stats-container"">
            <div class=""stat-item"">
                <div class=""stat-number"" style=""color: #DC2626;"">{critical}</div>
                <div class=""stat-label"">Critical</div>
            </div>
            <div class=""stat-item"">
                <div class=""stat-number"" style=""color: #EA580C;"">{high}</div>
                <div class=""stat-label"">High</div>
            </div>
            <div class=""stat-item"">
                <div class=""stat-number"" style=""color: #D97706;"">{medium}</div>
                <div class=""stat-label"">Medium</div>
            </div>
            <div class=""stat-item"">
                <div class=""stat-number"" style=""color: #65A30D;"">{low}</div>
                <div class=""stat-label"">Low</div>
            </div>
            <div class=""stat-item"">
                <div class=""stat-number"" style=""color: #3b82f6;"">{total}</div>
                <div class=""stat-label"">Total Issues</div>
            </div>
        </div>

        <div class=""vulnerability-container"">
            <h3>Detected Vulnerabilities</h3>
            {vulnerabilityItems}
            {(vulnerabilities.Count == 0 ? @"<div style=""text-align: center; padding: 40px; color: #6b7280;""><h3>No Vulnerabilities Found</h3><p>Security scan completed successfully.</p></div>" : "")}
        </div>
    </div>
</body>
</html>";
}

// Lancement :

app.Run();
