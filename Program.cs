using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Data.SqlClient;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

// Swagger / OpenAPI
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    // Adds an "Authorize" button in Swagger for X-API-Token
    c.AddSecurityDefinition("ApiToken", new OpenApiSecurityScheme
    {
        Type = SecuritySchemeType.ApiKey,
        Name = "X-API-Token",
        In = ParameterLocation.Header,
        Description = "API token required for protected endpoints"
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "ApiToken"
                }
            },
            Array.Empty<string>()
        }
    });
});

var app = builder.Build();

app.Use(async (context, next) =>
{
    var request = context.Request;

    app.Logger.LogInformation(
        "Incoming request: {Method} {Path}{Query}",
        request.Method,
        request.Path,
        request.QueryString
    );

    await next();
});


if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// Read expected token from configuration
var expectedToken = builder.Configuration["ApiToken"] ?? "";
var connectionString = builder.Configuration.GetConnectionString("Mankiflow")
    ?? "Server=mhfssqltest;Database=Mankiflow;Trusted_Connection=True;TrustServerCertificate=True;";

await EnsureMfMagellanTableAsync(connectionString);

// Token-check middleware (only for /mfrequest)
app.Use(async (context, next) =>
{
    if (context.Request.Path.StartsWithSegments("/mfrequest"))
    {
        if (!context.Request.Headers.TryGetValue("X-API-Token", out var provided))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsJsonAsync(new { error = "Missing API token" });
            return;
        }

        var a = System.Text.Encoding.UTF8.GetBytes(provided.ToString());
        var b = System.Text.Encoding.UTF8.GetBytes(expectedToken);

        if (a.Length != b.Length || !CryptographicOperations.FixedTimeEquals(a, b))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsJsonAsync(new { error = "Invalid API token" });
            return;
        }
    }

    await next();
});

app.MapPost("/mfrequest", async (JsonElement payload) =>
{
    var payloadAsJson = payload.GetRawText();
    await SaveMfRequestAsync(connectionString, payloadAsJson);

    app.Logger.LogInformation("Incoming mfrequest stored in mfMagellan");
    return Results.Ok(new
    {
        status = "Mankiflow sagt Danke",
        received = payload
    });
});

//// Your protected mfrequest endpoint
//app.MapPost("/mfrequest", (MFRequest payload) =>
//{
//    // TODO: store/process payload here
//    return Results.Ok(new { status = "ok", received = payload });
//})
//.WithName("MFRequest")
//.WithOpenApi();

app.Run();

//public record MFRequest(string Source, double Value, DateTime Timestamp);

static async Task EnsureMfMagellanTableAsync(string connectionString)
{
    const string ensureTableSql =
        """
        IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'mfMagellan' AND schema_id = SCHEMA_ID('dbo'))
        BEGIN
            CREATE TABLE dbo.mfMagellan
            (
                Id INT IDENTITY(1,1) PRIMARY KEY,
                Payload NVARCHAR(MAX) NOT NULL
            );
        END
        """;

    await using var connection = new SqlConnection(connectionString);
    await connection.OpenAsync();

    await using var cmd = new SqlCommand(ensureTableSql, connection);
    await cmd.ExecuteNonQueryAsync();
}

static async Task SaveMfRequestAsync(string connectionString, string payloadAsJson)
{
    const string insertSql = "INSERT INTO dbo.mfMagellan (Payload) VALUES (@payload);";

    await using var connection = new SqlConnection(connectionString);
    await connection.OpenAsync();

    await using var cmd = new SqlCommand(insertSql, connection);
    cmd.Parameters.AddWithValue("@payload", payloadAsJson);
    await cmd.ExecuteNonQueryAsync();
}
