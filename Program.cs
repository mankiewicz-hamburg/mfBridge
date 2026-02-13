using System.Security.Cryptography;
using System.Text;
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
    await SaveMfRequestAsync(connectionString, payload);

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
    await using var connection = new SqlConnection(connectionString);
    await connection.OpenAsync();

    await EnsureMfMagellanTableAsync(connection);
}

static async Task EnsureMfMagellanTableAsync(SqlConnection connection)
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

    await using var cmd = new SqlCommand(ensureTableSql, connection);
    await cmd.ExecuteNonQueryAsync();
}

static async Task SaveMfRequestAsync(string connectionString, JsonElement payload)
{
    var payloadAsJson = payload.GetRawText();

    await using var connection = new SqlConnection(connectionString);
    await connection.OpenAsync();

    await EnsureMfMagellanTableAsync(connection);

    var attributes = DeconstructPayload(payloadAsJson);
    await EnsureColumnsExistAsync(connection, attributes.Keys);

    var allColumns = new List<string> { "Payload" };
    allColumns.AddRange(attributes.Keys);

    var columnList = string.Join(", ", allColumns.Select(QuoteSqlIdentifier));
    var parameterNames = allColumns.Select((_, index) => $"@p{index}").ToList();
    var parameterList = string.Join(", ", parameterNames);
    var insertSql = $"INSERT INTO dbo.mfMagellan ({columnList}) VALUES ({parameterList});";

    await using var cmd = new SqlCommand(insertSql, connection);
    cmd.Parameters.AddWithValue(parameterNames[0], payloadAsJson);

    for (var i = 0; i < attributes.Count; i++)
    {
        var value = attributes.ElementAt(i).Value;
        cmd.Parameters.AddWithValue(parameterNames[i + 1], value is null ? DBNull.Value : value);
    }

    await cmd.ExecuteNonQueryAsync();
}

static Dictionary<string, string?> DeconstructPayload(string payloadAsJson)
{
    using var document = JsonDocument.Parse(payloadAsJson);

    if (document.RootElement.ValueKind != JsonValueKind.Object)
    {
        return new Dictionary<string, string?>
        {
            ["rootValue"] = document.RootElement.ToString()
        };
    }

    var result = new Dictionary<string, string?>();
    foreach (var property in document.RootElement.EnumerateObject())
    {
        AddJsonValueToResult(result, property.Name, property.Value);
    }

    return result;
}

static void AddJsonValueToResult(Dictionary<string, string?> target, string path, JsonElement value)
{
    var columnName = GetUniqueColumnName(target, ToColumnName(path));

    switch (value.ValueKind)
    {
        case JsonValueKind.Object:
            foreach (var nested in value.EnumerateObject())
            {
                AddJsonValueToResult(target, $"{path}_{nested.Name}", nested.Value);
            }
            return;
        case JsonValueKind.Array:
            target[columnName] = value.GetRawText();
            return;
        case JsonValueKind.Null:
        case JsonValueKind.Undefined:
            target[columnName] = null;
            return;
        default:
            target[columnName] = value.ToString();
            return;
    }
}

static string GetUniqueColumnName(Dictionary<string, string?> target, string columnName)
{
    if (!target.ContainsKey(columnName))
    {
        return columnName;
    }

    var suffix = 2;
    var candidate = $"{columnName}_{suffix}";
    while (target.ContainsKey(candidate))
    {
        suffix++;
        candidate = $"{columnName}_{suffix}";
    }

    return candidate;
}

static string ToColumnName(string key)
{
    var normalized = new string(key.Select(c => char.IsLetterOrDigit(c) ? c : '_').ToArray()).Trim('_');

    if (string.IsNullOrWhiteSpace(normalized))
    {
        normalized = "Field";
    }

    if (char.IsDigit(normalized[0]))
    {
        normalized = $"F_{normalized}";
    }

    if (normalized.Length > 120)
    {
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(key))).Substring(0, 6);
        normalized = $"{normalized[..113]}_{hash}";
    }

    return normalized;
}

static async Task EnsureColumnsExistAsync(SqlConnection connection, IEnumerable<string> desiredColumns)
{
    const string existingColumnsSql =
        "SELECT name FROM sys.columns WHERE object_id = OBJECT_ID('dbo.mfMagellan');";

    var existingColumns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    await using (var listColumnsCmd = new SqlCommand(existingColumnsSql, connection))
    await using (var reader = await listColumnsCmd.ExecuteReaderAsync())
    {
        while (await reader.ReadAsync())
        {
            existingColumns.Add(reader.GetString(0));
        }
    }

    foreach (var column in desiredColumns.Distinct(StringComparer.OrdinalIgnoreCase))
    {
        if (existingColumns.Contains(column))
        {
            continue;
        }

        var addColumnSql = $"ALTER TABLE dbo.mfMagellan ADD {QuoteSqlIdentifier(column)} NVARCHAR(MAX) NULL;";
        await using var addColumnCmd = new SqlCommand(addColumnSql, connection);
        await addColumnCmd.ExecuteNonQueryAsync();
        existingColumns.Add(column);
    }
}

static string QuoteSqlIdentifier(string identifier) => $"[{identifier.Replace("]", "]]", StringComparison.Ordinal)}]";
