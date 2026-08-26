using System.Text.Json;
using System.Text.Json.Serialization;
using Amazon.CognitoIdentityProvider;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using Padi.Services.Authentication.Application.Abstractions;
using Padi.Services.Authentication.Application.Users;
using Padi.Services.Authentication.Infrastructure.Cognito;
using Padi.Services.Authentication.Infrastructure.Core;

namespace Padi.Services.Authentication.Api;

public sealed class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        ConfigureServices(builder);

        var app = builder.Build();

        Configure(app);

        app.Run();
    }

    private static void ConfigureServices(WebApplicationBuilder builder)
    {
        // API Gateway REST APIs use the v1 proxy payload. Running outside Lambda this is a
        // no-op and the app starts under Kestrel as usual.
        builder.Services.AddAWSLambdaHosting(LambdaEventSource.RestApi);

        var settings = ApiSettings.From(builder.Configuration);

        AddAuthentication(builder, settings);
        AddAuthorization(builder, settings);
        AddApplicationServices(builder, settings);

        builder.Services
            .AddControllers()
            .AddJsonOptions(options =>
            {
                // camelCase on the wire, matching the browser client and the rest of the
                // platform.
                options.JsonSerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
                options.JsonSerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
            });

        builder.Services.AddProblemDetails();
        builder.Services.AddExceptionHandler<DirectoryExceptionHandler>();
    }

    /// <summary>
    /// API Gateway's Cognito authorizer has already validated the token by the time a
    /// request arrives. Validating again here is deliberate: it keeps the API safe if it is
    /// ever reached directly — a test invoke, a future gateway misconfiguration — and it is
    /// what puts the claims on <c>HttpContext.User</c> for the policies below.
    /// </summary>
    private static void AddAuthentication(WebApplicationBuilder builder, ApiSettings settings)
    {
        builder.Services
            .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                options.Authority = settings.Issuer;
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuer = settings.Issuer,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    // Cognito access tokens carry client_id rather than aud, so the audience
                    // is checked by IssuedForClient instead.
                    ValidateAudience = false,
                };
            });
    }

    private static void AddAuthorization(WebApplicationBuilder builder, ApiSettings settings)
    {
        builder.Services.AddAuthorizationBuilder()
            .AddPolicy(Policies.Caller, policy => policy
                .RequireAuthenticatedUser()
                .AddRequirements(new IssuedForClient(settings.ClientId)))
            .AddPolicy(Policies.Administrator, policy => policy
                .RequireAuthenticatedUser()
                .AddRequirements(new IssuedForClient(settings.ClientId))
                .RequireAssertion(context => context.User.IsInCognitoGroup(settings.AdminGroup)));

        builder.Services.AddSingleton<IAuthorizationHandler, IssuedForClientHandler>();
    }

    private static void AddApplicationServices(WebApplicationBuilder builder, ApiSettings settings)
    {
        builder.Services.AddSingleton<IAmazonCognitoIdentityProvider>(
            _ => new AmazonCognitoIdentityProviderClient());

        builder.Services.AddSingleton<IUserAdministration, CognitoUserAdministration>();
        builder.Services.AddSingleton<IUserSelfService, CognitoUserSelfService>();
        builder.Services.AddSingleton<IUserRegistration, CognitoUserRegistration>();
        builder.Services.AddSingleton(new CognitoRegistrationOptions(settings.ClientId));
        builder.Services.AddSingleton<IIdentifierFactory, GuidIdentifierFactory>();
        builder.Services.AddSingleton<ChangeUsername>();
        builder.Services.AddSingleton<SetUserUsername>();
        builder.Services.AddSingleton<RegisterUser>();
        builder.Services.AddSingleton<IAuditLog, ConsoleAuditLog>();
        builder.Services.AddSingleton(new PoolContext(settings.UserPoolId, settings.AdminGroup));
    }

    private static void Configure(WebApplication app)
    {
        app.UseExceptionHandler();
        app.UseStatusCodePages();
        app.UseAuthentication();
        app.UseAuthorization();

        app.MapControllers();
    }
}
