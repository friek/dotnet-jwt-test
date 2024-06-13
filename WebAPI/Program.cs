using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.AddSecurityDefinition(
        BearerTokenDefaults.AuthenticationScheme,
        new OpenApiSecurityScheme
        {
            In = ParameterLocation.Header,
            Description = "Please provide JWT with bearer (Bearer {jwt token})",
            Name = "Authorization",
            Type = SecuritySchemeType.ApiKey,
        });

    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                },
            },
            new List<string>()
        }
    });
});

builder.Services.AddAuthorization(options =>
{
    options.DefaultPolicy = new AuthorizationPolicyBuilder()
        .RequireClaim("preferred_username")
        // .RequireClaim("email_verified", "true")
        // .RequireRole(["grafana", "view-profile"])
        .Build();
});

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme,
        options =>
        {
            // The 'account' value is set in the JWT token by keycloak in the aud claim. It is necessary
            // as the token authenticator needs to verify this. I should find out if there are ways to
            // use multiple audiences
            options.Audience = "account";
            options.Authority = builder.Configuration["OIDC:Authority"];
            options.TokenValidationParameters = new TokenValidationParameters
            {
                // This indicates which claim contains the actual name of the user.
                // It can also be retrieved dynamically by creating a NameClaimTypeRetriever which returns the
                // name claim based on the actual JWT contents or the issuer
                NameClaimType = "preferred_username",
            };

            /*
            options.Events = new JwtBearerEvents
            {
                OnTokenValidated = context =>
                {
                    context.Principal.HasClaim("email_verified", "true");
                    return Task.CompletedTask;
                }
            };
        */
        })
    /*
    .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
    {
        // dotnet user-secrets set OIDC:ClientId
        options.ClientId = builder.Configuration["OIDC:ClientId"];
        // dotnet user-secrets set OIDC:ClientSecret
        options.ClientSecret = builder.Configuration["OIDC:ClientSecret"];
        options.ResponseType = OpenIdConnectResponseType.Code;
        options.ResponseMode = OpenIdConnectResponseMode.Query;

        // See appsettings.json
        options.Authority = builder.Configuration["OIDC:Authority"];

        options.GetClaimsFromUserInfoEndpoint = true;
        options.SaveTokens = true;

        options.Scope.Add("openid");
        options.Scope.Add("profile");
    })
    */
    ;


var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(options => options.EnableTryItOutByDefault());
}

app.UseHttpsRedirection();

// app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();