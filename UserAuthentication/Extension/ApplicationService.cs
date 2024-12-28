using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using UserAuthentication.Domain.Contracts;
using UserAuthentication.Domain.Entities;
using UserAuthentication.Infrastructure.Context;

namespace UserAuthentication.Extension
{
    public static partial class ApplicationService
    {
        public static void ConfigureCors(this IServiceCollection services)
        {
            services.AddCors(opt =>
            {
                opt.AddPolicy("CorsPolicy", builder =>
                {
                    builder.AllowAnyOrigin()
                    .AllowAnyMethod()
                    .AllowAnyHeader();
                });
            });
        }

        public static void ConfigureIdentity(this IServiceCollection services)
        {
            services.AddIdentityCore<IdentityUser>(o =>
            {
                o.Password.RequireNonAlphanumeric = false;
                o.Password.RequireDigit = true;
                o.Password.RequireLowercase = true;
                o.Password.RequireUppercase = true;
                o.Password.RequiredLength = 8;
            }).AddEntityFrameworkStores<ApplicationDbContext>()
            .AddDefaultTokenProviders();
        }

        public static void ConfigureJwt(this IServiceCollection services, IConfiguration config)
        {
            var jwtSetting = config.GetSection("JwtSetting:").Get<JwtSettings>();
            var key = jwtSetting is not null ? jwtSetting.Key : null;
            if (jwtSetting is null || string.IsNullOrEmpty(key))
            {
                throw new InvalidOperationException("Jwt secret key is not configured.");
            }
            var secretKey=new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSetting.Key));
            services.AddAuthentication(o =>
            {
                o.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                o.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            }).AddJwtBearer(o =>
            {
                o.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = jwtSetting.Key,
                    ValidAudience = jwtSetting.ValidAudience,
                    IssuerSigningKey = secretKey
                };
                o.Events = new JwtBearerEvents
                {
                    OnChallenge= context =>
                    {
                        context.HandleResponse();
                        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                        context.Response.ContentType = "application/json";
                        var result=System.Text.Json.JsonSerializer.Serialize(
                            new
                            {
                                message="You are not authorized to access this resource. Please authenticate."
                            });
                        return context.Response.WriteAsync(result);
                    }
                };
            });

        }
    }
}
