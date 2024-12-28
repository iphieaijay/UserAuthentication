using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using UserAuthentication.Domain.Contracts;
using UserAuthentication.Domain.Entities;

namespace UserAuthentication.Service
{
    public class TokenService : ITokenService
    {
        private readonly SymmetricSecurityKey _secretkey;
        private readonly string? _validIssuer, _validAudience;
        private readonly double _expires;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<TokenService> _logger;
        private readonly IConfiguration _config;
        public TokenService(IConfiguration configuration,UserManager<ApplicationUser> userManager, ILogger<TokenService> logger)
        {
            _logger = logger;
            _config = configuration;
            _userManager = userManager;
            var jwtSettings = _config.GetSection("JwtSettings").Get<JwtSettings>();

            if (jwtSettings is null)
            {
                throw new InvalidOperationException("JWT Secret key is not configured.");
            }

            _secretkey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.Key));
            _validIssuer = jwtSettings.ValidIssuer;
            _validAudience = jwtSettings.ValidAudience;
            _expires = jwtSettings.Expires;

        }
        public string GenerateRefreshToken()
        {
            var randNuum = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randNuum);
            var refreshToken=Convert.ToBase64String(randNuum);
            return refreshToken;

        }

        public async Task<string> GenerateToken(ApplicationUser user)
        {
           var signInCred= new SigningCredentials(_secretkey,SecurityAlgorithms.HmacSha256);
            var claims=await GetCliams(user);
            var tokenOptions = GenerateTokenOptions(signInCred, claims);
            return new JwtSecurityTokenHandler().WriteToken(tokenOptions);
        }

        private JwtSecurityToken GenerateTokenOptions(SigningCredentials signingCredentials, List<Claim> claims)
        {
            return new JwtSecurityToken(
                issuer:_validIssuer,
                audience:_validAudience,
                claims:claims,
                expires:DateTime.Now.AddMinutes(_expires),
                signingCredentials:signingCredentials
                );
        }

        private async Task<List<Claim>> GetCliams(ApplicationUser user)
        {
            var claims = new List<Claim> {
                new Claim(ClaimTypes.NameIdentifier,user.Id),
                new Claim(ClaimTypes.Name,user?.UserName ?? string.Empty),
                new Claim(ClaimTypes.Email,user.Email),
                new Claim("FirstName",user.FirstName),
                new Claim("LastName", user.LastName),
                new Claim("Gender",user.Gender),
            };
            var roles = await _userManager.GetRolesAsync(user);
             claims.AddRange(roles.Select(role=>new Claim(ClaimTypes.Role, role)));
            
            return claims;
        }
    }
}
