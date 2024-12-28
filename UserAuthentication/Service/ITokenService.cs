using UserAuthentication.Domain.Entities;

namespace UserAuthentication.Service
{
    public interface ITokenService
    {
        public Task<string> GenerateToken(ApplicationUser user);
        string GenerateRefreshToken();
    }
}
