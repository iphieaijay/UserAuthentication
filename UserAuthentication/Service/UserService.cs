using Microsoft.AspNetCore.Identity;
using UserAuthentication.Domain.Contracts;
using UserAuthentication.Domain.Entities;

namespace UserAuthentication.Service
{
    public class UserService : IUserService
    {
        public readonly ITokenService tokenService;
        public readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<UserService> _logger;

        public UserService(ILogger<UserService> logger,UserManager<ApplicationUser> userManager) { }    
        public Task DeleteAsync(Guid id)
        {
            throw new NotImplementedException();
        }

        public Task<UserResponse> GetByIdAsync(Guid id)
        {
            throw new NotImplementedException();
        }

        public Task<CurrentUserResponse> GetCurrentUserAsync()
        {
            throw new NotImplementedException();
        }

        public Task<UserResponse> GetUserByEmailAsync(string email)
        {
            throw new NotImplementedException();
        }

        public Task<UserResponse> LoginAsync(UserLoginRequest loginRequest)
        {
            throw new NotImplementedException();
        }

        public Task<CurrentUserResponse> RefreshTokenAsync(RefreshTokenRequest refreshTokenRequest)
        {
            throw new NotImplementedException();
        }

        public Task<UserResponse> RegisterAsync(UserRegisterRequest request)
        {
            throw new NotImplementedException();
        }

        public Task<RevokeRefreshTokenResponse> RevokeRefreshToken(RefreshTokenRequest refreshTokenRequest)
        {
            throw new NotImplementedException();
        }

        public Task<UserResponse> UpdateAsync(Guid id, UpdateUserRequest request)
        {
            throw new NotImplementedException();
        }
    }
}
