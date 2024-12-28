using UserAuthentication.Domain.Contracts;

namespace UserAuthentication.Service
{
    public interface IUserService
    {
        Task<UserResponse> RegisterAsync(UserRegisterRequest request);
        Task<CurrentUserResponse> GetCurrentUserAsync();
        Task<UserResponse> GetUserByEmailAsync(string email);
        Task<UserResponse> GetByIdAsync(Guid id);
        Task<UserResponse> UpdateAsync(Guid id, UpdateUserRequest request);
        Task DeleteAsync(Guid id);
        Task<RevokeRefreshTokenResponse> RevokeRefreshToken(RefreshTokenRequest refreshTokenRequest);
        Task<CurrentUserResponse> RefreshTokenAsync(RefreshTokenRequest refreshTokenRequest);
        Task<UserResponse> LoginAsync(UserLoginRequest loginRequest);
    }
}
