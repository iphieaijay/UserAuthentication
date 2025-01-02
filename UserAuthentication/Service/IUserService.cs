using Microsoft.AspNetCore.Identity.Data;
using UserAuthentication.Domain.Contracts;

namespace UserAuthentication.Service
{
    public interface IUserService
    {
        Task<CustomResponse> RegisterAsync(UserRegisterRequest request);
        Task<CurrentUserResponse> GetCurrentUserAsync();
        Task<UserResponse> GetUserByEmailAsync(string email);
        Task<UserResponse> GetByIdAsync(Guid id);
        Task<UserResponse> UpdateAsync(Guid id, UpdateUserRequest request);
        Task DeleteAsync(Guid id);
        Task<RevokeRefreshTokenResponse> RevokeRefreshToken(RefreshTokenRequest refreshTokenRequest);
        Task<CurrentUserResponse> RefreshTokenAsync(RefreshTokenRequest refreshTokenRequest);
        Task<CustomResponse> LoginAsync(UserLoginRequest loginRequest);
        Task<CustomResponse> ConfirmEmail(string email, string code);
        Task<CustomResponse> ForgotPasswordAsync(string email);
        Task<CustomResponse> EmailVerificationAsync(VerifyEmailRequest request);
        Task<CustomResponse> ResetPasswordAsync(ResetPasswordRequest req);
    }
}
