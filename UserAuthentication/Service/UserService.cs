using AutoMapper;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Text;
using UserAuthentication.Domain.Contracts;
using UserAuthentication.Domain.Entities;

namespace UserAuthentication.Service
{
    public class UserService : IUserService
    {
        private readonly ITokenService _tokenService;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<UserService> _logger;
        private readonly IMapper _mapper;
        private readonly ICurrentUserService _currentUserService;

        public UserService(ILogger<UserService> logger,UserManager<ApplicationUser> userManager,
            IMapper mapper, ITokenService tokenService, ICurrentUserService currentUserService) 
        {
            _logger = logger;
            _mapper = mapper;
            _userManager = userManager;
            _tokenService = tokenService;
            _currentUserService = currentUserService;   

        }    
        public async Task DeleteAsync(Guid id)
        {
            var user = await _userManager.FindByIdAsync(id.ToString());
            if (user is null)
            {
                _logger.LogError("User not found");
                throw new Exception("User not found");
            }
            await _userManager.DeleteAsync(user);
            _logger.LogInformation("User account deleted successfully.");
        }

        public async Task<UserResponse> GetByIdAsync(Guid id)
        {
            var user=await _userManager.FindByIdAsync(id.ToString());
            if(user is null)
            {
                _logger.LogError("User not found.");
                throw new Exception("User not found.");
            }
            _logger.LogInformation("User found.");
            return _mapper.Map<UserResponse>(user);
        }

        public async Task<CurrentUserResponse> GetCurrentUserAsync()
        {
            var user= await _userManager.FindByIdAsync(_currentUserService.GetUserId());
            if(user is null)
            {
                _logger.LogError("User not found.");
                throw new Exception("User not found.");
            }
            return _mapper.Map<CurrentUserResponse>(user);
        }

        public async Task<UserResponse> GetUserByEmailAsync(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user is null)
            {
                _logger.LogError("User not found.");
                throw new Exception("User not found.");
            }
            _logger.LogInformation("User found.");
            return _mapper.Map<UserResponse>(user);

        }

        public async Task<UserResponse> LoginAsync(UserLoginRequest loginRequest)
        {
            if(loginRequest is null) throw new ArgumentNullException(nameof(loginRequest)); 

            var user=await _userManager.FindByEmailAsync(loginRequest.Email);
            if (user is null || await _userManager.CheckPasswordAsync(user,loginRequest.Password)) 
            {
                _logger.LogError("Invalid email or password");
                throw new Exception("Email and/or password is incorrect.");
            }
             var accessToken=await _tokenService.GenerateToken(user);
            var refreshToken = _tokenService.GenerateRefreshToken();
            

            //Hash refreshToken  and store in the db or override the existing refresh token

            using var sha256 = SHA256.Create();
            var refreshTokenHash=sha256.ComputeHash(Encoding.UTF8.GetBytes(refreshToken));
            user.RefreshToken=Convert.ToBase64String(refreshTokenHash);
            user.RefreshTokenExpiryDate = DateTime.Now.AddDays(2);

            //update the user info in the db
            var result= await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
            {
                var errs = string.Join(", ", result.Errors.Select(x => x.Description));
                _logger.LogError($"Failed to Update User: {errs}");
                throw new Exception($"User update failed {errs}");
            }
            _logger.LogInformation("User logged in successfully");

            var userResponse= _mapper.Map<ApplicationUser,UserResponse>(user);
            userResponse.RefreshToken=refreshToken;
            userResponse.AccessToken = accessToken;
            return userResponse;

        }

        public async Task<CurrentUserResponse> RefreshTokenAsync(RefreshTokenRequest refreshTokenRequest)
        {
            _logger.LogInformation("..Refresh Token for an active User");
            using var sha256= SHA256.Create();
            var refreshTokenHash = sha256.ComputeHash(Encoding.UTF8.GetBytes(refreshTokenRequest.RefreshToken));
            var hashedRefreshToken = Convert.ToBase64String(refreshTokenHash);

            var user= await _userManager.Users.FirstOrDefaultAsync(u=>u.RefreshToken==hashedRefreshToken);
            if (user is null)
            {
                _logger.LogError("Invalid refresh token");
                throw new Exception("Invalid refresh token.");
            }
            if(user.RefreshTokenExpiryDate < DateTime.Now)
            {
                _logger.LogWarning($"Refresh Token expired for userId: {user.Id}");
                throw new Exception("Refresh token expired");
            }

            var newAccessToken = await _tokenService.GenerateToken(user);
            _logger.LogInformation("Access token generated successfully.");

            var currentUserponse = _mapper.Map<CurrentUserResponse>(user);
            currentUserponse.AccessToken = newAccessToken;
            return currentUserponse;

        }
        public async Task<RevokeRefreshTokenResponse> RevokeRefreshToken(RefreshTokenRequest refreshTokenRequest)
        {
            string userId = string.Empty;
            _logger.LogInformation("..Revoking Token..");
            try
            {
                using var sha256 = SHA256.Create();
                var refreshTokenHash = sha256.ComputeHash(Encoding.UTF8.GetBytes(refreshTokenRequest.RefreshToken));
                var hashedRefreshToken = Convert.ToBase64String(refreshTokenHash);

                var user = await _userManager.Users.FirstOrDefaultAsync(u => u.RefreshToken == hashedRefreshToken);
                if (user is null)
                {
                    _logger.LogError("Invalid refresh token");
                    throw new Exception("Invalid refresh token.");
                }
                userId = user.Id;
                if (user.RefreshTokenExpiryDate < DateTime.Now)
                {
                    _logger.LogWarning($"Refresh Token expired for userId: {user.Id}");
                    throw new Exception("Refresh token expired");
                }
                user.RefreshToken = null;
                user.RefreshTokenExpiryDate = null;

                var updateResult = await _userManager.UpdateAsync(user);
                if (!updateResult.Succeeded)
                {
                    var errs = string.Join(", ", updateResult.Errors.Select(x => x.Description));
                    _logger.LogError($"Failed to update user: {errs}");
                    return new RevokeRefreshTokenResponse
                    {
                        Message = "Failed to revoke refresh token"
                    };
                }
                _logger.LogInformation("Token revoked successfully");
                return new RevokeRefreshTokenResponse
                {
                    Message = "Refresh Token revoked successfully"
                };
            }
            catch (Exception ex)
            {

                _logger.LogWarning($"failed to revoke token for user with Id: {userId}");
                throw new Exception("Failed to revoke token");

            }

        }
        public async Task<UserResponse> RegisterAsync(UserRegisterRequest request)
        {
            _logger.LogInformation("Registering new User");
            var userExists=await _userManager.FindByEmailAsync(request.Email);
            if (userExists is not null)
            {
                _logger.LogError("Email already exists");
                throw new Exception("Email already exist.");
            }
            var newUser = _mapper.Map<ApplicationUser>(request);
                
            //Generate a unique userName
            newUser.UserName=GetUniqueUserName(request.FirstName,request.LastName);
            newUser.CreatedOn = DateTime.Now;
            var result=await _userManager.CreateAsync(newUser,request.Password);
            if (!result.Succeeded)
            {
                var errs = string.Join(", ", result.Errors.Select(x => x.Description));
                _logger.LogError($"New User creation failed: {errs}");
                throw new Exception("New User creation failed");
            }
            _logger.LogInformation("User created successfully");
            await _tokenService.GenerateToken(newUser);
            return _mapper.Map<UserResponse>(newUser);
        }

        

        public async Task<UserResponse> UpdateAsync(Guid id, UpdateUserRequest request)
        {
            var user = await _userManager.FindByIdAsync(id.ToString());
            if(user is null)
            {
                _logger.LogError("User not found");
                throw new Exception("User not found");
            }
            _mapper.Map(request,user);
            user.LastUpdatedOn = DateTime.Now;
            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
            {
                _logger.LogError("User update failed");
                throw new Exception("User update failed.");
            }
            _logger.LogInformation("Update successful.");
            return _mapper.Map<UserResponse>(user);
        }
        private string GetUniqueUserName(string firstName, string lastName)
        {
            var uniqueUserName = $"{firstName} {lastName}".ToLower();
            var userName = uniqueUserName;
            var count = 1;
            while(_userManager.Users.Any(u=>u.UserName== userName))
            {
                userName = $"{uniqueUserName} {count}";
                count++;
            }
            return userName;
        }
    }
}
