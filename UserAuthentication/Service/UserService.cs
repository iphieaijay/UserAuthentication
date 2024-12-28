using AutoMapper;
using Microsoft.AspNetCore.Identity;
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


        }

        public Task<RevokeRefreshTokenResponse> RevokeRefreshToken(RefreshTokenRequest refreshTokenRequest)
        {
            throw new NotImplementedException();
        }

        public Task<UserResponse> UpdateAsync(Guid id, UpdateUserRequest request)
        {
            throw new NotImplementedException();
        }
        private string GetUniqueUserName(string firstName, string lastName)
        {
            var userName = $"{firstName} {lastName}".ToLower();
            
        }
    }
}
