using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using UserAuthentication.Domain.Contracts;
using UserAuthentication.Service;

namespace UserAuthentication.Controllers
{
    [Route("api/userauth")]
    [ApiController]
    public class UserAuthenticationController : ControllerBase
    {
        private readonly IUserService _userService;

        public UserAuthenticationController(IUserService userService)
        {
            _userService = userService;
        }
        [HttpPost("register")]
        [AllowAnonymous]
        public async Task<IActionResult> Register([FromBody] UserRegisterRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            var result = await _userService.RegisterAsync(request);
            if (result is null)
            {
                return BadRequest("User registeration failed");
            }

            return Ok(result);
        }

        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromBody] UserLoginRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            var result = await _userService.LoginAsync(request);
            if (result is null)
            {
                return BadRequest("Login failed");
            }
            return Ok(result);
        }
        [HttpPost("refresh-token")]
        [Authorize]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            var response = await _userService.RefreshTokenAsync(request);
            return Ok(response);

        }
        [HttpPost("revoke-refresh-token")]
        [Authorize]
        public async Task<IActionResult> RevokeRefreshToken([FromBody] RefreshTokenRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            var response = await _userService.RevokeRefreshToken(request);
            if (response is not null && response.Message.ToLower() == "refresh token revoked successfully")
            {
                return Ok(response);
            }
            return BadRequest(response);
        }
        [HttpPost("forgot-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordRequest req)
        {
            if (string.IsNullOrEmpty(req.Email))
            {
                return BadRequest("Email address is required.");
            }
            var result=await _userService.ForgotPasswordAsync(req.Email);
            if(result.responseCode==StatusCodes.Status200OK) 
                return Ok(result);
            return BadRequest(result);
        }
        [HttpPost("verify-email")]
        [AllowAnonymous]
        public async Task<IActionResult> VerifyEmail([FromBody] VerifyEmailRequest request)
        {
            if (ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            var result = await _userService.EmailVerificationAsync(request);
            if (result.responseCode == StatusCodes.Status200OK)
                return Ok(result);
            return BadRequest(result);
        }
        [Route(("reset-password"))]
        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            var result = await _userService.ResetPasswordAsync(request);
            if (result.responseCode == StatusCodes.Status200OK)
                return Ok(result);
            return BadRequest(result);
        }

        [HttpGet("getById")]
        [Authorize]
        public async Task<IActionResult> GetUserById(Guid id)
        {
            var response = await _userService.GetByIdAsync(id);
            return Ok(response);

        }
        [HttpGet("getByEmail")]
        [Authorize]
        public async Task<IActionResult> GetUserByEmail(string email)
        {
            var response = await _userService.GetUserByEmailAsync(email);
            return Ok(response);

        }
        [HttpGet("getCurrentUser")]
        [Authorize]
        public async Task<IActionResult> GetCurrentUser()
        {
            var response = await _userService.GetCurrentUserAsync();
            return Ok(response);

        }
        [HttpDelete("DeleteUser")]
        [Authorize]
        public async Task<IActionResult> DeleteUser(Guid id)
        {
            await _userService.DeleteAsync(id);
            return Ok("User account deleted successfully.");

        }
        [HttpPost("confirm-email")]
        [AllowAnonymous]
        public async Task<IActionResult> ConfirmEmail(string email, string token)
        {
            var result=await _userService.ConfirmEmail(email, token);
            if (result.responseCode == StatusCodes.Status200OK)
            {
                return Ok(result);
            }
            else if (result.responseCode == StatusCodes.Status404NotFound)
            {
                return NotFound(result);
            }
            else 
                return BadRequest(result);

        }

    }
}
