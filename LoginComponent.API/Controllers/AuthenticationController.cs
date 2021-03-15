using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using LoginComponent.API.Authentication;
using LoginComponent.API.Contracts.V1.Requests;
using LoginComponent.API.Contracts.V1.Responses;
using LoginComponent.API.Services;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using JwtRegisteredClaimNames = Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames;

namespace LoginComponent.API.Controllers
{
    [EnableCors(policyName: "mata")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _config;
        private readonly IDatabaseService _databaseService;

        public AuthenticationController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager,
            IConfiguration config, IDatabaseService databaseService)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _config = config;
            _databaseService = databaseService;
        }

        [HttpPost("api/login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            var authResult = await _databaseService.LoginAsync(model.Username, model.Password);

            if (authResult.Success)
            {
                return Ok(new LoginResponse()
                {
                    Success = true,
                    Messages = new[] {authResult.Token, authResult.RefreshToken} //0: Token, 1: RefreshToken
                });
            }

            return Unauthorized(new LoginResponse()
            {
                Success = false,
                Messages = new[] {"Failed to login !"}
            });
        }

        [HttpPost("api/register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            var userExists = await _userManager.FindByNameAsync(model.Username);

            if (userExists != null)
            {
                return StatusCode(StatusCodes.Status409Conflict,
                    new Response() {Status = "Failed", Errors = new[] {"User already exists"}});
            }

            var user = new IdentityUser()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username,
            };

            var result = await _userManager.CreateAsync(user, model.Password);

            if (!result.Succeeded)
            {
                return StatusCode(StatusCodes.Status500InternalServerError,
                    new Response() {Status = "Failed", Errors = new[] {"User creation has failed"}});
            }

            await AddUserToRole(model, user);

            return Ok(new Response() {Status = "Created", Errors = new[] {string.Empty}});
        }

        [HttpPost("/api/refresh")]
        public async Task<IActionResult> Refresh([FromBody] RefreshTokenRequest refreshTokenRequest)
        {
            var authResponse =
                await _databaseService.RefreshTokenAsync(refreshTokenRequest.Token, refreshTokenRequest.RefreshToken);

            if (!authResponse.Success)
            {
                return BadRequest(new LoginResponse()
                {
                    Messages = authResponse.Errors
                });
            }

            return Ok(new LoginResponse()
            {
                Success = true,
                Messages = new[] {authResponse.Token, authResponse.RefreshToken} //0: Token, 1: RefreshToken
            });
        }


        private async Task AddUserToRole(RegisterModel model, IdentityUser user)
        {
            if (model.IsBroker) await _userManager.AddToRoleAsync(user, UserRoles.Broker);
            else await _userManager.AddToRoleAsync(user, UserRoles.Customer);
        }
    }
}