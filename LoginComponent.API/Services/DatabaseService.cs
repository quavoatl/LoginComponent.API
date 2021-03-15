using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using LoginComponent.API.Authentication;
using LoginComponent.API.Domain;
using LoginComponent.API.Options;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace LoginComponent.API.Services
{
    public class DatabaseService : IDatabaseService
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly JwtSettings _jwtSettings;
        private readonly TokenValidationParameters _tokenValidationParameters;
        private readonly UsersDbContext _dbContext;

        public DatabaseService(UserManager<IdentityUser> userManager, JwtSettings jwtSettings,
            TokenValidationParameters tokenValidationParameters, UsersDbContext dbContext)
        {
            _userManager = userManager;
            _jwtSettings = jwtSettings;
            _tokenValidationParameters = tokenValidationParameters;
            _dbContext = dbContext;
        }

        public async Task<AuthenticationResult> RefreshTokenAsync(string token, string refreshToken)
        {
            var validatedToken = GetPrincipalFromToken(token);

            if (validatedToken == null)
            {
                return new AuthenticationResult()
                {
                    Errors = new[] {"Invalid token"}
                };
            }

            var expiryDateUnix =
                long.Parse(validatedToken.Claims.SingleOrDefault(x => x.Type == JwtRegisteredClaimNames.Exp).Value);
            var expiryDateTimeUtc = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)
                .AddSeconds(expiryDateUnix);

            if (expiryDateTimeUtc > DateTime.UtcNow)
            {
                return new AuthenticationResult()
                {
                    Errors = new[] {"Current token has not expired yet"}
                };
            }

            var jti = validatedToken.Claims.SingleOrDefault(x => x.Type == JwtRegisteredClaimNames.Jti).Value;

            var storedRefreshToken = await _dbContext.RefreshTokens.SingleOrDefaultAsync(x => x.Token == refreshToken);

            if (storedRefreshToken == null)
            {
                return new AuthenticationResult()
                {
                    Errors = new[] {"This refresh token does not exist!"}
                };
            }

            if (DateTime.UtcNow > storedRefreshToken.ExpiryDate)
            {
                return new AuthenticationResult()
                {
                    Errors = new[] {"This refresh token has expired!"}
                };
            }

            if (storedRefreshToken.Invalidated)
            {
                return new AuthenticationResult()
                {
                    Errors = new[] {"This refresh token has been invalidated"}
                };
            }

            if (storedRefreshToken.Used)
            {
                return new AuthenticationResult()
                {
                    Errors = new[] {"This refresh token has been used"}
                };
            }

            if (storedRefreshToken.JwtJti != jti)
            {
                return new AuthenticationResult()
                {
                    Errors = new[] {"This refresh token does not match this JWT"}
                };
            }

            storedRefreshToken.Used = true;
            _dbContext.RefreshTokens.Update(storedRefreshToken);
            await _dbContext.SaveChangesAsync();

            var user = await _userManager.FindByIdAsync(
                validatedToken.Claims.SingleOrDefault(x => x.Type == "id").Value);
            return await GenerateAuthenticationResultForUser(user);
        }

        public async Task<AuthenticationResult> LoginAsync(string email, string password)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                return new AuthenticationResult()
                {
                    Success = false,
                    Errors = new[] {"Failed to login !"}
                };
            }

            var userHadValidPassword = await _userManager.CheckPasswordAsync(user, password);

            if (!userHadValidPassword)
            {
                return new AuthenticationResult()
                {
                    Success = false,
                    Errors = new[] {"Email/Password combination is wrong"}
                };
            }

            return await GenerateAuthenticationResultForUser(user);
        }


        #region Private Helpers

        private async Task<AuthenticationResult> GenerateAuthenticationResultForUser(IdentityUser user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_jwtSettings.Secret);

            var userRoles = await _userManager.GetRolesAsync(user);

            var authClaims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim("userId", user.Id)
            };

            foreach (var role in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, role));
            }

            // var token = new JwtSecurityToken(
            //     issuer: _config["JWT:ValidIssuer"],
            //     audience: _config["JWT:ValidAudience"],
            //     expires: DateTime.Now.AddHours(5),
            //     claims: authClaims,
            //     signingCredentials: new SigningCredentials(authSignInKey, SecurityAlgorithms.HmacSha256)
            // );

            var tokenDescriptor = new SecurityTokenDescriptor()
            {
                Subject = new ClaimsIdentity(authClaims),
                
                Issuer = _jwtSettings.ValidIssuer,
                Audience = _jwtSettings.ValidAudience,
                
                Expires = DateTime.UtcNow.Add(_jwtSettings.TokenLifetime),

                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);

            var refreshToken = new RefreshToken()
            {
                JwtJti = token.Id,
                UserId = user.Id,
                CreationDate = DateTime.UtcNow,
                ExpiryDate = DateTime.UtcNow.AddMonths(6)
            };

            await _dbContext.RefreshTokens.AddAsync(refreshToken);
            await _dbContext.SaveChangesAsync();

            return new AuthenticationResult
            {
                Success = true,
                Token = tokenHandler.WriteToken(token),
                RefreshToken = refreshToken.Token
            };
        }

        private ClaimsPrincipal GetPrincipalFromToken(string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            try
            {
                var principal = tokenHandler.ValidateToken(token, _tokenValidationParameters, out var validatedToken);

                if (!IsJwtWithValidSecurityAlgo(validatedToken))
                {
                    return null;
                }

                return principal;
            }
            catch
            {
                return null;
            }
        }

        private bool IsJwtWithValidSecurityAlgo(SecurityToken validatedToken)
        {
            return (validatedToken is JwtSecurityToken jwtSecurityToken) &&
                   jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256,
                       StringComparison.InvariantCultureIgnoreCase);
        }

        #endregion
    }
}