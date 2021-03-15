using System.Threading.Tasks;
using LoginComponent.API.Domain;

namespace LoginComponent.API.Services
{
    public interface IDatabaseService
    {
        Task<AuthenticationResult> RefreshTokenAsync(string token, string refreshToken);
        Task<AuthenticationResult> LoginAsync(string email, string password);
    }
}