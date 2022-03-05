using IdentityAuthAPI.ViewModels;
using System.Threading.Tasks;

namespace IdentityAuthAPI.Interfaces
{
    public interface IAuthService
    {
        Task<LoginResponseViewModel> RegisterUser(RegisterUserViewModel registerUser);
        Task<LoginResponseViewModel> Login(LoginUserViewModel loginUser);
    }
}
