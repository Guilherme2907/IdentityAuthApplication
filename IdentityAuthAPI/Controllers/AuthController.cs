using IdentityAuthAPI.Extensions;
using IdentityAuthAPI.Interfaces;
using IdentityAuthAPI.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;

namespace IdentityAuthAPI.Controllers
{
    [Authorize]
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;

        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        [AllowAnonymous]
        [HttpPost("register")]
        public async Task<ActionResult> Register(RegisterUserViewModel registerUser)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest();
            }

            var response = await _authService.RegisterUser(registerUser);

            return Ok(response);
        }

        [AllowAnonymous]
        [HttpPost("login")]
        public async Task<ActionResult> Login(LoginUserViewModel loginUser)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest();
            }

            var response = await _authService.Login(loginUser);

            return Ok(response);
        }

        /// <summary>
        /// Endpoint para teste de autenticação e autorização 
        /// </summary>
        /// <param name="loginUser"></param>
        /// <returns></returns>
        [ClaimsAuthorize("Provider","Update")]
        [HttpGet("teste")]
        public ActionResult Teste()
        {
            return Ok("Teste");
        }
    }
}
