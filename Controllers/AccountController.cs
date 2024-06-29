using ClaimAPI.Models;
using FullStack.API.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace FullStack.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : Controller
    {
        //userManager will hold the UserManager instance
        private readonly UserManager<IdentityUser> userManager;
        //signInManager will hold the SignInManager instance
        private readonly SignInManager<IdentityUser> signInManager;
        private readonly IConfiguration _config;
        private APIResponse response = new APIResponse();

        //Both UserManager and SignInManager services are injected into the AccountController
        //using constructor injection
        public AccountController(UserManager<IdentityUser> userManager,
            SignInManager<IdentityUser> signInManager, IConfiguration config,) 
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
            _config = config;
        }

        [HttpPost("Register")]
        public async Task<IActionResult> Register(RegisterModel model)
        {

            try
            {
                if (ModelState.IsValid)
                {
                    // Copy data from RegisterViewModel to IdentityUser
                    var user = new IdentityUser
                    {
                        UserName = model.Email,
                        Email = model.Email
                    };
                    // Store user data in AspNetUsers database table
                    var result = await userManager.CreateAsync(user, model.Password);
                    // If user is successfully created, sign-in the user using
                    // SignInManager and redirect to index action of HomeController
                    if (result.Succeeded)
                    {
                     
                        //await signInManager.SignInAsync(user, isPersistent: false);
                        return new JsonResult("Registration successfull !");
                    }
                    // If there are any errors, add them to the ModelState object
                    // which will be displayed by the validation summary tag helper
                    foreach (var error in result.Errors)
                    {
                        //ModelState.AddModelError(string.Empty, error.Description);
                        return new JsonResult(error.Description);
                    }
                }
                return new JsonResult("incorrect data !");
            }
            catch (Exception ex)
            {

                return new JsonResult(ex.Message);
            }
        }

        [HttpPost("Login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login(LoginModel model)
        {
            try
            {
                if (ModelState.IsValid)
                {
                    var result = await signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, lockoutOnFailure: false);

                    if (result.Succeeded)
                    {
                        response.status = 200;
                        response.ok = true;
                        response.data = result;
                        response.message = "User authenticated successfully!";

                        response.token = GenerateJSONWebToken(model);
                        // Handle successful login
                        // return new JsonResult("Login successfull !");
                        return Ok(response);
                    }
                    //if (result.RequiresTwoFactor)
                    //{
                    //    // Handle two-factor authentication case
                    //}
                    //if (result.IsLockedOut)
                    //{
                    //    // Handle lockout scenario
                    //}
                    else
                    {
                        // Handle failure
                        //ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                        return new JsonResult("Invalid login attempt.");
                    }
                }

                // If we got this far, something failed, redisplay form
                return new JsonResult("Invalid login attempt.");
            }
            catch (Exception ex)
            {
                return new JsonResult(ex.Message);
            }

        }

        [HttpPost("Logout")]
        public async Task<IActionResult> Logout()
        {
            try
            {
                await signInManager.SignOutAsync();
                return new JsonResult("signout successfull");
            }
            catch (Exception ex)
            {

               return new JsonResult(ex.Message);
            }
            
        }

        [HttpPost]
        public string GenerateJSONWebToken(LoginModel loginRequest)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[] {
            new Claim(JwtRegisteredClaimNames.Sub, loginRequest.Email),
            new Claim(JwtRegisteredClaimNames.Email, loginRequest.Email),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
              };

            var token = new JwtSecurityToken(_config["Jwt:Issuer"],
                _config["Jwt:Issuer"],
                claims,
                expires: DateTime.Now.AddMinutes(15),
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
