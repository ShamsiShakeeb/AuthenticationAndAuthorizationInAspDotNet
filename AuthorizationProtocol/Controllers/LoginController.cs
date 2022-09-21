using AuthorizationProtocol.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace AuthorizationProtocol.Controllers
{
    [AllowAnonymous]
    public class LoginController : Controller
    {
        private readonly SignInManager<IdentityUser> _signManager;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public LoginController(SignInManager<IdentityUser> signManager,
            UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager)
        {
            _signManager = signManager;
            _userManager = userManager;
            _roleManager = roleManager;
        }
        public IActionResult Index()
        {
            return View();
        }
        [Route("Auth/Login")]
        public IActionResult Login()
        {
            return View();
        }
        [Route("Auth/Login")]
        [HttpPost]
        public async Task<IActionResult> Login(LoginViewModel loginViewModel)
        {

            var login = await _signManager.PasswordSignInAsync(loginViewModel.UserName, loginViewModel.Password,true,false);
            if (login.Succeeded)
            {
                var user = await _userManager.FindByNameAsync(loginViewModel.UserName);
              //  var roles = await _userManager.GetRolesAsync(user);
                await _signManager.SignInAsync(user,true);
            } 
           
            //ClaimsIdentity identity = new ClaimsIdentity(new[] {
            // new Claim(ClaimTypes.Name,loginViewModel.UserName),
            // new Claim(ClaimTypes.Role,"Owner"),
            // new Claim(ClaimTypes.Role,"Chairmen")
            //}, CookieAuthenticationDefaults.AuthenticationScheme);

            //var principal = new ClaimsPrincipal(identity);
            //await HttpContext.SignInAsync("Owner", principal);

            return RedirectToAction(controllerName: "Home", actionName: "Index");
        }

        [Route("Auth/Registration")]
        public IActionResult Registration()
        {
            return View();
        }

        [Route("Auth/Registration")]
        [HttpPost]
        public async Task<IActionResult> Registration(RegistrationViewModel registrationViewModel)
        {
            var user = new IdentityUser()
            {
                UserName = registrationViewModel.UserName,
            };

            await _roleManager.CreateAsync(new IdentityRole("Owner"));
            await _roleManager.CreateAsync(new IdentityRole("Chairmen"));
          
            var result = await _userManager.CreateAsync(user, registrationViewModel.Password);

            if (!result.Succeeded)
            {
                foreach (var x in result.Errors) 
                {
                    ModelState.AddModelError(string.Empty,x.Description);
                }
                return View();
            }

            if (result.Succeeded)
            {
                await _userManager.AddToRoleAsync(user, "Owner");
                await _userManager.AddToRoleAsync(user, "Chairmen");
            }

            return Redirect("~/Auth/Login");
        }


    }
}
