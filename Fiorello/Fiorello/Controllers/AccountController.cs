using EntityFrameworkProject.Enums;
using Fiorello.Models;
using Fiorello.Services.Interfaces;
using Fiorello.ViewModels;
using Fiorello.ViewModels.AccountVMs;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Data;

namespace Fiorello.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly SignInManager<AppUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IFileService _fileService;
        private readonly IEmailService _emailService;

        public AccountController(
            UserManager<AppUser> userManager,
            SignInManager<AppUser> signInManager,
            IFileService fileService,
            IEmailService emailService,
            RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _fileService = fileService;
            _emailService = emailService;
            _roleManager = roleManager;
        }

        public async Task<IActionResult> Update()
        {
            if (!User.Identity.IsAuthenticated)
                return RedirectToAction(nameof(Login));

            AppUser appUser = await _userManager.FindByNameAsync(User.Identity.Name);

            UpdateUserVM vm = new()
            {
                Name = appUser.Name,
                Surname = appUser.Surname,
                Username = appUser.UserName,
                Email = appUser.Email
            };

            return View(vm);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Update(UpdateUserVM request)
        {
            if (!ModelState.IsValid) return View(request);

            if (!User.Identity.IsAuthenticated)
                return RedirectToAction(nameof(Login));

            AppUser appUser = await _userManager.FindByNameAsync(User.Identity.Name);

            appUser.Name = request.Name;
            appUser.Surname = request.Surname;
            appUser.UserName = request.Username;
            appUser.Email = request.Email;

            IdentityResult result = await _userManager.UpdateAsync(appUser);

            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                    ModelState.AddModelError("", error.Description);

                return View(request);
            }

            if (request.OldPassword != null &&
                request.NewPassword != null &&
                request.ConfirmPassword != null)
            {
                IdentityResult passwordResult =
                    await _userManager.ChangePasswordAsync(
                        appUser,
                        request.OldPassword,
                        request.NewPassword);

                if (!passwordResult.Succeeded)
                {
                    foreach (var error in passwordResult.Errors)
                        ModelState.AddModelError("", error.Description);

                    return View(request);
                }

                await _userManager.UpdateSecurityStampAsync(appUser);
            }

            await _signInManager.SignOutAsync();
            return RedirectToAction(nameof(Login));
        }

        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterVM request)
        {
            if (!ModelState.IsValid) return View(request);

            AppUser appUser = new()
            {
                Name = request.Name,
                Surname = request.Surname,
                UserName = request.Username,
                Email = request.Email
            };

            IdentityResult result =
                await _userManager.CreateAsync(appUser, request.Password);

            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                    ModelState.AddModelError("", error.Description);

                return View(request);
            }

            await _userManager.AddToRoleAsync(appUser, Roles.Member.ToString());

            string token =
                await _userManager.GenerateEmailConfirmationTokenAsync(appUser);

            string confirmationLink = Url.Action(
                "ConfirmEmail",
                "Account",
                new { userId = appUser.Id, token },
                Request.Scheme);

            string emailBody =
                await _fileService.ReadFile("wwwroot/template/verify.html");

            emailBody = emailBody.Replace("{{link}}", confirmationLink);
            emailBody = emailBody.Replace("{{name}}", appUser.Name);
            emailBody = emailBody.Replace("{{surname}}", appUser.Surname);

            _emailService.Send(appUser.Email, "Confirm your email", emailBody);

            return RedirectToAction(nameof(CheckEmail));
        }

        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            AppUser appUser = await _userManager.FindByIdAsync(userId);

            if (appUser == null) return NotFound();

            IdentityResult result =
                await _userManager.ConfirmEmailAsync(appUser, token);

            if (!result.Succeeded)
                return BadRequest();

            await _userManager.UpdateSecurityStampAsync(appUser);

            return RedirectToAction(nameof(Login));
        }

        public IActionResult CheckEmail()
        {
            return View();
        }

        public IActionResult ForgetPassword()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgetPassword(ForgetPasswordVM request)
        {
            if (!ModelState.IsValid) return View(request);

            AppUser appUser =
                await _userManager.FindByEmailAsync(request.Email);

            if (appUser == null)
            {
                ModelState.AddModelError("", "User not found!");
                return View(request);
            }

            string token =
                await _userManager.GeneratePasswordResetTokenAsync(appUser);

            string resetLink = Url.Action(
                "ResetPassword",
                "Account",
                new { userId = appUser.Id, token },
                Request.Scheme);

            string emailBody =
                await _fileService.ReadFile("wwwroot/template/verify.html");

            emailBody = emailBody.Replace("{{link}}", resetLink);
            emailBody = emailBody.Replace("{{name}}", appUser.Name);
            emailBody = emailBody.Replace("{{surname}}", appUser.Surname);

            _emailService.Send(appUser.Email, "Reset your password", emailBody);

            return RedirectToAction(nameof(CheckEmail));
        }

        public IActionResult ResetPassword(string userId, string token)
        {
            ResetPasswordVM vm = new()
            {
                UserId = userId,
                Token = token
            };

            return View(vm);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordVM request)
        {
            if (!ModelState.IsValid) return View(request);

            AppUser appUser =
                await _userManager.FindByIdAsync(request.UserId);

            if (appUser == null)
            {
                ModelState.AddModelError("", "User not found!");
                return View(request);
            }

            bool samePassword =
                await _userManager.CheckPasswordAsync(appUser, request.NewPassword);

            if (samePassword)
            {
                ModelState.AddModelError("", "Cant assign Old Password!");
                return View(request);
            }

            IdentityResult result =
                await _userManager.ResetPasswordAsync(
                    appUser,
                    request.Token,
                    request.NewPassword);

            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                    ModelState.AddModelError("", error.Description);

                return View(request);
            }

            await _userManager.UpdateSecurityStampAsync(appUser);

            return RedirectToAction(nameof(Login));
        }

        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginVM request)
        {
            if (!ModelState.IsValid) return View(request);

            AppUser appUser =
                await _userManager.FindByNameAsync(request.UsernameOrEmail)
                ?? await _userManager.FindByEmailAsync(request.UsernameOrEmail);

            if (appUser == null)
            {
                ModelState.AddModelError("", "Username or Password wrong!");
                return View(request);
            }

            var result =
                await _signInManager.PasswordSignInAsync(
                    appUser,
                    request.Password,
                    false,
                    false);

            if (!result.Succeeded)
            {
                ModelState.AddModelError("", "Username or Password wrong!");
                return View(request);
            }

            return RedirectToAction("Index", "Home");
        }

        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Index", "Home");
        }

        public async Task<IActionResult> CreateRoles()
        {
            foreach (var role in Enum.GetValues<Roles>())
            {
                if (!await _roleManager.RoleExistsAsync(role.ToString()))
                {
                    await _roleManager.CreateAsync(
                        new IdentityRole { Name = role.ToString() });
                }
            }

            return Json("Roles created");
        }
    }
}
