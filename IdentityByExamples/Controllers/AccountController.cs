using System.Security.Claims;
using AutoMapper;
using IdentityByExamples.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using EmailService;
using Microsoft.AspNetCore.Authentication;

namespace IdentityByExamples.Controllers
{
    public class AccountController : Controller
    {
        private readonly IMapper _mapper;
        private readonly IEmailSender _emailSender;
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;

        public AccountController(IMapper mapper, IEmailSender emailSender, UserManager<User> userManager, SignInManager<User> signInManager)
        {
            _mapper = mapper;
            _emailSender = emailSender;
            _userManager = userManager;
            _signInManager = signInManager;
        }

        [HttpGet] public IActionResult Register() => View();

        [HttpGet] public IActionResult SuccessRegistration() => View();

        [HttpGet] public IActionResult Error() => View();

        [HttpGet] public IActionResult ForgotPassword() => View();

        [HttpGet] public IActionResult ResetPasswordConfirmation() => View();

        public IActionResult ForgotPasswordConfirmation() => View();

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(UserRegistrationModel userModel)
        {
            if (!ModelState.IsValid)
                return View(model: userModel);

            var user = _mapper.Map<User>(source: userModel);

            var result = await _userManager.CreateAsync(user: user, password: userModel.Password);
            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                    ModelState.TryAddModelError(key: error.Code, errorMessage: error.Description);

                return View(model: userModel);
            }

            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user: user);
            var confirmationLink = Url.Action(action: nameof(ConfirmEmail), controller: "Account", values: new { token, email = user.Email }, protocol: Request.Scheme);

            var message = new Message(to: new[] { user.Email }, subject: "Confirmation email link", content: confirmationLink, attachments: null);
            await _emailSender.SendEmailAsync(message: message);

            await _userManager.AddToRoleAsync(user: user, role: "Visitor");

            return RedirectToAction(actionName: nameof(SuccessRegistration));
        }

        [HttpGet]
        public async Task<IActionResult> ConfirmEmail(string token, string email)
        {
            var user = await _userManager.FindByEmailAsync(email: email);
            if (user == null)
                return View(viewName: "Error");

            var result = await _userManager.ConfirmEmailAsync(user: user, token: token);
            return View(viewName: result.Succeeded ? nameof(ConfirmEmail) : "Error");
        }

        [HttpGet]
        public IActionResult Login(string returnUrl = null)
        {
            ViewData[index: "ReturnUrl"] = returnUrl;
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(UserLoginModel userModel, string returnUrl = null)
        {
            if (!ModelState.IsValid)
                return View(model: userModel);

            var result = await _signInManager.PasswordSignInAsync(userName: userModel.Email, password: userModel.Password, isPersistent: userModel.RememberMe, lockoutOnFailure: true);
            if (result.Succeeded)
                return RedirectToLocal(returnUrl: returnUrl);

            if (result.RequiresTwoFactor)
                return RedirectToAction(actionName: nameof(LoginTwoStep), routeValues: new { userModel.Email, userModel.RememberMe, returnUrl });

            if (result.IsLockedOut)
            {
                var forgotPassLink = Url.Action(action: nameof(ForgotPassword), controller: "Account", values: new { }, protocol: Request.Scheme);
                var content = string.Format(format: "Your account is locked out, to reset your password, please click this link: {0}", arg0: forgotPassLink);

                var message = new Message(to: new[] { userModel.Email }, subject: "Locked out account information", content: content, attachments: null);
                await _emailSender.SendEmailAsync(message: message);

                ModelState.AddModelError(key: "", errorMessage: "The account is locked out");
                return View();
            }

            ModelState.AddModelError(key: "", errorMessage: "Invalid Login Attempt");
            return View();
        }

        /*
         * TwoFactorEnabled of the User should be 1 or true
         */

        [HttpGet]
        public async Task<IActionResult> LoginTwoStep(string email, bool rememberMe, string returnUrl = null)
        {
            var user = await _userManager.FindByEmailAsync(email: email);
            if (user == null)
                return View(viewName: nameof(Error));

            var providers = await _userManager.GetValidTwoFactorProvidersAsync(user: user);
            if (!providers.Contains(item: "Email"))
                return View(viewName: nameof(Error));

            var token = await _userManager.GenerateTwoFactorTokenAsync(user: user, tokenProvider: "Email");

            var message = new Message(to: new[] { email }, subject: "Authentication token", content: token, attachments: null);
            await _emailSender.SendEmailAsync(message: message);

            ViewData[index: "ReturnUrl"] = returnUrl;
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LoginTwoStep(TwoStepModel twoStepModel, string returnUrl = null)
        {
            if (!ModelState.IsValid)
                return View(model: twoStepModel);

            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
                return RedirectToAction(actionName: nameof(Error));

            var result = await _signInManager.TwoFactorSignInAsync(provider: "Email", code: twoStepModel.TwoFactorCode, isPersistent: twoStepModel.RememberMe, rememberClient: false);
            if (result.Succeeded)
                return RedirectToLocal(returnUrl: returnUrl);

            if (result.IsLockedOut)
            {
                //TODO: Same logic as in the Login action
                ModelState.AddModelError(key: "", errorMessage: "The account is locked out");
                return View();
            }

            ModelState.AddModelError(key: "", errorMessage: "Invalid Login Attempt");
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();

            return RedirectToAction(actionName: nameof(HomeController.Index), controllerName: "Home");
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordModel forgotPasswordModel)
        {
            if (!ModelState.IsValid)
                return View(model: forgotPasswordModel);

            var user = await _userManager.FindByEmailAsync(email: forgotPasswordModel.Email);
            if (user == null)
                return RedirectToAction(actionName: nameof(ForgotPasswordConfirmation));

            var token = await _userManager.GeneratePasswordResetTokenAsync(user: user);
            var callback = Url.Action(action: nameof(ResetPassword), controller: "Account", values: new { token, email = user.Email }, protocol: Request.Scheme);

            var message = new Message(to: new[] { user.Email }, subject: "Reset password token", content: callback, attachments: null);
            await _emailSender.SendEmailAsync(message: message);

            return RedirectToAction(actionName: nameof(ForgotPasswordConfirmation));
        }

        [HttpGet]
        public IActionResult ResetPassword(string token, string email)
        {
            var model = new ResetPasswordModel() { Token = token, Email = email };
            return View(model: model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordModel resetPasswordModel)
        {
            if (!ModelState.IsValid) return View(model: resetPasswordModel);

            var user = await _userManager.FindByEmailAsync(email: resetPasswordModel.Email);
            if (user == null)
                RedirectToAction(actionName: nameof(ResetPasswordConfirmation));

            var resetPassResult =
                await _userManager.ResetPasswordAsync(user: user, token: resetPasswordModel.Token, newPassword: resetPasswordModel.Password);

            if (resetPassResult.Succeeded) return RedirectToAction(actionName: nameof(ResetPasswordConfirmation));

            foreach (var error in resetPassResult.Errors)
                ModelState.TryAddModelError(key: error.Code, errorMessage: error.Description);

            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult ExternalLogin(string provider, string returnUrl = null)
        {
            var redirectUrl = Url.Action(action: nameof(ExternalLoginCallback), controller: "Account", values: new { returnUrl });
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider: provider, redirectUrl: redirectUrl);

            return Challenge(properties: properties, provider);
        }

        [HttpGet]
        public async Task<IActionResult> ExternalLoginCallback(string returnUrl = null)
        {
            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
                return RedirectToAction(actionName: nameof(Login));

            var signInResult =
                await _signInManager.ExternalLoginSignInAsync(loginProvider: info.LoginProvider, providerKey: info.ProviderKey, isPersistent: false,
                    bypassTwoFactor: true);
            if (signInResult.Succeeded)
                return RedirectToLocal(returnUrl: returnUrl);

            if (signInResult.IsLockedOut)
                return RedirectToAction(actionName: nameof(ForgotPassword));
            else
            {
                ViewData[index: "ReturnUrl"] = returnUrl;
                ViewData[index: "Provider"] = info.LoginProvider;
                var email = info.Principal.FindFirstValue(claimType: ClaimTypes.Email);

                return View(viewName: "ExternalLogin", model: new ExternalLoginModel { Email = email });
            }
        }

        [HttpPost]
        [AutoValidateAntiforgeryToken]
        public async Task<IActionResult> ExternalLoginConfirmation(ExternalLoginModel model, string returnUrl = null)
        {
            if (!ModelState.IsValid)
                return View(model: model);

            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
                return View(viewName: nameof(Error));

            var user = await _userManager.FindByEmailAsync(email: model.Email);
            IdentityResult result;

            if (user != null)
            {
                result = await _userManager.AddLoginAsync(user: user, login: info);
                if (result.Succeeded)
                {
                    await _signInManager.SignInAsync(user: user, isPersistent: false);
                    return RedirectToLocal(returnUrl: returnUrl);
                }
            }
            else
            {
                model.Principal = info.Principal;
                user = _mapper.Map<User>(source: model);
                result = await _userManager.CreateAsync(user: user);
                if (result.Succeeded)
                {
                    //TODO: Send an email for the email confirmation and add a default role as in the Register action
                    await _signInManager.SignInAsync(user: user, isPersistent: false);
                    return RedirectToLocal(returnUrl: returnUrl);
                }
            }

            foreach (var error in result.Errors)
            {
                ModelState.TryAddModelError(key: error.Code, errorMessage: error.Description);
            }

            return View(viewName: nameof(ExternalLogin), model: model);
        }

        private IActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(url: returnUrl))
                return Redirect(url: returnUrl);

            return RedirectToAction(actionName: nameof(HomeController.Index), controllerName: "Home");
        }
    }
}