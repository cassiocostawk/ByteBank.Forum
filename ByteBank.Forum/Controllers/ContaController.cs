using ByteBank.Forum.Models;
using ByteBank.Forum.ViewModels;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace ByteBank.Forum.Controllers
{
    public class ContaController : Controller
    {
        private UserManager<UsuarioAplicacao> _userManager;
        public UserManager<UsuarioAplicacao> UserManager
        {
            get
            {
                if (_userManager == null)
                {
                    var contextOwin = HttpContext.GetOwinContext();
                    _userManager = contextOwin.GetUserManager<UserManager<UsuarioAplicacao>>();
                }
                return _userManager;
            }
            set
            {
                _userManager = value;
            }
        }

        private SignInManager<UsuarioAplicacao, string> _signInManager;
        public SignInManager<UsuarioAplicacao, string> SignInManager
        {
            get
            {
                if (_signInManager == null)
                {
                    var contextOwin = HttpContext.GetOwinContext();
                    _signInManager = contextOwin.GetUserManager<SignInManager<UsuarioAplicacao, string>>();
                }
                return _signInManager;
            }
            set
            {
                _signInManager = value;
            }
        }

        public IAuthenticationManager AuthenticationManager 
        {
            get
            {
                var contextoOwin = Request.GetOwinContext();
                return contextoOwin.Authentication;
            }

        }

        public ActionResult Registrar()
        {
            return View();
        }

        [HttpPost]
        public async Task<ActionResult> Registrar(ContaRegistrarViewModel modelo)
        {
            if (ModelState.IsValid)
            {
                var novoUsuario = new UsuarioAplicacao();

                novoUsuario.Email = modelo.Email;
                novoUsuario.UserName = modelo.UserName;
                novoUsuario.NomeCompleto = modelo.NomeCompleto;

                var usuario = await UserManager.FindByEmailAsync(modelo.Email);
                var usuarioJaExiste = usuario != null;

                if (usuarioJaExiste)
                {
                    return View("AguardandoConfirmacao");
                }

                var resultado = await UserManager.CreateAsync(novoUsuario, modelo.Senha);

                if (resultado.Succeeded)
                {
                    // Enviar email de confirmação
                    await EnviarEmailDeConfirmaçãoAsync(novoUsuario);

                    return View("AguardandoConfirmacao");
                }
                else
                {
                    AddErrors(resultado);
                }
            }

            // Erro de validação
            return View(modelo);
        }

        [HttpPost]
        public ActionResult RegistrarAuthExterna(string provider)
        {
            SignInManager.AuthenticationManager.Challenge(new AuthenticationProperties
            {
                RedirectUri = Url.Action("RegistrarAuthExternaCallback")
            },
            provider);

            return new HttpUnauthorizedResult();
        }

        public async Task<ActionResult> RegistrarAuthExternaCallback()
        {
            var loginInfo = await SignInManager.AuthenticationManager.GetExternalLoginInfoAsync();

            var usuarioExistente = await UserManager.FindByEmailAsync(loginInfo.Email);
            if (usuarioExistente != null)
                return View("Error");

            var novoUsuario = new UsuarioAplicacao();
            novoUsuario.Email = loginInfo.Email;
            novoUsuario.UserName = loginInfo.Email;
            novoUsuario.NomeCompleto = loginInfo.ExternalIdentity.FindFirstValue(loginInfo.ExternalIdentity.NameClaimType);

            var resultado = await UserManager.CreateAsync(novoUsuario);
            if (resultado.Succeeded)
            {
                var resultadoAddLoginInfo = await UserManager.AddLoginAsync(novoUsuario.Id, loginInfo.Login);

                if (resultadoAddLoginInfo.Succeeded)
                    return RedirectToAction("Index", "Home");
            }

            return View("Error");
        }

        private async Task EnviarEmailDeConfirmaçãoAsync(UsuarioAplicacao usuario)
        {
            var token = await UserManager.GenerateEmailConfirmationTokenAsync(usuario.Id);
            var linkDeCallback =
                Url.Action("ConfirmacaoEmail",
                           "Conta",
                           new { usuarioId = usuario.Id, token = token },
                           Request.Url.Scheme);

            await UserManager.SendEmailAsync(
                usuario.Id,
                "Fórum ByteBank - Confirmação de Email",
                $"Bem vindo ao fórum ByteBank, clique aqui {linkDeCallback} para confirmar seu email!");
        }

        public async Task<ActionResult> ConfirmacaoEmail(string usuarioId, string token)
        {
            if (usuarioId == null || token == null)
                return View("Error");

            var resultado = await UserManager.ConfirmEmailAsync(usuarioId, token);

            if (resultado.Succeeded)
                return RedirectToAction("Index", "Home");
            else
                return View("Error");
        }

        public async Task<ActionResult> Login()
        {
            return View();
        }

        [HttpPost]
        public async Task<ActionResult> Login(ContaLoginViewModel modelo)
        {
            if (ModelState.IsValid)
            {
                var usuario = await UserManager.FindByEmailAsync(modelo.Email);

                if (usuario == null)
                    return SenhaOuUsuarioInvalidos();

                var signInResultado = await SignInManager.PasswordSignInAsync(
                    usuario.UserName,
                    modelo.Senha,
                    isPersistent: modelo.ContinuarLogado,
                    shouldLockout: true);

                switch (signInResultado)
                {
                    case SignInStatus.Success:

                        if (!usuario.EmailConfirmed)
                        {
                            AuthenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);
                            return View("AguardandoConfirmacao");
                        }


                        return RedirectToAction("Index", "Home");
                    case SignInStatus.LockedOut:
                        var senhaCorreta = await UserManager.CheckPasswordAsync(usuario, modelo.Senha);

                        if (senhaCorreta)
                            ModelState.AddModelError("", "A conta está bloqueada!");
                        else
                            return SenhaOuUsuarioInvalidos();
                        break;
                    default:
                        return SenhaOuUsuarioInvalidos();
                }
            }

            // erro
            return View(modelo);
        }

        public ActionResult LoginAuthExterna(string provider)
        {
            SignInManager.AuthenticationManager.Challenge(new AuthenticationProperties
            {
                RedirectUri = Url.Action("LoginAuthExternaCallback")
            },
            provider);

            return new HttpUnauthorizedResult();
        }

        public async Task<ActionResult> LoginAuthExternaCallback()
        {
            var loginInfo = await SignInManager.AuthenticationManager.GetExternalLoginInfoAsync();
            var signInResultado = await SignInManager.ExternalSignInAsync(loginInfo, true);

            if (signInResultado == SignInStatus.Success)
                return RedirectToAction("Index", "Home");

            return View("Error");
        }

        public ActionResult EsqueciSenha()
        {
            return View();
        }

        [HttpPost]
        public async Task<ActionResult> EsqueciSenha(ContaEsqueciSenhaViewModel modelo)
        {
            if (ModelState.IsValid)
            {
                var usuario = await UserManager.FindByEmailAsync(modelo.Email);
                if (usuario != null)
                {
                    var token = await UserManager.GeneratePasswordResetTokenAsync(usuario.Id);

                    var linkDeCallback = Url.Action("ConfirmacaoAlteracaoSenha", "Conta", new { usuarioId = usuario.Id, token = token },
                        Request.Url.Scheme);

                    await UserManager.SendEmailAsync(usuario.Id, "Fórum ByteBank - Alteração de Senha", 
                        $"Clique aqui {linkDeCallback} para alterar a sua senha!");
                }

                return View("EmailAlteracaoSenhaEnviado");
            }

            return View();
        }

        public ActionResult ConfirmacaoAlteracaoSenha(string usuarioId, string token)
        {
            var modelo = new ContaConfirmacaoAlteracaoSenhaViewModel
            {
                UsuarioId = usuarioId,
                Token = token
            };

            return View(modelo);
        }

        [HttpPost]
        public async Task<ActionResult> ConfirmacaoAlteracaoSenha(ContaConfirmacaoAlteracaoSenhaViewModel modelo)
        {
            if (ModelState.IsValid)
            {
                var resultadoAlteracao = await UserManager.ResetPasswordAsync(modelo.UsuarioId, modelo.Token, modelo.NovaSenha);

                if (resultadoAlteracao.Succeeded)
                {
                    return RedirectToAction("Index", "Home");
                }

                AddErrors(resultadoAlteracao);                    
            }

            return View();
        }

        [HttpPost]
        public ActionResult Logoff()
        {
            AuthenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);
            return RedirectToAction("Index", "Home");
        }

        private ActionResult SenhaOuUsuarioInvalidos()
        {
            ModelState.AddModelError("", "Credenciais inválidas!");
            return View("Login");
        }

        public async Task<ActionResult> MinhaConta()
        {
            var modelo = new ContaMinhaContaViewModel();
            var usuarioId = HttpContext.User.Identity.GetUserId();
            var usuario = await UserManager.FindByIdAsync(usuarioId);

            if (usuario != null)
            {
                modelo.NomeCompleto = usuario.NomeCompleto;
                modelo.NumeroDeCelular = usuario.PhoneNumber;
                modelo.HabilitarAutenticacaoDeDoisFatores = usuario.TwoFactorEnabled;
                modelo.NumeroDeCelularConfirmado = usuario.PhoneNumberConfirmed;

                return View(modelo);
            }

            return View();
        }

        [HttpPost]
        public async Task<ActionResult> MinhaConta(ContaMinhaContaViewModel modelo)
        {
            if (ModelState.IsValid)
            {
                var usuarioId = HttpContext.User.Identity.GetUserId();
                var usuario = await UserManager.FindByIdAsync(usuarioId);

                usuario.NomeCompleto = modelo.NomeCompleto;
                usuario.PhoneNumber = modelo.NumeroDeCelular;

                if (!usuario.PhoneNumberConfirmed)
                    await EnviarSmsDeConfirmacaoAsync(usuario);

                var resultadoUpdate = await UserManager.UpdateAsync(usuario);

                if (resultadoUpdate.Succeeded)
                    return RedirectToAction("Index", "Home");

                AddErrors(resultadoUpdate);
            }

            return View();
        }

        private async Task EnviarSmsDeConfirmacaoAsync(UsuarioAplicacao usuario)
        {
            var tokenDeConfirmacao = await UserManager.GenerateChangePhoneNumberTokenAsync(usuario.Id, usuario.PhoneNumber);

            await UserManager.SendSmsAsync(usuario.Id, $"Token de confirmacao: {tokenDeConfirmacao}");
        }

        public ActionResult VerificacaoCodigoCelular()
        {
            return View();
        }

        [HttpPost]
        public async Task<ActionResult> VerificacaoCodigoCelular(string token)
        {
            var usuarioId = HttpContext.User.Identity.GetUserId();
            var usuario = await UserManager.FindByIdAsync(usuarioId);

            var resultado = await UserManager.ChangePhoneNumberAsync(usuarioId, usuario.PhoneNumber, token);

            if (resultado.Succeeded)
                return RedirectToAction("Index", "Home");

            AddErrors(resultado);
            return View();
        }

        private void AddErrors(IdentityResult resultado)
        {
            foreach (var erro in resultado.Errors)
                ModelState.AddModelError("", erro);
        }
    }
}