using ByteBank.Forum.App_Start.Identity;
using ByteBank.Forum.Models;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Google;
using Owin;
using System;
using System.Configuration;
using System.Data.Entity;

[assembly: OwinStartup(typeof(ByteBank.Forum.Startup))]

namespace ByteBank.Forum
{
    public class Startup
    {
        public void Configuration(IAppBuilder builder)
        {
            /*IUserStore<UsuarioAplicacao> test(IdentityFactoryOptions<IUserStore<UsuarioAplicacao>> opcoes, IOwinContext conextoOwin)
            {
                var dbContext = conextoOwin.Get<DbContext>();
                return new UserStore<UsuarioAplicacao>(dbContext);
            }*/
            /*
              var test = (opcoes, conextoOwin) =>
                {
                    var dbContext = conextoOwin.Get<DbContext>();
                    return new UserStore<UsuarioAplicacao>(dbContext);
                }
            */
            builder.CreatePerOwinContext<DbContext>(() => new IdentityDbContext<UsuarioAplicacao>("DefaultConnection"));

            builder.CreatePerOwinContext<IUserStore<UsuarioAplicacao>>( //test ou
                (opcoes, conextoOwin) =>
                {
                    var dbContext = conextoOwin.Get<DbContext>();
                    return new UserStore<UsuarioAplicacao>(dbContext);
                });

            builder.CreatePerOwinContext<RoleStore<IdentityRole>>( //test ou
                (opcoes, conextoOwin) =>
                {
                    var dbContext = conextoOwin.Get<DbContext>();
                    return new RoleStore<IdentityRole>(dbContext);
                });

            builder.CreatePerOwinContext<RoleManager<IdentityRole>>( //test ou
                (opcoes, conextoOwin) =>
                {
                    var roleStrore = conextoOwin.Get<RoleStore<IdentityRole>>();
                    return new RoleManager<IdentityRole>(roleStrore);
                });

            builder.CreatePerOwinContext<UserManager<UsuarioAplicacao>>(
                (opcoes, contextoOwin) =>
                {
                    var userStore = contextoOwin.Get<IUserStore<UsuarioAplicacao>>();
                    var userManager = new UserManager<UsuarioAplicacao>(userStore);

                    var userValidator = new UserValidator<UsuarioAplicacao>(userManager);
                    userValidator.RequireUniqueEmail = true;
                    userManager.UserValidator = userValidator;

                    userManager.PasswordValidator = new SenhaValidador()
                    {
                        TamanhoRequerido = 6,
                        ObrigatorioCaracteresEspeciais = true,
                        ObrigatorioDigitos = true,
                        ObrigatorioLowerCase = true,
                        ObrigatorioUpperCase = true
                    };

                    userManager.EmailService = new EmailServico();
                    userManager.SmsService = new SmsServico();

                    var dataProtectionProvider = opcoes.DataProtectionProvider.Create("ByteBank.Forum");
                    userManager.UserTokenProvider = new DataProtectorTokenProvider<UsuarioAplicacao>(dataProtectionProvider);
                    userManager.MaxFailedAccessAttemptsBeforeLockout = 3;
                    userManager.DefaultAccountLockoutTimeSpan = TimeSpan.FromMinutes(5);
                    userManager.UserLockoutEnabledByDefault = true;

                    return userManager;
                });

            builder.CreatePerOwinContext<SignInManager<UsuarioAplicacao, string>>(
                (opcoes, contextoOwin) =>
                {
                    var userManager = contextoOwin.Get<UserManager<UsuarioAplicacao>>();
                    var signInManager = new SignInManager<UsuarioAplicacao, string>(userManager, contextoOwin.Authentication);

                    return signInManager;
                });

            builder.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie
            });

            builder.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);            

            builder.UseGoogleAuthentication(new GoogleOAuth2AuthenticationOptions
            {
                ClientId = ConfigurationManager.AppSettings["google:client_id"],
                ClientSecret = ConfigurationManager.AppSettings["google:client_secret"],
                Caption = "Google"
            });

            using (var dbContext = new IdentityDbContext<UsuarioAplicacao>("DefaultConnection"))
            {
                CriarRoles(dbContext);
                CriarAdministrador(dbContext);
            }            
        }

        private void CriarRoles(IdentityDbContext<UsuarioAplicacao> dbContext)
        {
            using (var roleStore = new RoleStore<IdentityRole>(dbContext)) 
            using (var roleManager = new RoleManager<IdentityRole>(roleStore))
            {
                if(!roleManager.RoleExists(RolesNomes.ADMINISTRADOR))
                    roleManager.Create(new IdentityRole(RolesNomes.ADMINISTRADOR));

                if (!roleManager.RoleExists(RolesNomes.MODERADOR))
                    roleManager.Create(new IdentityRole(RolesNomes.MODERADOR));
            }
        }

        private void CriarAdministrador(IdentityDbContext<UsuarioAplicacao> dbContext)
        {
            using (var userStore = new UserStore<UsuarioAplicacao>(dbContext))
            using (var userManager = new UserManager<UsuarioAplicacao>(userStore))
            {
                var administradorEmail = ConfigurationManager.AppSettings["admin:email"];
                var administrador = userManager.FindByEmail(administradorEmail);

                if (administrador != null)
                    return;

                administrador = new UsuarioAplicacao();
                administrador.Email = administradorEmail;
                administrador.EmailConfirmed = true;
                administrador.UserName = ConfigurationManager.AppSettings["admin:user_name"];

                userManager.Create(administrador, ConfigurationManager.AppSettings["admin:senha"]);
                userManager.AddToRole(administrador.Id, RolesNomes.ADMINISTRADOR);
            }

        }
    }
}