using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;


namespace StatlerWaldorfCorp.SecureWebApp
{
    public class Startup
    {
        public Startup(IHostingEnvironment env)
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(env.ContentRootPath)
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: false)                
                .AddEnvironmentVariables();
            Configuration = builder.Build();
        }

        public IConfigurationRoot Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            // Add framework services.
            services.AddMvc();

            services.AddOptions();

            var openIdConfiguration = Configuration.GetSection("OpenID");
            services.Configure<OpenIDSettings>(openIdConfiguration);

            var openIdSettings = openIdConfiguration.Get(typeof (OpenIDSettings)) as OpenIDSettings;
            Console.WriteLine("Using OpenID Auth domain of : " + openIdSettings.Domain);
            services.AddAuthentication(options => {
                options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            }).AddCookie()
            .AddOpenIdConnect(options =>{
                ConfigureOpenIdConnectOptions(options, openIdSettings);
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, 
                    ILoggerFactory loggerFactory)
        {

            loggerFactory.AddConsole(Configuration.GetSection("Logging"));
            loggerFactory.AddDebug();

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();                
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }

            app.UseStaticFiles();

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }

        private void ConfigureOpenIdConnectOptions(OpenIdConnectOptions options, OpenIDSettings openIdSettings)
        {
            options.Authority = $"https://{openIdSettings.Domain}";
            options.ClientId = openIdSettings.ClientId;
            options.ClientSecret = openIdSettings.ClientSecret;

            options.ResponseType = "code";
            options.CallbackPath = new PathString("/signin-auth0");

            options.ClaimsIssuer = "Auth0";
            options.SaveTokens = true;
            options.Events = CreateOpenIdConnectEvents();

            options.Scope.Clear();
            options.Scope.Add("openid");
            options.Scope.Add("name");
            options.Scope.Add("email");
            options.Scope.Add("picture");   
        }

        private OpenIdConnectEvents CreateOpenIdConnectEvents()
        {
            return new OpenIdConnectEvents()
            {
                OnTicketReceived = context =>
                {
                    var identity = 
                        context.Principal.Identity as ClaimsIdentity;
                    if (identity != null) {
                        if (!context.Principal.HasClaim( c => c.Type == ClaimTypes.Name) &&
                        identity.HasClaim( c => c.Type == "name"))
                        identity.AddClaim(new Claim(ClaimTypes.Name, identity.FindFirst("name").Value));
                    }
                    return Task.FromResult(0);
                }
            };
        }
    }
}
