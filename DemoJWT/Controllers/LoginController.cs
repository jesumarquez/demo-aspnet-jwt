using DemoJWT.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Principal;
using System.Threading;
using System.Web.Http;

namespace DemoJWT.Controllers
{
    [AllowAnonymous]
    [RoutePrefix("api/login")]
    public class LoginController : ApiController
    {

        [HttpGet]
        [Route("echoping")]
        public IHttpActionResult EchoPing()
        {
            return Ok();
        }

        [HttpGet]
        [Route("echouser")]
        public IHttpActionResult EchoUser()
        {
            IIdentity identiy = Thread.CurrentPrincipal.Identity;

            return Ok($"IPrincipal-user: { identiy.Name } - IsAuthenticated: { identiy.IsAuthenticated }.");
        }

        [HttpPost]
        [Route("authenticate")]
        public IHttpActionResult Authenticate(LoginRequest login)
        {
            if (login == null)
                throw new HttpResponseException(HttpStatusCode.BadRequest);

            bool isCredentialValid = login.Password == "123456";

            if (isCredentialValid)
            {
                string token = TokenGenerator.GenerateTokenJwt(login.Username);

                return Ok(token);
            }
            else
            {
                return Unauthorized();
            }
        }
    }
}
