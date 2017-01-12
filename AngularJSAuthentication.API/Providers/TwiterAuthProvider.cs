using Microsoft.Owin.Security.Twitter;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;

namespace AngularJSAuthentication.API.Providers
{
    public class TwiterAuthProvider : TwitterAuthenticationProvider
    {
        public const string AccessToken = "TwitterAccessToken";
        public const string AccessTokenSecret = "TwitterAccessTokenSecret";
        public const string UserID = "UserID";

        public override Task Authenticated(TwitterAuthenticatedContext context)
        {
            context.Identity.AddClaims(
              new List<Claim>
              {
                    new Claim(AccessToken, context.AccessToken),
                    new Claim(AccessTokenSecret, context.AccessTokenSecret),
                    new Claim(UserID, context.UserId)
              });

            //context.Identity.AddClaim(new Claim("ExternalAccessToken", context.AccessToken));
            return Task.FromResult<object>(null);
        }
    }
}