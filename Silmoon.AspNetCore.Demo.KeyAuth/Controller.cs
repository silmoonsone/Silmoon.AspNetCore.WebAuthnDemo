using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MongoDB.Bson;
using Newtonsoft.Json.Linq;
using Silmoon.AspNetCore.Demo.KeyAuth.Models;
using Silmoon.AspNetCore.Extensions;
using Silmoon.Extension;
using Silmoon.Secure;
using System.Security.Claims;

namespace Silmoon.AspNetCore.Demo.KeyAuth
{
    public class Controller : Microsoft.AspNetCore.Mvc.Controller
    {
        Core Core { get; set; }
        public Controller(Core core)
        {
            Core = core;
        }

        [HttpGet("getWebAuthnOptions"), Authorize]
        public IActionResult GetWebAuthnOptions()
        {
            var options = new ClientWebAuthnOptions()
            {
                Attestation = "direct",
                Challenge = Convert.FromBase64String(Convert.ToBase64String(Guid.NewGuid().ToByteArray())),
                Rp = new ClientWebAuthnOptions.ClientWebAuthnRp() { Id = HttpContext.Request.Host.Host, Name = "YourAppName" },
                User = new ClientWebAuthnOptions.ClientWebAuthnUser()
                {
                    Id = Convert.ToBase64String(Guid.NewGuid().ToByteArray()),
                    Name = "user@example.com",
                    DisplayName = "Example User"
                },
                PubKeyCredParams =
                [
                    new ClientWebAuthnOptions.ClientWebAuthnPubKeyCredParams() { Alg = -7, Type = "public-key" },
                    new ClientWebAuthnOptions.ClientWebAuthnPubKeyCredParams() { Alg = -257, Type = "public-key" }
                ],
                AuthenticatorSelection = new ClientWebAuthnOptions.ClientWebAuthnAuthenticatorSelection() { UserVerification = "preferred" },
                Timeout = 60000
            };

            return Ok(options);
        }
        [HttpPost("addWebAuthn"), Authorize]
        public IActionResult AddWebAuthn([FromBody] JObject credential)
        {
            var sessionUserObjectId = ObjectId.Parse(User.Claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier).Value);
            var user = Core.GetUser(sessionUserObjectId);
            if (user is null) return this.JsonStateFlag(false, "User not found");

            var attestationObjectByteArray = credential["response"]["attestationObject"].ToObject<byte[]>();
            var attestationData = WebAuthnParser.ParseAttestationObject(attestationObjectByteArray);

            var clientDataJSON = credential["response"]["clientDataJSON"].ToObject<byte[]>().GetString();

            var result = Core.AddUserWebAuthnInfo(user._id, new Models.SubModels.UserWebAuthnInfo()
            {
                AAGuid = attestationData.AAGUID,
                AttestationFormat = attestationData.AttestationFormat,
                CredentialId = attestationData.CredentialId,
                PublicKey = attestationData.PublicKey,
                PublicKeyAlgorithm = attestationData.PublicKeyAlgorithm,
                SignCount = attestationData.SignCount,
                UserVerified = attestationData.UserVerified,
                AttestationObject = attestationObjectByteArray,
                AuthenticatorAttachment = credential["authenticatorAttachment"].Value<string>(),
            });

            if (result.State) return this.JsonStateFlag(true);
            else return this.JsonStateFlag(false, result.Message);
        }
        [HttpPost("deleteWebAuthn"), Authorize]
        public IActionResult DeleteWebAuthn([FromForm] string CredentialId)
        {
            if (CredentialId.IsNullOrEmpty()) return this.JsonStateFlag(false, "CredentialId is empty");
            var sessionUserObjectId = ObjectId.Parse(User.Claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier).Value);
            var user = Core.GetUser(sessionUserObjectId);
            if (user is null) return this.JsonStateFlag(false, "User not found");

            var result = Core.DeleteUserWebAuthnInfo(user._id, Convert.FromBase64String(CredentialId));
            if (result.State) return this.JsonStateFlag(true);
            else return this.JsonStateFlag(false, result.Message);
        }


        [HttpPost("doSignup")]
        public IActionResult DoSignup(string Username, string Password, string Retypepassword)
        {
            if (Username.IsNullOrEmpty()) return this.JsonStateFlag(false, "Username is empty");
            if (Password.IsNullOrEmpty()) return this.JsonStateFlag(false, "Password is empty");
            if (Password != Retypepassword) return this.JsonStateFlag(false, "Password not match");

            var result = Core.NewUser(new User()
            {
                Username = Username,
                Password = Password.GetMD5Hash(),
                Nickname = Username,
            });

            if (result.State) return this.JsonStateFlag(true);
            else return this.JsonStateFlag(false, result.Message);
        }
        [HttpPost("doSignin")]
        public async Task<IActionResult> DoSignin(string Username, string Password)
        {
            var user = Core.GetUser(Username);
            if (user is null) return this.JsonStateFlag(false, "User not found");
            if (user.Password != Password.GetMD5Hash()) return this.JsonStateFlag(false, "Password incorrect");

            var claims = new List<Claim>()
            {
                new Claim(ClaimTypes.NameIdentifier, user._id.ToString()),
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Role, user.Role.ToString())
            };
            var claimsIdentity = new ClaimsIdentity(claims, "Customer");
            var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);
            await HttpContext.SignInAsync(claimsPrincipal);
            return this.JsonStateFlag(true);
        }
        [HttpGet("doSignout")]
        public async Task<IActionResult> DoSignout()
        {
            await HttpContext.SignOutAsync();
            return this.JsonStateFlag(true);
        }
    }
}
