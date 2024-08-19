using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using MongoDB.Bson;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using PeterO.Cbor;
using Silmoon.AspNetCore.Demo.KeyAuth.Models;
using Silmoon.AspNetCore.Encryption;
using Silmoon.AspNetCore.Encryption.ClientModels;
using Silmoon.AspNetCore.Extensions;
using Silmoon.Extension;
using Silmoon.Runtime.Cache;
using Silmoon.Secure;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Silmoon.AspNetCore.Demo.KeyAuth
{
    public class Controller : Microsoft.AspNetCore.Mvc.Controller
    {
        Core Core { get; set; }
        public Controller(Core core)
        {
            Core = core;
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
