using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using MongoDB.Bson;
using Silmoon.AspNetCore.KeyAuthDemo.Models.SubModels;
using System.Security.Claims;

namespace Silmoon.AspNetCore.KeyAuthDemo.Pages
{
    public class UserModel : PageModel
    {
        Core Core { get; set; }
        ObjectId UserObjectId { get; set; }
        UserWebAuthnInfo[] UserWebAuthnInfos { get; set; } = [];

        public UserModel(Core core)
        {
            Core = core;
        }
        public void OnGet()
        {
            UserObjectId = ObjectId.Parse(User.Claims.Where(x => x.Type == ClaimTypes.NameIdentifier).FirstOrDefault().Value);
            UserWebAuthnInfos = Core.GetUserWebAuthnInfos(UserObjectId);
            ViewData["UserWebAuthnInfos"] = UserWebAuthnInfos;
            ViewData["UserObjectId"] = UserObjectId;
        }
    }
}
