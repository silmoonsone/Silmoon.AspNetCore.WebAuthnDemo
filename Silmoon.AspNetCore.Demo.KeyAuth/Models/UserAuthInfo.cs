using MongoDB.Bson;
using Silmoon.AspNetCore.Demo.KeyAuth.Models.SubModels;
using Silmoon.Data.MongoDB;

namespace Silmoon.AspNetCore.Demo.KeyAuth.Models
{
    public class UserAuthInfo : IdObject
    {
        public ObjectId UserObjectId { get; set; }
        public List<UserWebAuthnInfo> WebAuthnInfos { get; set; } = [];

    }
}
