using MongoDB.Bson;
using Silmoon.AspNetCore.KeyAuthDemo.Models.SubModels;
using Silmoon.Data.MongoDB;

namespace Silmoon.AspNetCore.KeyAuthDemo.Models
{
    public class UserAuthInfo : IdObject
    {
        public ObjectId UserObjectId { get; set; }
        public List<UserWebAuthnInfo> WebAuthnInfos { get; set; } = [];

    }
}
