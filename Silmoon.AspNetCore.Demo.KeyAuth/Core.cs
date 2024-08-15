using MongoDB.Bson;
using Silmoon.AspNetCore.Demo.KeyAuth.Models;
using Silmoon.AspNetCore.Demo.KeyAuth.Models.SubModels;
using Silmoon.Data.LiteDB;
using Silmoon.Extension;
using Silmoon.Models;

namespace Silmoon.AspNetCore.Demo.KeyAuth
{
    public class Core : LiteDBService
    {
        public Core()
        {
            Database = new LiteDB.LiteDatabase("Filename=user.local.db; Connection=shared");
        }

        public User GetUser(ObjectId UserObjectId) => Get<User>(x => x._id == UserObjectId);
        public User GetUser(string username) => Get<User>(x => x.Username == username);
        public StateSet<bool> NewUser(User user)
        {
            if (GetUser(user.Username) is null)
            {
                Add(user);
                return true.ToStateSet();
            }
            else
                return false.ToStateSet("User already exists");
        }
        public UserAuthInfo GetUserAuthInfo(ObjectId UserObjectId)
        {
            if (GetUser(UserObjectId) is null) return null;
            var result = Get<UserAuthInfo>(x => x.UserObjectId == UserObjectId);
            if (result is null)
            {
                result = new UserAuthInfo()
                {
                    UserObjectId = UserObjectId,
                    WebAuthnInfos = []
                };
                Add(result);
            }
            return result;
        }
        public UserWebAuthnInfo[] GetUserWebAuthnInfos(ObjectId UserObjectId)
        {
            return GetUserAuthInfo(UserObjectId)?.WebAuthnInfos.ToArray();
        }

        public UserWebAuthnInfo GetUserWebAuthnInfo(ObjectId UserObjectId, byte[] CredentialId)
        {
            var userAuthInfo = GetUserAuthInfo(UserObjectId);
            return userAuthInfo.WebAuthnInfos.FirstOrDefault(x => x.CredentialId != null && x.CredentialId.SequenceEqual(CredentialId));
        }
        public StateSet<bool> AddUserWebAuthnInfo(ObjectId UserObjectId, UserWebAuthnInfo userWebAuthnInfo)
        {
            var userAuthInfo = GetUserAuthInfo(UserObjectId);
            if (GetUserWebAuthnInfo(UserObjectId, userWebAuthnInfo.CredentialId) is null)
            {
                userAuthInfo.WebAuthnInfos.Add(userWebAuthnInfo);
                Sets<UserAuthInfo>(x => new UserAuthInfo() { WebAuthnInfos = userAuthInfo.WebAuthnInfos }, x => x.UserObjectId == UserObjectId);
                return true.ToStateSet();
            }
            else
                return false.ToStateSet("CredentialId already exists");
        }
        public StateSet<bool> DeleteUserWebAuthnInfo(ObjectId UserObjectId, byte[] CredentialId)
        {
            var userAuthInfo = GetUserAuthInfo(UserObjectId);
            var userWebAuthnInfo = GetUserWebAuthnInfo(UserObjectId, CredentialId);
            if (userWebAuthnInfo is null)
                return false.ToStateSet("CredentialId not found");
            else
            {
                userAuthInfo.WebAuthnInfos.Remove(userAuthInfo.WebAuthnInfos.Where(x => x.CredentialId != null && x.CredentialId.SequenceEqual(CredentialId)).FirstOrDefault());
                Sets<UserAuthInfo>(x => new UserAuthInfo() { WebAuthnInfos = userAuthInfo.WebAuthnInfos }, x => x.UserObjectId == UserObjectId);
                return true.ToStateSet();
            }
        }
    }
}
