using Silmoon.AspNetCore.Encryption.Models;

namespace Silmoon.AspNetCore.Demo.KeyAuth.Models.SubModels
{
    public class UserWebAuthnInfo : PublicKeyInfo
    {
        public string AAGuid { get; set; }
        public string AttestationFormat { get; set; }
        public byte[] CredentialId { get; set; }
        public int SignCount { get; set; }
        public bool UserVerified { get; set; }
        public string AuthenticatorAttachment { get; set; }
        public byte[] AttestationObject { get; set; }
    }
}
