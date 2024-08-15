namespace Silmoon.AspNetCore.Demo.KeyAuth.Models.SubModels
{
    public class UserWebAuthnInfo
    {
        public string AAGuid { get; set; }
        public string AttestationFormat { get; set; }
        //public Dictionary<string, object> AttestationStatement { get; set; }
        public byte[] CredentialId { get; set; }
        public string PublicKeyAlgorithm { get; set; }
        public byte[] PublicKey { get; set; }
        public int SignCount { get; set; }
        public bool UserVerified { get; set; }

        public string AuthenticatorAttachment { get; set; }

        public byte[] AttestationObject { get; set; }
    }
}
