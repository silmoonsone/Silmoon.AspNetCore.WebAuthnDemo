namespace Silmoon.AspNetCore.Demo.KeyAuth
{
    public class AttestationObjectData
    {
        public string AAGUID { get; set; }
        public string AttestationFormat { get; set; }
        public Dictionary<string, object> AttestationStatement { get; set; }
        public byte[] CredentialId { get; set; }
        public string PublicKeyAlgorithm { get; set; }
        public byte[] PublicKey { get; set; }
        public int SignCount { get; set; }
        public bool UserVerified { get; set; }
    }
}
