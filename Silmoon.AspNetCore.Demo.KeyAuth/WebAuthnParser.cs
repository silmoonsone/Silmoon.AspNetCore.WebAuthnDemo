using PeterO.Cbor;

namespace Silmoon.AspNetCore.Demo.KeyAuth
{
    public static class WebAuthnParser
    {
        public static AttestationObjectData ParseAttestationObject(byte[] attestationObjectByteArray)
        {
            var attestationObject = CBORObject.DecodeFromBytes(attestationObjectByteArray);

            // 提取 authData (byte array)
            byte[] authData = attestationObject["authData"].GetByteString();

            // 提取 AAGUID (16字节)
            string aaguid = BitConverter.ToString(authData.Skip(37).Take(16).ToArray()).Replace("-", "").ToLower();

            // 提取 Credential ID 长度和值
            int credIdLen = BitConverter.ToUInt16(authData.Skip(53).Take(2).Reverse().ToArray(), 0);
            byte[] credentialId = authData.Skip(55).Take(credIdLen).ToArray();

            // 提取 COSE_Key 数据，从 Credential ID 后的位置开始
            int keyOffset = 55 + credIdLen;
            byte[] coseKey = authData.Skip(keyOffset).ToArray();

            var cborKey = CBORObject.DecodeFromBytes(coseKey);

            // 提取公钥算法
            string publicKeyAlgorithm = ExtractPublicKeyAlgorithm(cborKey);

            // 提取公钥
            byte[] publicKey = ExtractPublicKey(cborKey, publicKeyAlgorithm);

            // 提取用户验证状态和签名计数器
            bool userVerified = (authData[32] & 0x04) != 0;
            int signCount = BitConverter.ToInt32(authData.Skip(33).Take(4).Reverse().ToArray(), 0);

            // 提取 Attestation Statement
            var attStmt = new Dictionary<string, object>();
            foreach (var key in attestationObject["attStmt"].Keys)
            {
                attStmt.Add(key.ToString(), attestationObject["attStmt"][key]);
            }

            return new AttestationObjectData
            {
                AAGUID = aaguid,
                CredentialId = credentialId,
                PublicKeyAlgorithm = publicKeyAlgorithm,
                PublicKey = publicKey,
                SignCount = signCount,
                UserVerified = userVerified,
                AttestationFormat = attestationObject["fmt"].AsString(),
                AttestationStatement = attStmt
            };
        }

        private static string ExtractPublicKeyAlgorithm(CBORObject cborKey)
        {
            int alg = cborKey[CBORObject.FromObject(3)].AsInt32();
            return alg switch
            {
                -7 => "ES256",  // ECDSA w/ SHA-256
                -257 => "RS256", // RSASSA-PKCS1-v1_5 w/ SHA-256
                _ => "Unknown"
            };
        }

        private static byte[] ExtractPublicKey(CBORObject cborKey, string algorithm)
        {
            if (algorithm == "ES256")
            {
                // EC2 公钥（适用于 ES256）
                byte[] x = cborKey[CBORObject.FromObject(-2)].GetByteString();  // X coordinate
                byte[] y = cborKey[CBORObject.FromObject(-3)].GetByteString();  // Y coordinate
                return new byte[] { 0x04 }.Concat(x).Concat(y).ToArray();  // 0x04前缀表示未压缩的公钥
            }
            else if (algorithm == "RS256")
            {
                // RSA 公钥（适用于 RS256）
                byte[] n = cborKey[CBORObject.FromObject(-1)].GetByteString();  // Modulus
                byte[] e = cborKey[CBORObject.FromObject(-2)].GetByteString();  // Exponent
                var publicKey = new byte[n.Length + e.Length + 1];
                publicKey[0] = 0x30; // PKCS#1 format prefix for RS256
                Array.Copy(n, 0, publicKey, 1, n.Length);
                Array.Copy(e, 0, publicKey, 1 + n.Length, e.Length);
                return publicKey;
            }

            return null;
        }
    }
}
