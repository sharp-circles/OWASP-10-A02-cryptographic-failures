using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Asymmetric;
using Org.BouncyCastle.Crypto.Fips;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using owasp10.A02.Decorators.Contracts;
using owasp10.A02.Decorators.Models;
using owasp10.A02.Visitors.Contracts;
using System.Text.Json;

namespace owasp10.A02.Visitors
{
    public class RsaSignerVisitor : ISignerVisitor
    {
        private const int KeySize = 3072;

        private static readonly BigInteger KeyExponent = new(1, Hex.DecodeStrict("00010001"));

        public ISignee VisitForSignature(ISignable target)
        {
            var key = GenerateRSAKeyPair(KeyExponent, KeySize);

            var objectBytes = GetByteArrayFromObject(target.Target);

            var signature = GenerateRSASignature(key.PrivateKey, objectBytes);

            var base64EncodedSignature = Convert.ToBase64String(signature);

            target.Signature = base64EncodedSignature;

            target.KeyMetadata = GenerateKeyMetadata(key);

            return target;
        }

        public bool VisitForVerification(IVerifiable target)
        {
            var keyMetadata = target.KeyMetadata;

            var base64EncodedSignature = target.Signature ?? string.Empty;

            var objectBytes = GetByteArrayFromObject(target.Target);

            var modulus = keyMetadata?.Modulus;

            var publicExponent = keyMetadata?.PublicExponent;

            var publicKey = new AsymmetricRsaPublicKey(FipsRsa.Pkcs1v15.Algorithm, new BigInteger(Hex.DecodeStrict(modulus)), new BigInteger(Hex.DecodeStrict(publicExponent)));

            return VerifyRSASignature(publicKey, Convert.FromBase64String(base64EncodedSignature), objectBytes);
        }

        private static AsymmetricKeyPair<AsymmetricRsaPublicKey, AsymmetricRsaPrivateKey> GenerateRSAKeyPair(BigInteger e, int keySize)
        {
            FipsRsa.KeyGenerationParameters keyGenParameters = new FipsRsa.KeyGenerationParameters(e, keySize);

            FipsRsa.KeyPairGenerator kpGen = CryptoServicesRegistrar.CreateGenerator(keyGenParameters, new SecureRandom());

            return kpGen.GenerateKeyPair();
        }

        private static byte[] GenerateRSASignature(AsymmetricRsaPrivateKey key, byte[] message)
        {
            ISignatureFactoryService signatureFactoryProvider = CryptoServicesRegistrar.CreateService(key, new SecureRandom());

            ISignatureFactory<FipsRsa.SignatureParameters> signer = signatureFactoryProvider.CreateSignatureFactory(FipsRsa.Pkcs1v15);

            IStreamCalculator<IBlockResult> calculator = signer.CreateCalculator();

            Stream sOut = calculator.Stream;
            sOut.Write(message, 0, message.Length);
            sOut.Close();

            return calculator.GetResult().Collect();
        }

        private static bool VerifyRSASignature(AsymmetricRsaPublicKey key, byte[] signature, byte[] message)
        {
            IVerifierFactoryService verifierFactoryProvider = CryptoServicesRegistrar.CreateService(key);

            IVerifierFactory<FipsRsa.SignatureParameters> verifier = verifierFactoryProvider.CreateVerifierFactory(FipsRsa.Pkcs1v15);

            IStreamCalculator<IVerifier> calculator = verifier.CreateCalculator();

            Stream sOut = calculator.Stream;
            sOut.Write(message, 0, message.Length);
            sOut.Close();

            return calculator.GetResult().IsVerified(signature);
        }

        private static byte[] GetByteArrayFromObject(object obj)
        {
            return JsonSerializer.SerializeToUtf8Bytes(obj);
        }

        private KeyMetadata? GenerateKeyMetadata(AsymmetricKeyPair<AsymmetricRsaPublicKey, AsymmetricRsaPrivateKey> key)
        {
            var modulus = Hex.ToHexString(key.PublicKey.Modulus.ToByteArray());
            var publicExponent = Hex.ToHexString(key.PublicKey.PublicExponent.ToByteArray());

            return new()
            {
                Modulus = modulus,
                PublicExponent = publicExponent
            };
        }
    }
}
