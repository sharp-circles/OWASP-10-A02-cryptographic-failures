using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Asymmetric;
using Org.BouncyCastle.Crypto.Fips;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using owasp10.A02.Services.Contracts;
using owasp10.A02.Services.Models;
using System.Text.Json;

namespace owasp10.A02.Services;

public class RsaSignerService : IRsaSignerService
{
    private const int KeySize = 3072;

    private static readonly BigInteger KeyExponent = new(1, Hex.DecodeStrict("00010001"));

    public AsymmetricKeyPair<AsymmetricRsaPublicKey, AsymmetricRsaPrivateKey> GenerateRSAKeyPair()
    {
        return GenerateRSAKeyPair(KeyExponent, KeySize);
    }

    public ISignee GenerateRSASignature(AsymmetricKeyPair<AsymmetricRsaPublicKey, AsymmetricRsaPrivateKey> keyPair, object message)
    {
        var objectBytes = GetByteArrayFromObject(message);

        ISignatureFactoryService signatureFactoryProvider = CryptoServicesRegistrar.CreateService(keyPair.PrivateKey, new SecureRandom());

        ISignatureFactory<FipsRsa.SignatureParameters> signer = signatureFactoryProvider.CreateSignatureFactory(FipsRsa.Pkcs1v15);

        IStreamCalculator<IBlockResult> calculator = signer.CreateCalculator();

        Stream sOut = calculator.Stream;
        sOut.Write(objectBytes, 0, objectBytes.Length);
        sOut.Close();

        var calculatedSignature = calculator.GetResult().Collect();

        var base64EncodedSignature = Convert.ToBase64String(calculatedSignature);

        var keyMetadata = GenerateKeyMetadata(keyPair);

        var signee = new Signee(message, base64EncodedSignature, keyMetadata);

        return signee;
    }

    public bool VerifyRSASignature(ISignee signee, object message)
    {
        var keyMetadata = signee.KeyMetadata;

        var base64EncodedSignature = signee.Signature ?? string.Empty;

        var objectBytes = GetByteArrayFromObject(message);

        var modulus = keyMetadata?.Modulus;

        var publicExponent = keyMetadata?.PublicExponent;

        var publicKey = new AsymmetricRsaPublicKey(FipsRsa.Pkcs1v15.Algorithm, new BigInteger(Hex.DecodeStrict(modulus)), new BigInteger(Hex.DecodeStrict(publicExponent)));

        IVerifierFactoryService verifierFactoryProvider = CryptoServicesRegistrar.CreateService(publicKey);

        IVerifierFactory<FipsRsa.SignatureParameters> verifier = verifierFactoryProvider.CreateVerifierFactory(FipsRsa.Pkcs1v15);

        IStreamCalculator<IVerifier> calculator = verifier.CreateCalculator();

        Stream sOut = calculator.Stream;
        sOut.Write(objectBytes, 0, objectBytes.Length);
        sOut.Close();

        return calculator.GetResult().IsVerified(Convert.FromBase64String(base64EncodedSignature));
    }

    private static byte[] GetByteArrayFromObject(object obj)
    {
        return JsonSerializer.SerializeToUtf8Bytes(obj);
    }

    private static AsymmetricKeyPair<AsymmetricRsaPublicKey, AsymmetricRsaPrivateKey> GenerateRSAKeyPair(BigInteger e, int keySize)
    {
        FipsRsa.KeyGenerationParameters keyGenParameters = new FipsRsa.KeyGenerationParameters(e, keySize);

        FipsRsa.KeyPairGenerator kpGen = CryptoServicesRegistrar.CreateGenerator(keyGenParameters, new SecureRandom());

        return kpGen.GenerateKeyPair();
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
