using Org.BouncyCastle.Crypto.Asymmetric;

namespace owasp10.A02.Services.Contracts;

public interface IRsaSignerService
{
    AsymmetricKeyPair<AsymmetricRsaPublicKey, AsymmetricRsaPrivateKey> GenerateRSAKeyPair();
    ISignee GenerateRSASignature(AsymmetricKeyPair<AsymmetricRsaPublicKey, AsymmetricRsaPrivateKey> keyPair, object message);
    bool VerifyRSASignature(ISignee signee, object message);
}
