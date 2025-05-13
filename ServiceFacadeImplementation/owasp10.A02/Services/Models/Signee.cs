using owasp10.A02.Services.Contracts;

namespace owasp10.A02.Services.Models;

public class Signee : ISignee
{
    public object Target { get; }
    public string? Signature { get; set; }
    public KeyMetadata? KeyMetadata { get; set; }

    public Signee(object target, string? signature = null, KeyMetadata? keyMetadata = null)
    {
        Target = target;
        Signature = signature;
        KeyMetadata = keyMetadata;
    }
}
