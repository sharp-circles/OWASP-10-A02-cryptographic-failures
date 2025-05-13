using owasp10.A02.Decorators.Models;

namespace owasp10.A02.Decorators.Contracts
{
    public interface ISignee
    {
        public object Target { get; }
        public string? Signature { get; set; }
        public KeyMetadata? KeyMetadata { get; set; }
    }
}
