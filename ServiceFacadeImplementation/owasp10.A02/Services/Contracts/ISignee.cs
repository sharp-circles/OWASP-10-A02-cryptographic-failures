using owasp10.A02.Services.Models;

namespace owasp10.A02.Services.Contracts
{
    public interface ISignee
    {
        public object Target { get; }
        public string? Signature { get; set; }
        public KeyMetadata? KeyMetadata { get; set; }
    }
}
