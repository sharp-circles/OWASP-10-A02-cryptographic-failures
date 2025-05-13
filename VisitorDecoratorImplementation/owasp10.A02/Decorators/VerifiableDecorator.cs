using owasp10.A02.Decorators.Contracts;
using owasp10.A02.Decorators.Models;
using owasp10.A02.Visitors.Contracts;

namespace owasp10.A02.Decorators
{
    public class VerifiableDecorator : IVerifiable
    {
        private readonly ISignee _signee;

        public object Target { get => _signee.Target; }
        public string? Signature { get => _signee.Signature; set => _signee.Signature = value; }
        public KeyMetadata? KeyMetadata { get => _signee.KeyMetadata; set => _signee.KeyMetadata = value; }

        public VerifiableDecorator(ISignee signee)
        {
            _signee = signee;
        }

        public bool Accept(ISignerVisitor visitor)
        {
            return visitor.VisitForVerification(this);
        }
    }
}
