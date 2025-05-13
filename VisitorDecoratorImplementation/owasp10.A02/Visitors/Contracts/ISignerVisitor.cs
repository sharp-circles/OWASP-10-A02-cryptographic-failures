using owasp10.A02.Decorators.Contracts;

namespace owasp10.A02.Visitors.Contracts
{
    public interface ISignerVisitor
    {
        public bool VisitForVerification(IVerifiable target);
        public ISignee VisitForSignature(ISignable target);
    }
}
