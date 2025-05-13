using owasp10.A02.Visitors.Contracts;

namespace owasp10.A02.Decorators.Contracts
{
    public interface IVerifiable : IConfigurableSignee, ISignee
    {
        public bool Accept(ISignerVisitor visitor);
    }
}
