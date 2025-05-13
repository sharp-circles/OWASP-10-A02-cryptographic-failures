using owasp10.A02.Visitors.Contracts;

namespace owasp10.A02.Decorators.Contracts
{
    public interface ISignable : IConfigurableSignee, ISignee
    {
        public ISignee Accept(ISignerVisitor visitor);
    }
}
