using owasp10.A02.Decorators;
using owasp10.A02.Decorators.Models;
using owasp10.A02.demo.Models;
using owasp10.A02.Visitors;

// Signable object
var user = new User()
{
    Id = 1,
    Name = "Iván"
};

Console.WriteLine("=========================================================================================");
Console.WriteLine("Start of signature generation and verification with visitor and decorator implementations");
Console.WriteLine("=========================================================================================");

// Utility class used to encapsulate signing information and act as the anchor among decorators
var signee = new Signee(user);

// Signable decorator
var signableDecorator = new SignableDecorator(signee);

// Rsa signer visitor
var signerVisitor = new RsaSignerVisitor();

// Accept visitation from decorator to sign the object
var signedUser = signableDecorator.Accept(signerVisitor);

Console.WriteLine();
Console.WriteLine($"Base 64 encoded signature output: {signedUser.Signature}");
Console.WriteLine();

var userToVerify = new User()
{
    Id = 1,
    Name = "Iván"
};

// With generated signature and public key, we pass the new element to verify
var userToVerifySignee = new Signee(userToVerify, signedUser.Signature, signedUser.KeyMetadata);

// ISignee is reused then as a input for verification
var verifiableDecorator = new VerifiableDecorator(userToVerifySignee);

// Accept visitation from decorator to verify the signature
var isVerified = verifiableDecorator.Accept(signerVisitor);

var verificationResult = isVerified ? "Success" : "Failed";

Console.WriteLine($"Verification result: {verificationResult}");



