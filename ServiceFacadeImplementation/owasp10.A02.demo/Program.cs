using owasp10.A02.demo.Models;
using owasp10.A02.Services;

// Signable object
var user = new User()
{
    Id = 1,
    Name = "Iván"
};

Console.WriteLine("=========================================================================================");
Console.WriteLine("Start of signature generation and verification with service/facade implementation");
Console.WriteLine("=========================================================================================");

// Rsa signer service
var rsaSignerService = new RsaSignerService();

// Get public/private key pair
var keyPair = rsaSignerService.GenerateRSAKeyPair();

// Sign the user
var signedUser = rsaSignerService.GenerateRSASignature(keyPair, user);

Console.WriteLine();
Console.WriteLine($"Base 64 encoded signature output: {signedUser.Signature}");
Console.WriteLine();

var userToVerify = new User()
{
    Id = 1,
    Name = "Iván"
};

// Verify the signature
var isVerified = rsaSignerService.VerifyRSASignature(signedUser, userToVerify);

var verificationResult = isVerified ? "Success" : "Failed";

Console.WriteLine($"Verification result: {verificationResult}");



