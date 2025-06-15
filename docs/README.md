<!-- README for Kdf108: A NIST SP 800-108 KDF implementation using BouncyCastle for .NET -->
# Kdf108

> A .NET library implementing the NIST SP 800-108 Key Derivation Function (KDF) modes (Counter, Feedback, Double-Pipeline) with support for HMAC and CMAC.

## Features

- Implements NIST SP 800-108 KDF in Counter, Feedback, and Double-Pipeline modes
- Supports HMAC-based PRFs (SHA1, SHA224, SHA256, SHA384, SHA512)
- Supports CMAC-based PRFs (AES128, AES192, AES256, TDES)
- Flexible configuration via `KdfOptions` or fluent `KdfOptionsBuilder`
- Fully exercised against official NIST RSP test vectors (included)

## Getting Started

### Prerequisites

- .NET Standard 2.0 / .NET 6.0 / .NET 7.0 / .NET 8.0
- [BouncyCastle.Cryptography](https://www.nuget.org/packages/BouncyCastle.Cryptography/)
- [FluentValidation](https://www.nuget.org/packages/FluentValidation/)

### Installation

Install the library from NuGet:

```bash
dotnet add package Kdf108
```

Or reference the project directly:

```xml
<ProjectReference Include="src/Kdf108/Kdf108.csproj" />
```

## Quick Examples

### Counter Mode (SP800-108)

```csharp
using Kdf108.Domain.Kdf.Modes;
using Kdf108.Domain.Kdf;

// Key Derivation Key (KDK)
byte[] kdk = Convert.FromHexString("4E6F77206973207468");
// Fixed input (Label || Context)
byte[] fixedInput = System.Text.Encoding.ASCII.GetBytes("LabelAndContext");
long outputBits = 256;

var options = new KdfOptions
{
    PrfType = PrfType.HmacSha256,
    CounterLengthBits = 32,
    UseCounter = true,
    CounterLocation = CounterLocation.BeforeFixed,
    MaxBitsAllowed = outputBits
};

var kdf = new CounterModeKdf();
byte[] derived = kdf.DeriveWithFixedInput(kdk, fixedInput, outputBits, options);
Console.WriteLine(Convert.ToHexString(derived));
```

### Counter in the Middle (Split Fixed Input)

```csharp
using Kdf108.Domain.Kdf.Modes;
using Kdf108.Domain.Kdf;

byte[] key = Convert.FromHexString("DFF1E50AC0B69DC40F1051D46C2B069C");
byte[] before = Convert.FromHexString("0011223344");
byte[] after  = Convert.FromHexString("AABBCCDDEE");

var opts = KdfOptions.CreateBuilder()
    .WithPrfType(PrfType.CmacAes128)
    .WithCounterLengthBits(8)
    .WithUseCounter(true)
    .WithCounterLocation(CounterLocation.MiddleFixed)
    .Build();

byte[] result = new CounterModeKdf()
    .DeriveWithSplitFixedInput(key, before, after, 128, opts);
Console.WriteLine(Convert.ToHexString(result));
```

### Double-Pipeline Mode

```csharp
using Kdf108.Domain.Kdf.Modes;
using Kdf108.Domain.Kdf;

byte[] context = Convert.FromHexString("CAFEBABE");

var dpOptions = KdfOptions.CreateBuilder()
    .WithPrfType(PrfType.HmacSha256)
    .WithCounterLengthBits(16)
    .WithUseCounter(true)
    .WithCounterLocation(CounterLocation.BeforeFixed)
    .ForDoublePipelineMode()
    .Build();

byte[] dpKey = new DoublePipelineKdf(useCounter: true)
    .DeriveKey(kdk, "label", context, 512, dpOptions);
Console.WriteLine(Convert.ToHexString(dpKey));
```

### Feedback Mode

```csharp
using Kdf108.Domain.Kdf.Modes;
using Kdf108.Domain.Kdf;

var fbOptions = KdfOptions.CreateBuilder()
    .WithPrfType(PrfType.HmacSha256)
    .WithCounterLengthBits(8)
    .WithUseCounter(true)
    .WithCounterLocation(CounterLocation.BeforeFixed)
    .ForFeedbackMode(iv: null)
    .Build();

byte[] fbKey = new FeedbackModeKdf()
    .DeriveWithFixedInput(kdk, fixedInput, null, 256, fbOptions);
Console.WriteLine(Convert.ToHexString(fbKey));
```

## Running the Tests

Test vectors from NIST SP 800-108 (RSP format) are included under `tests/Kdf108.Test/res/vectors`. Run the full suite:

```bash
dotnet test
```

## Project Structure

```
/src/Kdf108       # Core library (KdfOptions, modes, validators)
/tests/Kdf108.Test # Unit tests and vector loaders
/docs             # Documentation (this README, license)
```

## Disclaimer

The conformance tests in this repository make use of NIST Cryptographic Algorithm Validation Program (CAVP) SP 800‑108 response vectors.  While every reasonable effort has been made to ensure compatibility with the NIST SP 800‑108 specification and to reproduce the expected outputs, this project is neither produced, sponsored, nor endorsed by NIST and has not been formally validated under the CAVP.  USE OF THIS SOFTWARE IS AT YOUR OWN RISK.  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, OR NON-INFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS, CONTRIBUTORS, OR NIST BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## License

This project is licensed under the GNU Affero General Public License v3.0 only. See [LICENSE](../LICENSE) for details.
