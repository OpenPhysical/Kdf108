# Domain separation

A KDF gives you independent keys only if every use feeds it different input. In practice that
means two rules.

**Give every purpose its own label.** "encrypt", "mac", and "iv" (or something more specific such
as "orders-db/row-key/v2") make sure the same key-derivation key never yields the same bytes for
two jobs. Version the label when you change how a key is used.

**Encode context so that two different contexts can never produce the same bytes.**
`$"user-{a}-{b}"` is ambiguous: user "1-2" with suffix "3" and user "1" with suffix "2-3" give the
same string. Length-prefix each field instead:

<!-- snippet: length-prefixed -->
```csharp
// Datalen || Data for every field, so "ab" + "c" and "a" + "bc" can never collide.
static byte[] Encode(params string[] fields)
{
    var output = new System.IO.MemoryStream();
    foreach (string field in fields)
    {
        byte[] data = Encoding.UTF8.GetBytes(field);
        output.Write([(byte)(data.Length >> 24), (byte)(data.Length >> 16), (byte)(data.Length >> 8), (byte)data.Length]);
        output.Write(data);
    }
    return output.ToArray();
}

byte[] context = Encode("tenant", "42", "user", "1001");
```

The same applies to SP 800-56C FixedInfo. Build it from fixed-length fields or length-prefixed
fields, typically `AlgorithmID || PartyUInfo || PartyVInfo`, so that it binds the derived key to
the algorithm it is for and to both parties.

A few more habits worth keeping:

- Put L (the output length) in the fixed input, as `Sp800108.FixedInput` does, so that a short
  key is never a prefix of a long one.
- Use one key-derivation key per trust boundary (per tenant, for example) rather than per
  application, and keep the key-derivation key itself out of application code.
- Clear derived keys, Z, and key-derivation keys with `Array.Clear` as soon as you are done.
