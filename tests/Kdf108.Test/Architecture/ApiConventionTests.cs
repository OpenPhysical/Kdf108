using System;
using System.Linq;
using System.Reflection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Kdf108.Test.Architecture;

/// <summary>Holds the public API to the conventions documented in docs/api.md.</summary>
[TestFixture]
public sealed class ApiConventionTests
{
    private static readonly Type[] PublicTypes = typeof(Sp800108).Assembly.GetExportedTypes();

    [Test]
    public void EveryPublicTypeLivesInTheRootNamespace() =>
        Assert.That(PublicTypes.Where(t => t.Namespace != "Kdf108").Select(t => t.FullName), Is.Empty);

    [Test]
    public void NoPublicTypeNeedsDisposing() =>
        Assert.That(PublicTypes.Where(t => typeof(IDisposable).IsAssignableFrom(t)).Select(t => t.Name), Is.Empty);

    [Test]
    public void ByteInputsAreSpans()
    {
        var offenders = PublicTypes
            .SelectMany(t => t.GetMethods(BindingFlags.Public | BindingFlags.Static | BindingFlags.Instance | BindingFlags.DeclaredOnly)
                .Cast<MethodBase>().Concat(t.GetConstructors()))
            .Where(m => m.GetParameters().Any(p => p.ParameterType == typeof(byte[])))
            .Select(m => $"{m.DeclaringType!.Name}.{m.Name}");
        Assert.That(offenders, Is.Empty);
    }

    [Test]
    public void LengthsAreBitLengths()
    {
        var offenders = PublicTypes
            .SelectMany(t => t.GetMethods(BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly))
            .SelectMany(m => m.GetParameters().Select(p => (m, p)))
            .Where(x => (x.p.Name == "length" || x.p.Name!.EndsWith("Length", StringComparison.Ordinal)) && x.p.ParameterType != typeof(BitLength))
            .Select(x => $"{x.m.DeclaringType!.Name}.{x.m.Name}({x.p.Name})");
        Assert.That(offenders, Is.Empty);
    }

    [Test]
    public void StaticOperationsArePureAndReturnFreshArrays()
    {
        foreach (MethodInfo m in StaticOperations())
        {
            Assert.That(m.GetParameters().Any(p => typeof(ILogger).IsAssignableFrom(p.ParameterType)), Is.False, Describe(m));
            Assert.That(m.ReturnType, Is.EqualTo(typeof(byte[])).Or.EqualTo(typeof(bool)), Describe(m));
        }
    }

    private static readonly (Type Static, Type Service, Type Implementation)[] Services =
    [
        (typeof(Sp800108), typeof(ISp800108Kdf), typeof(Sp800108Kdf)),
        (typeof(Sp80056C), typeof(ISp80056CKdf), typeof(Sp80056CKdf)),
        (typeof(EcSchemes), typeof(IEcKeyAgreement), typeof(EcKeyAgreement)),
        (typeof(FfcSchemes), typeof(IFfcKeyAgreement), typeof(FfcKeyAgreement)),
        (typeof(KeyConfirmation), typeof(IKeyConfirmation), typeof(KeyConfirmationService)),
    ];

    [Test]
    public void EveryServiceMirrorsItsStaticClassExactly()
    {
        foreach (var (statics, service, _) in Services)
        {
            var expected = statics.GetMethods(BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly)
                .Where(m => m.Name != nameof(Sp800108.FixedInput)).Select(Signature).Order(StringComparer.Ordinal);
            var actual = service.GetMethods().Select(Signature).Order(StringComparer.Ordinal);
            Assert.That(actual, Is.EqualTo(expected), service.Name);
        }
    }

    [Test]
    public void ServicesWorkWithoutAContainerAndRegisterWithOne()
    {
        var provider = new ServiceCollection().AddLogging().AddKdf108().BuildServiceProvider();
        foreach (var (_, service, implementation) in Services)
        {
            ConstructorInfo constructor = implementation.GetConstructors().Single();
            ParameterInfo logger = constructor.GetParameters().Single();
            Assert.That(logger.ParameterType, Is.EqualTo(typeof(ILogger<>).MakeGenericType(implementation)), implementation.Name);
            Assert.That(logger.HasDefaultValue && logger.DefaultValue is null, Is.True, $"{implementation.Name} must be constructible without a logger");
            Assert.That(provider.GetRequiredService(service), Is.InstanceOf(implementation));
            Assert.That(implementation.IsSealed, Is.True, implementation.Name);
        }
    }

    [Test]
    public void AddKdf108KeepsExistingRegistrations()
    {
        var custom = new Sp800108Kdf();
        var provider = new ServiceCollection().AddSingleton<ISp800108Kdf>(custom).AddKdf108().BuildServiceProvider();
        Assert.That(provider.GetRequiredService<ISp800108Kdf>(), Is.SameAs(custom));
    }

    private static System.Collections.Generic.IEnumerable<MethodInfo> StaticOperations() =>
        Services.SelectMany(s => s.Static.GetMethods(BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly))
            .Where(m => m.Name != nameof(Sp800108.FixedInput));

    private static string Signature(MethodInfo m) =>
        $"{m.ReturnType.Name} {m.Name}({string.Join(", ", m.GetParameters().Select(p => $"{p.ParameterType.Name} {p.Name}"))})";

    private static string Describe(MethodInfo m) => $"{m.DeclaringType!.Name}.{m.Name}";

    [Test]
    public void EcAndFfcSchemesOfferTheSameMethods() =>
        Assert.That(Names(typeof(EcSchemes)), Is.EqualTo(Names(typeof(FfcSchemes))));

    [Test]
    public void EveryExceptionDerivesFromKdf108Exception() =>
        Assert.That(PublicTypes.Where(t => typeof(Exception).IsAssignableFrom(t) && !typeof(Kdf108Exception).IsAssignableFrom(t)).Select(t => t.Name), Is.Empty);

    private static string[] Names(Type t) =>
        t.GetMethods(BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly).Select(m => m.Name).Order(StringComparer.Ordinal).ToArray();
}
