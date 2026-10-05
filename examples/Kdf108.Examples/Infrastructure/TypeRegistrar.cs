using System;
using Microsoft.Extensions.DependencyInjection;
using Spectre.Console.Cli;

namespace Kdf108.Examples.Infrastructure;

/// <summary>Lets Spectre.Console.Cli build commands from a Microsoft.Extensions.DependencyInjection container.</summary>
public sealed class TypeRegistrar(IServiceCollection services) : ITypeRegistrar
{
    public ITypeResolver Build() => new TypeResolver(services.BuildServiceProvider());
    public void Register(Type service, Type implementation) => services.AddSingleton(service, implementation);
    public void RegisterInstance(Type service, object implementation) => services.AddSingleton(service, implementation);
    public void RegisterLazy(Type service, Func<object> factory) => services.AddSingleton(service, _ => factory());
}

public sealed class TypeResolver(IServiceProvider provider) : ITypeResolver, IDisposable
{
    public object? Resolve(Type? type) => type is null ? null : provider.GetService(type);
    public void Dispose() => (provider as IDisposable)?.Dispose();
}
