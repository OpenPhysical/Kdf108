// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using System.Collections.Generic;
using System.Linq;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;

namespace Kdf108.Domain.Sp80056A;

/// <summary>
/// Provides centralized management of supported elliptic curves.
/// </summary>
public static class CurveRegistry
{
    private static readonly Dictionary<string, Func<ECDomainParameters>> CurveFactories = new()
    {
        // Prime curves
        ["P-224"] = () => CreateFromNamedCurve("P-224"),
        ["P-256"] = () => CreateFromNamedCurve("P-256"),
        ["P-384"] = () => CreateFromNamedCurve("P-384"),
        ["P-521"] = () => CreateFromNamedCurve("P-521"),
        
        // Binary curves
        ["B-233"] = () => CreateFromNamedCurve("sect233r1"),
        ["K-233"] = () => CreateFromNamedCurve("sect233k1"),
        ["K-283"] = () => CreateFromNamedCurve("sect283k1"),
        ["B-409"] = () => CreateFromNamedCurve("sect409r1"),
        ["B-571"] = () => CreateFromNamedCurve("sect571r1"),
        ["K-571"] = () => CreateFromNamedCurve("sect571k1"),
    };

    /// <summary>
    /// Gets the elliptic curve domain parameters for the specified curve.
    /// </summary>
    /// <param name="curveName">The name of the curve.</param>
    /// <returns>The domain parameters if supported; otherwise, null.</returns>
    public static ECDomainParameters? GetParameters(string curveName)
    {
        if (string.IsNullOrEmpty(curveName))
            return null;
            
        if (CurveFactories.TryGetValue(curveName, out var factory))
        {
            return factory();
        }
        
        return null;
    }

    /// <summary>
    /// Determines whether the specified curve is supported.
    /// </summary>
    /// <param name="curveName">The name of the curve.</param>
    /// <returns>true if the curve is supported; otherwise, false.</returns>
    public static bool IsSupported(string curveName)
    {
        return !string.IsNullOrEmpty(curveName) && CurveFactories.ContainsKey(curveName);
    }

    /// <summary>
    /// Gets the names of all supported curves.
    /// </summary>
    public static IEnumerable<string> SupportedCurves => CurveFactories.Keys;

    /// <summary>
    /// Gets the names of all supported prime curves.
    /// </summary>
    public static IEnumerable<string> SupportedPrimeCurves => 
        CurveFactories.Keys.Where(name => name.StartsWith("P-"));

    /// <summary>
    /// Gets the names of all supported binary curves.
    /// </summary>
    public static IEnumerable<string> SupportedBinaryCurves => 
        CurveFactories.Keys.Where(name => name.StartsWith("B-") || name.StartsWith("K-"));

    /// <summary>
    /// Determines whether the specified curve is a binary curve.
    /// </summary>
    /// <param name="curveName">The name of the curve.</param>
    /// <returns>true if the curve is a binary curve; otherwise, false.</returns>
    public static bool IsBinaryCurve(string curveName)
    {
        return !string.IsNullOrEmpty(curveName) && 
               (curveName.StartsWith("B-") || curveName.StartsWith("K-"));
    }

    private static ECDomainParameters CreateFromNamedCurve(string bcCurveName)
    {
        var curve = ECNamedCurveTable.GetByName(bcCurveName);
        if (curve == null)
        {
            throw new InvalidOperationException($"Curve '{bcCurveName}' not found in BouncyCastle");
        }
        
        return new ECDomainParameters(
            curve.Curve, 
            curve.G, 
            curve.N, 
            curve.H, 
            curve.GetSeed());
    }
}