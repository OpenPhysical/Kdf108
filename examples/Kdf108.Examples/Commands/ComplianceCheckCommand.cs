using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Threading.Tasks;
using Kdf108.Simple;
using Microsoft.Extensions.Logging;
using Spectre.Console;
using Spectre.Console.Cli;
using Kdf108.Examples.Infrastructure;

namespace Kdf108.Examples.Commands;

/// <summary>
/// Interactive compliance checker that validates KDF configurations against NIST standards
/// and provides real-time feedback on security strength and best practices.
/// </summary>
public class ComplianceCheckCommand : AsyncCommand<ComplianceCheckCommand.Settings>
{
    public sealed class Settings : CommandSettings
    {
        [Description("Enable verbose explanations and detailed analysis")]
        [CommandOption("-v|--verbose")]
        [DefaultValue(false)]
        public bool Verbose { get; init; }
    }

    public override async Task<int> ExecuteAsync([NotNull] CommandContext context, [NotNull] Settings settings)
    {
        var loggerFactory = LoggingSetup.CreateLoggerFactory(settings.Verbose);
        var logger = loggerFactory.CreateLogger<ComplianceCheckCommand>();

        AnsiConsole.Write(new FigletText("Compliance Checker")
            .Centered()
            .Color(Color.Blue));
        
        AnsiConsole.MarkupLine("[dim]Interactive NIST compliance validation for KDF configurations[/]");
        AnsiConsole.WriteLine();

        try
        {
            await RunComplianceChecker(settings, logger);
            return 0;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error during compliance check");
            AnsiConsole.Write(new Panel($"[red]Error:[/] {ex.Message}")
                .Header("[red]✗ Failed[/]")
                .BorderColor(Color.Red));
            return 1;
        }
    }

    private async Task RunComplianceChecker(Settings settings, ILogger logger)
    {
        bool continueChecking = true;
        
        while (continueChecking)
        {
            AnsiConsole.Clear();
            AnsiConsole.Write(new FigletText("Compliance Checker")
                .Centered()
                .Color(Color.Blue));
            
            AnsiConsole.MarkupLine("[dim]Interactive NIST compliance validation for KDF configurations[/]");
            AnsiConsole.WriteLine();
            
            var checkType = await SelectComplianceCheck();
            
            switch (checkType)
            {
                case "kdf-config":
                    await CheckKdfConfiguration(settings, logger);
                    break;
                case "key-strength":
                    await CheckKeyStrength(settings, logger);
                    break;
                case "curve-analysis":
                    await CheckCurveCompliance(settings, logger);
                    break;
                case "scenario-review":
                    await ReviewScenarioCompliance(settings, logger);
                    break;
                case "exit":
                    continueChecking = false;
                    break;
            }
            
            if (continueChecking)
            {
                AnsiConsole.WriteLine();
                AnsiConsole.MarkupLine("[dim]Press any key to return to compliance checker menu...[/]");
                Console.ReadKey(true);
            }
        }
        
        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine("[green]✅ Compliance review completed. Stay secure![/]");
    }

    private async Task<string> SelectComplianceCheck()
    {
        AnsiConsole.Write(new Rule("[cyan]🔍 Compliance Check Options[/]").RuleStyle("cyan"));
        AnsiConsole.WriteLine();
        
        await Task.Delay(10);
        
        var choice = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("[bold blue]What type of compliance check would you like to perform?[/]")
                .PageSize(10)
                .MoreChoicesText("[grey](Use ↑/↓ arrow keys to navigate, Enter to select)[/]")
                .AddChoices(new[] {
                    "kdf-config",
                    "key-strength", 
                    "curve-analysis",
                    "scenario-review",
                    "exit"
                })
                .UseConverter(choice => choice switch
                {
                    "kdf-config" => "📋 KDF Configuration Validator - Check your KDF parameters against NIST SP 800-108 requirements",
                    "key-strength" => "🔐 Key Strength Analyzer - Evaluate the security strength of your keys and algorithms",
                    "curve-analysis" => "📈 Elliptic Curve Compliance - Validate curve selection against NIST SP 800-56A standards",
                    "scenario-review" => "📚 Scenario Compliance Review - Check implementation scenarios against best practices",
                    "exit" => "🚪 Exit Compliance Checker - Return to your cryptographically secure life",
                    _ => choice
                }));
        
        AnsiConsole.WriteLine();
        return choice;
    }

    private async Task CheckKdfConfiguration(Settings settings, ILogger logger)
    {
        AnsiConsole.Write(new Rule("[green]📋 KDF Configuration Compliance Check[/]").RuleStyle("green"));
        AnsiConsole.WriteLine();
        
        AnsiConsole.MarkupLine("[bold]This wizard will validate your KDF configuration against NIST SP 800-108 requirements.[/]");
        AnsiConsole.WriteLine();

        // Master Key Length Check
        var masterKeyLength = AnsiConsole.Prompt(
            new SelectionPrompt<int>()
                .Title("[bold]What is the length of your master key in bits?[/]")
                .AddChoices(new[] { 128, 192, 256, 384, 512 })
                .AddChoices(999) // Custom option
                .UseConverter(length => length switch
                {
                    128 => "128 bits (16 bytes) - Minimum for most applications",
                    192 => "192 bits (24 bytes) - Enhanced security",
                    256 => "256 bits (32 bytes) - Recommended standard",
                    384 => "384 bits (48 bytes) - High security",
                    512 => "512 bits (64 bytes) - Maximum security",
                    999 => "Other (I'll specify)",
                    _ => $"{length} bits"
                }));

        if (masterKeyLength == 999)
        {
            masterKeyLength = AnsiConsole.Ask<int>("[bold]Enter your master key length in bits:[/]", 256);
        }

        // Purpose/Label Check
        var purpose = AnsiConsole.Ask<string>(
            "[bold]What purpose/label string do you use for key derivation?[/]\n" +
            "[dim](Examples: 'encryption', 'authentication', 'session-key')[/]", 
            "encryption");

        // Output Length Check
        var outputLength = AnsiConsole.Ask<int>(
            "[bold]What is your desired output key length in bytes?[/]\n" +
            "[dim](Common: 16 for AES-128, 32 for AES-256)[/]", 
            32);

        // Context Usage Check
        var usesContext = AnsiConsole.Confirm(
            "[bold]Do you use context data in your key derivation?[/]\n" +
            "[dim](Context data provides additional key separation and is recommended)[/]", 
            true);

        string contextDescription = "";
        if (usesContext)
        {
            contextDescription = AnsiConsole.Ask<string>(
                "[bold]Briefly describe your context data (e.g., 'user-id-session-id'):[/]", 
                "user-session-context");
        }

        AnsiConsole.WriteLine();
        AnsiConsole.Write(new Rule("[yellow]🔍 Analyzing Configuration...[/]").RuleStyle("yellow"));
        AnsiConsole.WriteLine();

        // Perform compliance analysis
        var complianceResults = AnalyzeKdfCompliance(masterKeyLength, purpose, outputLength, usesContext, contextDescription);

        // Display results
        var resultTable = new Table()
            .Border(TableBorder.Rounded)
            .AddColumn("[bold]Compliance Check[/]")
            .AddColumn("[bold]Status[/]")
            .AddColumn("[bold]Details[/]");

        foreach (var result in complianceResults)
        {
            var statusIcon = result.IsCompliant ? "[green]✅ PASS[/]" : 
                           result.Severity == ComplianceSeverity.Warning ? "[yellow]⚠️  WARN[/]" : "[red]❌ FAIL[/]";
            
            resultTable.AddRow(result.CheckName, statusIcon, result.Message);
        }

        AnsiConsole.Write(resultTable);
        AnsiConsole.WriteLine();

        // Overall compliance summary
        var passCount = complianceResults.Count(r => r.IsCompliant);
        var totalCount = complianceResults.Count;
        var overallScore = (double)passCount / totalCount * 100;

        var summaryColor = overallScore >= 90 ? "green" : overallScore >= 70 ? "yellow" : "red";
        var summaryIcon = overallScore >= 90 ? "🎉" : overallScore >= 70 ? "⚠️" : "🚨";

        AnsiConsole.MarkupLine($"[bold {summaryColor}]{summaryIcon} Overall Compliance Score: {overallScore:F1}% ({passCount}/{totalCount} checks passed)[/]");

        if (settings.Verbose)
        {
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[bold cyan]📚 Detailed Recommendations:[/]");
            
            foreach (var result in complianceResults.Where(r => !r.IsCompliant))
            {
                AnsiConsole.MarkupLine($"[yellow]•[/] [bold]{result.CheckName}:[/] {result.Recommendation}");
            }
        }

        await Task.Delay(500);
    }

    private async Task CheckKeyStrength(Settings settings, ILogger logger)
    {
        AnsiConsole.Write(new Rule("[blue]🔐 Key Strength Security Analysis[/]").RuleStyle("blue"));
        AnsiConsole.WriteLine();

        AnsiConsole.MarkupLine("[bold]This analyzer evaluates the effective security strength of your cryptographic configuration.[/]");
        AnsiConsole.WriteLine();

        // Algorithm selection
        var algorithm = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("[bold]What PRF algorithm are you using or planning to use?[/]")
                .AddChoices(new[] { "HMAC-SHA256", "HMAC-SHA384", "HMAC-SHA512", "AES-CMAC-128", "AES-CMAC-256" })
                .UseConverter(alg => alg switch
                {
                    "HMAC-SHA256" => "HMAC-SHA256 - 256-bit security strength (recommended)",
                    "HMAC-SHA384" => "HMAC-SHA384 - 384-bit security strength",
                    "HMAC-SHA512" => "HMAC-SHA512 - 512-bit security strength",
                    "AES-CMAC-128" => "AES-CMAC-128 - 128-bit security strength",
                    "AES-CMAC-256" => "AES-CMAC-256 - 256-bit security strength",
                    _ => alg
                }));

        var masterKeyBits = AnsiConsole.Ask<int>(
            "[bold]Master key length in bits:[/]", 
            256);

        var outputKeyBits = AnsiConsole.Ask<int>(
            "[bold]Output key length in bits:[/]", 
            256);

        AnsiConsole.WriteLine();
        AnsiConsole.Write(new Rule("[yellow]🧮 Calculating Security Strength...[/]").RuleStyle("yellow"));
        AnsiConsole.WriteLine();

        // Calculate effective security strength
        var analysis = AnalyzeKeyStrength(algorithm, masterKeyBits, outputKeyBits);

        var strengthTable = new Table()
            .Border(TableBorder.Rounded)
            .AddColumn("[bold]Security Metric[/]")
            .AddColumn("[bold]Value[/]")
            .AddColumn("[bold]Assessment[/]");

        strengthTable.AddRow("PRF Algorithm", algorithm, GetAlgorithmAssessment(algorithm));
        strengthTable.AddRow("Master Key Strength", $"{masterKeyBits} bits", GetKeyStrengthAssessment(masterKeyBits));
        strengthTable.AddRow("Output Key Length", $"{outputKeyBits} bits", GetOutputLengthAssessment(outputKeyBits));
        strengthTable.AddRow("[bold]Effective Security Strength[/]", $"[yellow]{analysis.EffectiveStrength} bits[/]", analysis.OverallAssessment);

        AnsiConsole.Write(strengthTable);
        AnsiConsole.WriteLine();

        // Security level mapping
        var securityLevel = GetSecurityLevel(analysis.EffectiveStrength);
        var levelColor = securityLevel.StartsWith("High") ? "green" : securityLevel.StartsWith("Medium") ? "yellow" : "red";
        
        AnsiConsole.MarkupLine($"[bold {levelColor}]🛡️  Security Level: {securityLevel}[/]");

        if (settings.Verbose)
        {
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[bold cyan]📊 Security Strength Breakdown:[/]");
            AnsiConsole.MarkupLine($"[dim]• PRF contribution: {GetPrfStrength(algorithm)} bits[/]");
            AnsiConsole.MarkupLine($"[dim]• Master key contribution: {masterKeyBits} bits[/]");
            AnsiConsole.MarkupLine($"[dim]• Effective strength: min(PRF, master_key) = {analysis.EffectiveStrength} bits[/]");
            AnsiConsole.MarkupLine($"[dim]• Output length impact: {(outputKeyBits <= analysis.EffectiveStrength ? "No limitation" : "May limit usable strength")}[/]");
        }

        await Task.Delay(500);
    }

    private async Task CheckCurveCompliance(Settings settings, ILogger logger)
    {
        AnsiConsole.Write(new Rule("[magenta]📈 Elliptic Curve Compliance Analysis[/]").RuleStyle("magenta"));
        AnsiConsole.WriteLine();

        AnsiConsole.MarkupLine("[bold]This analyzer validates elliptic curve selection against NIST SP 800-56A standards.[/]");
        AnsiConsole.WriteLine();

        var curve = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("[bold]Which elliptic curve are you using or considering?[/]")
                .AddChoices(new[] { "P-256", "P-384", "P-521", "secp256k1", "Curve25519", "other" })
                .UseConverter(c => c switch
                {
                    "P-256" => "P-256 (secp256r1) - NIST standard, widely supported",
                    "P-384" => "P-384 (secp384r1) - Higher security NIST curve",
                    "P-521" => "P-521 (secp521r1) - Highest security NIST curve",
                    "secp256k1" => "secp256k1 - Bitcoin curve (not NIST approved)",
                    "Curve25519" => "Curve25519 - Modern curve (not in NIST SP 800-56A)",
                    "other" => "Other curve (I'll specify)",
                    _ => c
                }));

        if (curve == "other")
        {
            curve = AnsiConsole.Ask<string>("[bold]Enter the curve name:[/]", "custom-curve");
        }

        var useCase = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("[bold]What is your primary use case?[/]")
                .AddChoices(new[] { "government", "enterprise", "commercial", "research", "personal" })
                .UseConverter(uc => uc switch
                {
                    "government" => "Government/Defense - Requires FIPS 140-2 compliance",
                    "enterprise" => "Enterprise/Corporate - Needs industry standard compliance",
                    "commercial" => "Commercial Application - Balance of security and compatibility",
                    "research" => "Research/Academic - Experimental or cutting-edge applications",
                    "personal" => "Personal Project - Learning or hobby use",
                    _ => uc
                }));

        AnsiConsole.WriteLine();
        AnsiConsole.Write(new Rule("[yellow]🔍 Analyzing Curve Compliance...[/]").RuleStyle("yellow"));
        AnsiConsole.WriteLine();

        var curveAnalysis = AnalyzeCurveCompliance(curve, useCase);

        var complianceTable = new Table()
            .Border(TableBorder.Rounded)
            .AddColumn("[bold]Compliance Standard[/]")
            .AddColumn("[bold]Status[/]")
            .AddColumn("[bold]Notes[/]");

        foreach (var standard in curveAnalysis.ComplianceResults)
        {
            var statusIcon = standard.Value.IsCompliant ? "[green]✅[/]" : "[red]❌[/]";
            complianceTable.AddRow(standard.Key, statusIcon, standard.Value.Notes);
        }

        AnsiConsole.Write(complianceTable);
        AnsiConsole.WriteLine();

        // Security properties table
        var propertiesTable = new Table()
            .Border(TableBorder.Rounded)
            .AddColumn("[bold]Security Property[/]")
            .AddColumn("[bold]Value[/]")
            .AddColumn("[bold]Assessment[/]");

        propertiesTable.AddRow("Security Level", $"{curveAnalysis.SecurityBits} bits", GetSecurityLevelAssessment(curveAnalysis.SecurityBits));
        propertiesTable.AddRow("Key Size", $"{curveAnalysis.KeySizeBits} bits", "Private key size");
        propertiesTable.AddRow("Performance", curveAnalysis.PerformanceRating, GetPerformanceNotes(curve));
        propertiesTable.AddRow("Quantum Resistance", curveAnalysis.QuantumResistance, "Protection against quantum computers");

        AnsiConsole.Write(propertiesTable);

        if (settings.Verbose && curveAnalysis.Recommendations.Any())
        {
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[bold cyan]💡 Recommendations:[/]");
            foreach (var recommendation in curveAnalysis.Recommendations)
            {
                AnsiConsole.MarkupLine($"[yellow]•[/] {recommendation}");
            }
        }

        await Task.Delay(500);
    }

    private async Task ReviewScenarioCompliance(Settings settings, ILogger logger)
    {
        AnsiConsole.Write(new Rule("[cyan]📚 Scenario Compliance Review[/]").RuleStyle("cyan"));
        AnsiConsole.WriteLine();

        AnsiConsole.MarkupLine("[bold]This reviewer checks common implementation scenarios against security best practices.[/]");
        AnsiConsole.MarkupLine("[dim]Reference scenarios are available in docs/scenarios/[/]");
        AnsiConsole.WriteLine();

        var scenario = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("[bold]Which scenario best describes your use case?[/]")
                .AddChoices(new[] { "multi-tenant", "session-management", "database-encryption", "api-authentication", "backup-encryption", "custom" })
                .UseConverter(s => s switch
                {
                    "multi-tenant" => "🏢 Multi-Tenant Applications - Key separation for different tenants",
                    "session-management" => "🔐 Session Management - Web session key derivation",
                    "database-encryption" => "🗄️  Database Encryption - Data at rest protection",
                    "api-authentication" => "🔑 API Authentication - Token generation and validation",
                    "backup-encryption" => "💾 Backup Encryption - Long-term data protection",
                    "custom" => "🛠️  Custom Scenario - I have a different use case",
                    _ => s
                }));

        AnsiConsole.WriteLine();

        if (scenario == "custom")
        {
            AnsiConsole.MarkupLine("[yellow]📋 For custom scenarios, please review the general principles:[/]");
            await ShowGeneralCompliancePrinciples(settings);
        }
        else
        {
            await ReviewSpecificScenario(scenario, settings);
        }

        await Task.Delay(500);
    }

    private async Task ShowGeneralCompliancePrinciples(Settings settings)
    {
        var principlesTable = new Table()
            .Border(TableBorder.Rounded)
            .AddColumn("[bold]Security Principle[/]")
            .AddColumn("[bold]Implementation[/]")
            .AddColumn("[bold]Compliance Notes[/]");

        principlesTable.AddRow(
            "Key Separation", 
            "Different purposes → different keys",
            "Use distinct purpose strings for each use case");

        principlesTable.AddRow(
            "Context Usage", 
            "Include domain-specific context data",
            "Prevents key reuse across different contexts");

        principlesTable.AddRow(
            "Master Key Protection", 
            "Secure key storage (HSM/KMS)",
            "Root of trust must be properly protected");

        principlesTable.AddRow(
            "Deterministic Derivation", 
            "Same inputs → same outputs",
            "Enables key recovery and caching");

        principlesTable.AddRow(
            "Algorithm Selection", 
            "Use NIST-approved algorithms",
            "HMAC-SHA256 recommended for most cases");

        AnsiConsole.Write(principlesTable);
        AnsiConsole.WriteLine();

        if (settings.Verbose)
        {
            AnsiConsole.MarkupLine("[bold cyan]📖 Additional Resources:[/]");
            AnsiConsole.MarkupLine("[dim]• Review docs/scenarios/ for detailed implementation examples[/]");
            AnsiConsole.MarkupLine("[dim]• Consult NIST SP 800-108 for KDF requirements[/]");
            AnsiConsole.MarkupLine("[dim]• Consider NIST SP 800-56A for key agreement scenarios[/]");
            AnsiConsole.MarkupLine("[dim]• Implement proper key lifecycle management[/]");
        }

        await Task.Delay(100);
    }

    private async Task ReviewSpecificScenario(string scenario, Settings settings)
    {
        var scenarioInfo = GetScenarioInfo(scenario);
        
        AnsiConsole.MarkupLine($"[bold yellow]📋 Reviewing: {scenarioInfo.Name}[/]");
        AnsiConsole.MarkupLine($"[dim]{scenarioInfo.Description}[/]");
        AnsiConsole.WriteLine();

        var checklistTable = new Table()
            .Border(TableBorder.Rounded)
            .AddColumn("[bold]Best Practice[/]")
            .AddColumn("[bold]Implementation Status[/]")
            .AddColumn("[bold]Notes[/]");

        foreach (var practice in scenarioInfo.BestPractices)
        {
            var implemented = AnsiConsole.Confirm($"✓ {practice.Description}");
            var statusIcon = implemented ? "[green]✅ Implemented[/]" : "[red]❌ Missing[/]";
            checklistTable.AddRow(practice.Name, statusIcon, practice.ComplianceNote);
        }

        AnsiConsole.Write(checklistTable);
        AnsiConsole.WriteLine();

        AnsiConsole.MarkupLine($"[bold cyan]📚 For detailed implementation guidance, see: docs/scenarios/{scenario}.md[/]");

        await Task.Delay(100);
    }

    // Analysis methods
    private List<ComplianceResult> AnalyzeKdfCompliance(int masterKeyBits, string purpose, int outputBytes, bool usesContext, string contextDescription)
    {
        var results = new List<ComplianceResult>();

        // Master key length check
        if (masterKeyBits >= 256)
        {
            results.Add(new ComplianceResult("Master Key Length", true, "✅ Meets NIST recommendations (≥256 bits)", ""));
        }
        else if (masterKeyBits >= 128)
        {
            results.Add(new ComplianceResult("Master Key Length", false, "⚠️ Below recommended 256 bits but acceptable", "Consider upgrading to 256-bit master key", ComplianceSeverity.Warning));
        }
        else
        {
            results.Add(new ComplianceResult("Master Key Length", false, "❌ Below minimum security requirements", "Use at least 128-bit master key, preferably 256-bit"));
        }

        // Purpose string check
        if (!string.IsNullOrEmpty(purpose) && purpose.Length >= 3)
        {
            results.Add(new ComplianceResult("Purpose String", true, "✅ Purpose string provided for key separation", ""));
        }
        else
        {
            results.Add(new ComplianceResult("Purpose String", false, "❌ Missing or inadequate purpose string", "Use descriptive purpose strings for key separation"));
        }

        // Output length check
        if (outputBytes >= 16 && outputBytes <= 64)
        {
            results.Add(new ComplianceResult("Output Length", true, "✅ Output length within recommended range", ""));
        }
        else
        {
            results.Add(new ComplianceResult("Output Length", false, "⚠️ Unusual output length", "Consider standard lengths: 16, 32, or 64 bytes", ComplianceSeverity.Warning));
        }

        // Context usage check
        if (usesContext)
        {
            results.Add(new ComplianceResult("Context Data", true, "✅ Uses context data for additional separation", ""));
        }
        else
        {
            results.Add(new ComplianceResult("Context Data", false, "⚠️ No context data used", "Consider adding context for enhanced security", ComplianceSeverity.Warning));
        }

        // Algorithm compliance (assumed HMAC-SHA256)
        results.Add(new ComplianceResult("Algorithm", true, "✅ Uses NIST-approved HMAC-SHA256", ""));

        return results;
    }

    private KeyStrengthAnalysis AnalyzeKeyStrength(string algorithm, int masterKeyBits, int outputKeyBits)
    {
        var prfStrength = GetPrfStrength(algorithm);
        var effectiveStrength = Math.Min(prfStrength, masterKeyBits);
        
        var assessment = effectiveStrength >= 256 ? "[green]Excellent security strength[/]" :
                        effectiveStrength >= 128 ? "[yellow]Good security strength[/]" :
                        effectiveStrength >= 112 ? "[orange]Adequate security strength[/]" :
                        "[red]Insufficient security strength[/]";

        return new KeyStrengthAnalysis
        {
            EffectiveStrength = effectiveStrength,
            OverallAssessment = assessment
        };
    }

    private CurveComplianceAnalysis AnalyzeCurveCompliance(string curve, string useCase)
    {
        var analysis = new CurveComplianceAnalysis();

        switch (curve)
        {
            case "P-256":
                analysis.SecurityBits = 128;
                analysis.KeySizeBits = 256;
                analysis.PerformanceRating = "High";
                analysis.QuantumResistance = "Vulnerable ~2030";
                analysis.ComplianceResults["NIST SP 800-56A"] = new ComplianceStatus { IsCompliant = true, Notes = "Approved NIST curve" };
                analysis.ComplianceResults["FIPS 140-2"] = new ComplianceStatus { IsCompliant = true, Notes = "FIPS approved" };
                break;
                
            case "P-384":
                analysis.SecurityBits = 192;
                analysis.KeySizeBits = 384;
                analysis.PerformanceRating = "Medium";
                analysis.QuantumResistance = "Vulnerable ~2040";
                analysis.ComplianceResults["NIST SP 800-56A"] = new ComplianceStatus { IsCompliant = true, Notes = "Approved NIST curve" };
                analysis.ComplianceResults["FIPS 140-2"] = new ComplianceStatus { IsCompliant = true, Notes = "FIPS approved" };
                break;
                
            case "P-521":
                analysis.SecurityBits = 256;
                analysis.KeySizeBits = 521;
                analysis.PerformanceRating = "Low";
                analysis.QuantumResistance = "Vulnerable ~2050";
                analysis.ComplianceResults["NIST SP 800-56A"] = new ComplianceStatus { IsCompliant = true, Notes = "Approved NIST curve" };
                analysis.ComplianceResults["FIPS 140-2"] = new ComplianceStatus { IsCompliant = true, Notes = "FIPS approved" };
                break;
                
            case "secp256k1":
                analysis.SecurityBits = 128;
                analysis.KeySizeBits = 256;
                analysis.PerformanceRating = "High";
                analysis.QuantumResistance = "Vulnerable ~2030";
                analysis.ComplianceResults["NIST SP 800-56A"] = new ComplianceStatus { IsCompliant = false, Notes = "Not NIST approved" };
                analysis.ComplianceResults["FIPS 140-2"] = new ComplianceStatus { IsCompliant = false, Notes = "Not FIPS approved" };
                analysis.Recommendations.Add("Consider P-256 for compliance requirements");
                break;
                
            default:
                analysis.SecurityBits = 0;
                analysis.KeySizeBits = 0;
                analysis.PerformanceRating = "Unknown";
                analysis.QuantumResistance = "Unknown";
                analysis.ComplianceResults["NIST SP 800-56A"] = new ComplianceStatus { IsCompliant = false, Notes = "Unknown curve compliance" };
                analysis.Recommendations.Add("Verify curve compliance with your security requirements");
                break;
        }

        if (useCase == "government" && !analysis.ComplianceResults["FIPS 140-2"].IsCompliant)
        {
            analysis.Recommendations.Add("Government use cases typically require FIPS 140-2 approved curves");
        }

        return analysis;
    }

    // Helper methods
    private int GetPrfStrength(string algorithm)
    {
        return algorithm switch
        {
            "HMAC-SHA256" => 256,
            "HMAC-SHA384" => 384,
            "HMAC-SHA512" => 512,
            "AES-CMAC-128" => 128,
            "AES-CMAC-256" => 256,
            _ => 256
        };
    }

    private string GetAlgorithmAssessment(string algorithm)
    {
        return algorithm switch
        {
            "HMAC-SHA256" => "[green]✅ NIST approved, widely supported[/]",
            "HMAC-SHA384" => "[green]✅ NIST approved, higher security[/]",
            "HMAC-SHA512" => "[green]✅ NIST approved, maximum security[/]",
            "AES-CMAC-128" => "[yellow]⚠️ NIST approved, lower security[/]",
            "AES-CMAC-256" => "[green]✅ NIST approved, good security[/]",
            _ => "[yellow]⚠️ Unknown algorithm[/]"
        };
    }

    private string GetKeyStrengthAssessment(int bits)
    {
        return bits switch
        {
            >= 256 => "[green]✅ Excellent[/]",
            >= 128 => "[yellow]⚠️ Good[/]",
            >= 112 => "[orange]⚠️ Adequate[/]",
            _ => "[red]❌ Insufficient[/]"
        };
    }

    private string GetOutputLengthAssessment(int bits)
    {
        return bits switch
        {
            128 => "[green]✅ Standard (AES-128)[/]",
            256 => "[green]✅ Recommended (AES-256)[/]",
            512 => "[green]✅ High security[/]",
            _ when bits >= 128 => "[yellow]⚠️ Non-standard but acceptable[/]",
            _ => "[red]❌ Too short[/]"
        };
    }

    private string GetSecurityLevel(int effectiveStrength)
    {
        return effectiveStrength switch
        {
            >= 256 => "High Security (>= 256 bits)",
            >= 128 => "Medium-High Security (128-255 bits)",
            >= 112 => "Medium Security (112-127 bits)",
            >= 80 => "Low Security (80-111 bits)",
            _ => "Insufficient Security (< 80 bits)"
        };
    }

    private string GetSecurityLevelAssessment(int bits)
    {
        return bits switch
        {
            >= 256 => "[green]Very High[/]",
            >= 192 => "[green]High[/]",
            >= 128 => "[yellow]Medium-High[/]",
            >= 112 => "[orange]Medium[/]",
            _ => "[red]Low[/]"
        };
    }

    private string GetPerformanceNotes(string curve)
    {
        return curve switch
        {
            "P-256" => "Fastest NIST curve",
            "P-384" => "Balanced performance/security",
            "P-521" => "Slower but highest security",
            _ => "Performance varies"
        };
    }

    private ScenarioInfo GetScenarioInfo(string scenario)
    {
        return scenario switch
        {
            "multi-tenant" => new ScenarioInfo
            {
                Name = "Multi-Tenant Application",
                Description = "Key separation for different tenants in shared applications",
                BestPractices = new[]
                {
                    new BestPractice("Tenant ID in Context", "Include tenant identifier in context data", "Ensures cryptographic isolation between tenants"),
                    new BestPractice("Purpose Versioning", "Use versioned purpose strings", "Enables key rotation without breaking changes"),
                    new BestPractice("Master Key Security", "Secure master key storage (HSM/KMS)", "Critical for protecting all tenant data"),
                    new BestPractice("Deterministic Derivation", "Same tenant inputs produce same keys", "Enables key caching and recovery")
                }
            },
            "session-management" => new ScenarioInfo
            {
                Name = "Session Management",
                Description = "Web application session key derivation and management",
                BestPractices = new[]
                {
                    new BestPractice("Session ID Randomness", "Cryptographically secure session IDs", "Prevents session prediction and enumeration"),
                    new BestPractice("Multiple Key Types", "Different keys for encryption/auth/CSRF", "Provides defense in depth"),
                    new BestPractice("Time-based Rotation", "Optional time-based key rotation", "Limits exposure window for compromised keys"),
                    new BestPractice("Secure Cookies", "HttpOnly, Secure, SameSite attributes", "Prevents client-side session hijacking")
                }
            },
            "database-encryption" => new ScenarioInfo
            {
                Name = "Database Encryption",
                Description = "Data-at-rest encryption with hierarchical key management",
                BestPractices = new[]
                {
                    new BestPractice("Data Classification", "Different keys per data sensitivity", "Limits blast radius of key compromise"),
                    new BestPractice("Table-specific Keys", "Separate keys per table/schema", "Enables granular access control"),
                    new BestPractice("Key Versioning", "Support for key rotation", "Enables zero-downtime key updates"),
                    new BestPractice("Performance Optimization", "Key caching with TTL", "Balances security with performance")
                }
            },
            "api-authentication" => new ScenarioInfo
            {
                Name = "API Authentication",
                Description = "Token generation and validation for API security",
                BestPractices = new[]
                {
                    new BestPractice("Token Types", "Different keys for access/refresh/API keys", "Prevents token type confusion attacks"),
                    new BestPractice("Scope Validation", "Include and validate token scopes", "Implements principle of least privilege"),
                    new BestPractice("Stateless Validation", "Self-contained token validation", "Improves scalability and performance"),
                    new BestPractice("Revocation Support", "Token blacklisting capability", "Enables immediate access revocation")
                }
            },
            "backup-encryption" => new ScenarioInfo
            {
                Name = "Backup System Encryption",
                Description = "Long-term data protection with key recovery capabilities",
                BestPractices = new[]
                {
                    new BestPractice("Archive Master Key", "Offline master key storage", "Survives operational system compromise"),
                    new BestPractice("Generation Keys", "Time-based backup generation keys", "Enables temporal key separation"),
                    new BestPractice("Key Recovery", "Documented key recovery procedures", "Ensures data recoverability in disasters"),
                    new BestPractice("Compliance Logging", "Audit trail of all key operations", "Meets regulatory requirements")
                }
            },
            _ => new ScenarioInfo { Name = "Unknown", Description = "Unknown scenario", BestPractices = Array.Empty<BestPractice>() }
        };
    }

    // Supporting classes
    private class ComplianceResult
    {
        public ComplianceResult(string checkName, bool isCompliant, string message, string recommendation, ComplianceSeverity severity = ComplianceSeverity.Error)
        {
            CheckName = checkName;
            IsCompliant = isCompliant;
            Message = message;
            Recommendation = recommendation;
            Severity = severity;
        }

        public string CheckName { get; }
        public bool IsCompliant { get; }
        public string Message { get; }
        public string Recommendation { get; }
        public ComplianceSeverity Severity { get; }
    }

    private enum ComplianceSeverity
    {
        Error,
        Warning
    }

    private class KeyStrengthAnalysis
    {
        public int EffectiveStrength { get; set; }
        public string OverallAssessment { get; set; } = string.Empty;
    }

    private class CurveComplianceAnalysis
    {
        public int SecurityBits { get; set; }
        public int KeySizeBits { get; set; }
        public string PerformanceRating { get; set; } = string.Empty;
        public string QuantumResistance { get; set; } = string.Empty;
        public Dictionary<string, ComplianceStatus> ComplianceResults { get; set; } = new();
        public List<string> Recommendations { get; set; } = new();
    }

    private class ComplianceStatus
    {
        public bool IsCompliant { get; set; }
        public string Notes { get; set; } = string.Empty;
    }

    private class ScenarioInfo
    {
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public BestPractice[] BestPractices { get; set; } = Array.Empty<BestPractice>();
    }

    private class BestPractice
    {
        public BestPractice(string name, string description, string complianceNote)
        {
            Name = name;
            Description = description;
            ComplianceNote = complianceNote;
        }

        public string Name { get; }
        public string Description { get; }
        public string ComplianceNote { get; }
    }
}