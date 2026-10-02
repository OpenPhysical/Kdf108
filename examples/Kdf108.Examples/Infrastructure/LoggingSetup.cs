using System.IO;
using System.Reflection;
using log4net;
using log4net.Config;
using Microsoft.Extensions.Logging;

namespace Kdf108.Examples.Infrastructure;

public static class LoggingSetup
{
    public static ILoggerFactory CreateLoggerFactory(bool verbose)
    {
        // Configure log4net from config file
        var logRepository = LogManager.GetRepository(Assembly.GetExecutingAssembly());
        var configFile = new FileInfo("log4net.config");
        
        if (configFile.Exists)
        {
            XmlConfigurator.Configure(logRepository, configFile);
        }
        else
        {
            // Fallback to basic configuration
            BasicConfigurator.Configure(logRepository);
        }

        // Create Microsoft.Extensions.Logging factory that writes to log4net
        return LoggerFactory.Create(builder =>
        {
            builder.AddLog4Net();
            builder.SetMinimumLevel(verbose ? LogLevel.Debug : LogLevel.Information);
            
            // Also add console for immediate feedback
            builder.AddConsole(options =>
            {
                options.FormatterName = "simple";
            });
        });
    }
}
