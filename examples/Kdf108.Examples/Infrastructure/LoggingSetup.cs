using Microsoft.Extensions.Logging;

namespace Kdf108.Examples.Infrastructure;

public static class LoggingSetup
{
    public static ILoggerFactory CreateLoggerFactory(bool verbose)
    {
        return LoggerFactory.Create(builder =>
        {
            builder.SetMinimumLevel(verbose ? LogLevel.Debug : LogLevel.Information);
            builder.AddConsole(options =>
            {
                options.FormatterName = "simple";
            });
        });
    }
}
