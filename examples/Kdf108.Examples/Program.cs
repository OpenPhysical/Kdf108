using System.Linq;
using Kdf108.Examples;
using Microsoft.Extensions.Logging;
using Spectre.Console.Cli;

// --verbose shows the library's Debug log messages. It is read here because logging is set up
// when the container is built, before the command line is parsed.
var logLevel = args.Contains("--verbose") ? LogLevel.Debug : LogLevel.Warning;
var app = new CommandApp(ExampleApp.Registrar(ExampleApp.Services(logLevel)));
app.Configure(ExampleApp.Configure);
return app.Run(args);
