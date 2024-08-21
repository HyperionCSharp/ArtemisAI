using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Memory;

namespace ArtemisSecurity
{
    class Program
    {
        static async Task Main(string[] args)
        {
            var cache = new MemoryCache(new MemoryCacheOptions());
            var analyzer = new ThreatAnalyzer(cache);

            try
            {
                // Initialize the analyzer and train the model
                await analyzer.InitializeAsync();

                Console.WriteLine("Artemis Security AI is running in the background.");
                Console.WriteLine("Press Ctrl+C to exit.");

                using (var cts = new CancellationTokenSource())
                {
                    Console.CancelKeyPress += (s, e) =>
                    {
                        e.Cancel = true;
                        cts.Cancel();
                    };

                    while (!cts.Token.IsCancellationRequested)
                    {
                        // Monitor and log any blacklisted processes
                        var detectedThreats = analyzer.MonitorAndLogProcesses();

                        foreach (var threat in detectedThreats)
                        {
                            await analyzer.LogAndAnalyzeThreat(threat.Name, threat.Level);
                        }

                        // Preform visual analysis on the screen
                        analyzer.PreformVisualAnalysis();

                        // Retrain the model periodically
                        await analyzer.InitializeAsync();

                        // Wait for a short period before the next check
                        await Task.Delay(5000, cts.Token);
                    }
                }
            }
            catch (TaskCanceledException)
            {
                Console.WriteLine("Artemis Security AI has been stopped.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred: {ex.Message}");
                Console.WriteLine($"Stack trace: {ex.StackTrace}");
            }
        }
    }
}
