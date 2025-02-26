namespace Microsoft.ComponentDetection.Detectors.Rust;

using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.ComponentDetection.Contracts;
using Microsoft.ComponentDetection.Contracts.Internal;
using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.ComponentDetection.Detectors.Rust.Sbom.Contracts;
using Microsoft.Extensions.Logging;

public class RustSbomDetector : FileComponentDetector
{
    private const string CargoSbomSearchPattern = "*.cargo-sbom.json";
    private const string CratesIoSource = "registry+https://github.com/rust-lang/crates.io-index";

    /// <summary>
    /// Cargo Package ID: source#name@version
    /// https://rustwiki.org/en/cargo/reference/pkgid-spec.html.
    /// </summary>
    private static readonly Regex CargoPackageIdRegex = new Regex(
        @"^(?<source>[^#]*)#?(?<name>[\w\-]*)[@#]?(?<version>\d[\S]*)?$",
        RegexOptions.Compiled);

    public RustSbomDetector(
        IComponentStreamEnumerableFactory componentStreamEnumerableFactory,
        IObservableDirectoryWalkerFactory walkerFactory,
        ILogger<RustSbomDetector> logger)
    {
        this.ComponentStreamEnumerableFactory = componentStreamEnumerableFactory;
        this.Scanner = walkerFactory;
        this.Logger = logger;
    }

    public override string Id => "RustSbomDetector";

    public override IList<string> SearchPatterns => [CargoSbomSearchPattern];

    public override IEnumerable<ComponentType> SupportedComponentTypes => [ComponentType.Cargo];

    public override int Version { get; } = 1;

    public override IEnumerable<string> Categories => ["Rust"];

    private static bool ParsePackageIdSpec(string dependency, out CargoComponent component)
    {
        var match = CargoPackageIdRegex.Match(dependency);
        var packageNameMatch = match.Groups["name"];
        var versionMatch = match.Groups["version"];
        var sourceMatch = match.Groups["source"];

        var name = packageNameMatch.Success ? packageNameMatch.Value : null;
        var version = versionMatch.Success ? versionMatch.Value : null;
        var source = sourceMatch.Success ? sourceMatch.Value : null;

        if (string.IsNullOrWhiteSpace(source))
        {
            source = null;
        }

        component = new CargoComponent(name, version, source: source);

        return match.Success;
    }

    protected override async Task OnFileFoundAsync(ProcessRequest processRequest, IDictionary<string, string> detectorArgs, CancellationToken cancellationToken = default)
    {
        var singleFileComponentRecorder = processRequest.SingleFileComponentRecorder;
        var components = processRequest.ComponentStream;
        var reader = new StreamReader(components.Stream);
        var cargoSbom = CargoSbom.FromJson(await reader.ReadToEndAsync(cancellationToken));
        this.RecordLockfileVersion(cargoSbom.Version);
        this.ProcessCargoSbom(cargoSbom, singleFileComponentRecorder, components);
    }

    private void ProcessDependency(CargoSbom sbom, SbomCrate package, ISingleFileComponentRecorder recorder, IComponentStream components, CargoComponent parent = null, int depth = 0)
    {
        foreach (var dependency in package.Dependencies)
        {
            var dep = sbom.Crates[dependency.Index];
            if (ParsePackageIdSpec(dep.Id, out var component))
            {
                if (component.Source == CratesIoSource)
                {
                    recorder.RegisterUsage(new DetectedComponent(component), isExplicitReferencedDependency: depth <= 1, parent?.Id, isDevelopmentDependency: false);
                }
            }
            else
            {
                this.Logger.LogError(null, "Failed to parse Cargo PackageIdSpec '{}' in '{}'", dep.Id, components.Location);
                recorder.RegisterPackageParseFailure(dep.Id);
            }

            this.ProcessDependency(sbom, dep, recorder, components, component, depth + 1);
        }
    }

    private void ProcessCargoSbom(CargoSbom sbom, ISingleFileComponentRecorder recorder, IComponentStream components)
    {
        try
        {
            this.ProcessDependency(sbom, sbom.Crates[sbom.Root], recorder, components);
        }
        catch (Exception e)
        {
            // If something went wrong, just ignore the file
            this.Logger.LogError(e, "Failed to process Cargo SBOM file '{}'", components.Location);
        }
    }
}
