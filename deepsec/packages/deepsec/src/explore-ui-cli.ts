import { Command } from "commander";
import {
  exploreBundleCommand,
  exploreCiCommand,
  exploreCommand,
  exploreDoctorCommand,
  exploreListCommand,
  exploreManifestCommand,
  exploreRetryCommand,
  exploreSetupCommand,
  exploreStatusCommand,
  exploreVerifyBundleCommand,
  exploreVerifyManifestCommand,
} from "./commands/explore.js";

const program = new Command().name("deepsec");
const explore = program.command("explore");

function addRunOptions(command: Command): Command {
  return command
    .option("--project-id <id>")
    .option("--root <path>")
    .option("--profile <profile>", "Explore runtime profile", "java11-gradle")
    .option("--runtime <runtime>", "Docker runtime", "runsc")
    .option("--model-provider <provider>")
    .option("--model <model>")
    .option("--rank-model <model>")
    .option("--reasoning-effort <effort>")
    .option("--stub-model")
    .option("--live-model-check")
    .option("--limit <n>", "Ranked files to explore", Number.parseInt)
    .option("--all-files")
    .option("--concurrency <n>", "Parallel attempts", Number.parseInt)
    .option("--max-turns <n>", "Maximum turns per attempt", Number.parseInt)
    .option("--max-tokens <n>", "Reported-token budget", Number.parseInt)
    .option("--max-cost-usd <n>", "Reported-cost budget", Number.parseFloat);
}

addRunOptions(explore.command("run", { isDefault: true })).action(exploreCommand);

explore
  .command("setup")
  .option("--profile <profile>", "Explore runtime profile", "java11-gradle")
  .action(exploreSetupCommand);

addRunOptions(explore.command("doctor")).action(exploreDoctorCommand);

explore
  .command("list")
  .option("--project-id <id>")
  .option("--json")
  .option("--limit <n>", "Maximum runs", Number.parseInt)
  .action(exploreListCommand);

explore
  .command("status")
  .option("--project-id <id>")
  .option("--run-id <id>")
  .option("--json")
  .option("--min-severity <severity>")
  .option("--fail-on-accepted-findings")
  .action(exploreStatusCommand);

explore
  .command("ci")
  .option("--project-id <id>")
  .option("--run-id <id>")
  .option("--min-severity <severity>")
  .option("--out-dir <path>")
  .option("--no-fail-on-accepted-findings")
  .option("--no-report")
  .option("--no-export-json")
  .option("--no-export-sarif")
  .option("--no-junit")
  .action(exploreCiCommand);

explore
  .command("manifest")
  .option("--project-id <id>")
  .option("--run-id <id>")
  .option("--json")
  .option("--out <path>")
  .option("--min-severity <severity>")
  .option("--fail-on-accepted-findings")
  .option("--require-report")
  .option("--require-ci")
  .option("--fail-on-warnings")
  .action(exploreManifestCommand);

explore
  .command("verify-manifest <manifest>")
  .option("--json")
  .action((manifest, opts) => exploreVerifyManifestCommand({ ...opts, manifest }));

explore
  .command("bundle <manifest>")
  .option("--out-dir <path>")
  .option("--include-attempts")
  .option("--force")
  .option("--json")
  .action((manifest, opts) => exploreBundleCommand({ ...opts, manifest }));

explore
  .command("verify-bundle <bundle-dir>")
  .option("--json")
  .action((bundleDir, opts) => exploreVerifyBundleCommand({ ...opts, bundleDir }));

addRunOptions(explore.command("retry").option("--run-id <id>").option("--all")).action(
  exploreRetryCommand,
);

function printFatal(error: unknown): never {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
}

process.on("unhandledRejection", printFatal);
process.on("uncaughtException", printFatal);
program.parseAsync().catch(printFatal);
