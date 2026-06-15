import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import os from "node:os";
import path from "node:path";
import { execFileCapture } from "./process.js";
import { EXPLORE_IMAGE, EXPLORE_PROFILE, type ExploreProfile } from "./types.js";

export async function setupExploreProfile(profile: string | undefined): Promise<void> {
  if ((profile ?? EXPLORE_PROFILE) !== EXPLORE_PROFILE) {
    throw new Error(
      `Unsupported explore profile ${JSON.stringify(profile)}. Supported: ${EXPLORE_PROFILE}.`,
    );
  }
  await assertLocalUbuntuBase();
  const arch = process.arch === "arm64" ? "aarch64" : process.arch === "x64" ? "x64" : null;
  if (!arch) {
    throw new Error(`Unsupported host architecture ${process.arch}; expected arm64 or x64.`);
  }
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-explore-setup-"));
  try {
    const jdk11TarPath = path.join(temp, "jdk11.tar.gz");
    const jdk17TarPath = path.join(temp, "jdk17.tar.gz");
    const jdk11Url = `https://api.adoptium.net/v3/binary/latest/11/ga/linux/${arch}/jdk/hotspot/normal/eclipse?project=jdk`;
    const jdk17Url = `https://api.adoptium.net/v3/binary/latest/17/ga/linux/${arch}/jdk/hotspot/normal/eclipse?project=jdk`;
    console.log(`Downloading Temurin/OpenJDK 11 for linux/${arch}...`);
    await download(jdk11Url, jdk11TarPath);
    console.log(`Downloading Temurin/OpenJDK 17 for linux/${arch}...`);
    await download(jdk17Url, jdk17TarPath);
    fs.writeFileSync(path.join(temp, "Dockerfile"), dockerfile());
    console.log(`Building ${EXPLORE_IMAGE} from local ubuntu:22.04...`);
    const build = await execFileCapture("docker", ["build", "-t", EXPLORE_IMAGE, temp], {
      timeoutMs: 10 * 60_000,
      outputLimit: 128_000,
    });
    if (build.exitCode !== 0) {
      throw new Error(`Failed to build ${EXPLORE_IMAGE}:\n${build.stdout}\n${build.stderr}`);
    }
    console.log(`Built ${EXPLORE_IMAGE}.`);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
}

export function assertExploreProfile(profile: string | undefined): ExploreProfile {
  if ((profile ?? EXPLORE_PROFILE) !== EXPLORE_PROFILE) {
    throw new Error(
      `Unsupported explore profile ${JSON.stringify(profile)}. Supported: ${EXPLORE_PROFILE}.`,
    );
  }
  return EXPLORE_PROFILE;
}

async function assertLocalUbuntuBase(): Promise<void> {
  const inspect = await execFileCapture("docker", ["image", "inspect", "ubuntu:22.04"], {
    timeoutMs: 15_000,
  });
  if (inspect.exitCode !== 0) {
    throw new Error(
      "Local image ubuntu:22.04 is required for explore setup. Pull it once with `docker pull ubuntu:22.04`, then rerun setup.",
    );
  }
}

function dockerfile(): string {
  return `FROM ubuntu:22.04
COPY jdk11.tar.gz /tmp/jdk11.tar.gz
COPY jdk17.tar.gz /tmp/jdk17.tar.gz
RUN mkdir -p /opt/java/jdk-11 /opt/java/jdk-17 /workspace/target /workspace/out /workspace/home /workspace/gradle-cache \\
  && tar -xzf /tmp/jdk11.tar.gz -C /opt/java/jdk-11 --strip-components=1 \\
  && tar -xzf /tmp/jdk17.tar.gz -C /opt/java/jdk-17 --strip-components=1 \\
  && rm /tmp/jdk11.tar.gz /tmp/jdk17.tar.gz
ENV JAVA_HOME=/opt/java/jdk-17
ENV JDK11_HOME=/opt/java/jdk-11
ENV GRADLE_OPTS="-Dorg.gradle.java.installations.paths=/opt/java/jdk-11,/opt/java/jdk-17 -Dorg.gradle.java.installations.auto-download=false"
ENV PATH="/opt/java/jdk-17/bin:/opt/java/jdk-11/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
WORKDIR /workspace/target
CMD ["sh", "-lc", "sleep infinity"]
`;
}

async function download(url: string, dest: string, redirects = 0): Promise<void> {
  if (redirects > 5) throw new Error(`Too many redirects while downloading ${url}`);
  await new Promise<void>((resolve, reject) => {
    const client = url.startsWith("https:") ? https : http;
    const request = client.get(url, (response) => {
      const status = response.statusCode ?? 0;
      const location = response.headers.location;
      if (status >= 300 && status < 400 && location) {
        response.resume();
        download(new URL(location, url).toString(), dest, redirects + 1).then(resolve, reject);
        return;
      }
      if (status < 200 || status >= 300) {
        response.resume();
        reject(new Error(`Download failed with HTTP ${status} for ${url}`));
        return;
      }
      const out = fs.createWriteStream(dest);
      response.pipe(out);
      out.on("finish", () => out.close(() => resolve()));
      out.on("error", reject);
    });
    request.on("error", reject);
  });
}
