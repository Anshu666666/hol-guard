import { extname } from "node:path";

const SENTINEL = "guard-private-command-sentinel";

export async function assertProofArtifactsPrivate(proofDir: string, session: string): Promise<void> {
  for await (const relative of new Bun.Glob("**/*").scan({ cwd: proofDir, onlyFiles: true })) {
    if (extname(relative) === ".zip") throw new Error("trace archive retained in installed dashboard proof");
    const artifactPath = `${proofDir}/${relative}`;
    const artifact = Bun.file(artifactPath);
    const content = await artifact.text();
    let sanitized = content;
    if (extname(relative) === ".md") {
      if (session.length > 0) sanitized = sanitized.replaceAll(session, "[REDACTED]");
      sanitized = sanitized.replaceAll(SENTINEL, "[REDACTED]");
    }
    if (sanitized !== content) await Bun.write(artifactPath, sanitized);
    const hasSession = session.length > 0 && sanitized.includes(session);
    const hasCommand = sanitized.includes(SENTINEL);
    if (hasSession || hasCommand) {
      throw new Error(
        `private value retained in installed dashboard proof: ${relative} (session=${hasSession}, command=${hasCommand})`,
      );
    }
  }
}
