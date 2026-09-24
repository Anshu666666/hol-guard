import { extname } from "node:path";

const SENTINEL = "guard-private-command-sentinel";

export async function assertProofArtifactsPrivate(proofDir: string, session: string): Promise<void> {
  for await (const relative of new Bun.Glob("**/*").scan({ cwd: proofDir, onlyFiles: true })) {
    if (extname(relative) === ".zip") throw new Error("trace archive retained in installed dashboard proof");
    const artifact = Bun.file(`${proofDir}/${relative}`);
    const content = await artifact.text();
    const sanitized = session.length > 0 ? content.replaceAll(session, "[REDACTED]") : content;
    if (sanitized !== content) await Bun.write(artifact, sanitized);
    const hasSession = session.length > 0 && sanitized.includes(session);
    const hasCommand = sanitized.includes(SENTINEL);
    if (hasSession || hasCommand) {
      throw new Error(
        `private value retained in installed dashboard proof: ${relative} (session=${hasSession}, command=${hasCommand})`,
      );
    }
  }
}
