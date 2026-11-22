const MAX_IMPORT_BYTES = 8 * 1024 * 1024;

export function importFileError(error: unknown) {
  if (error instanceof Error && error.message === "large") return "dropTooLarge";
  if (error instanceof Error && error.message === "npv") return "protectedNpvFile";
  return "dropUnreadable";
}

export function canDropImport(data: DataTransfer | null): boolean {
  return !!data && (data.types.includes("Files") || data.types.includes("text/plain") || data.types.includes("text/uri-list"));
}

export async function readDroppedImport(data: DataTransfer): Promise<string> {
  const files = Array.from(data.files);
  if (files.length) return readImportFiles(files);
  const text = data.getData("text/plain") || data.getData("text/uri-list").split(/\r?\n/).filter((x) => !x.startsWith("#")).join("\n");
  if (new TextEncoder().encode(text).length > MAX_IMPORT_BYTES) throw new Error("large");
  return text.trim();
}

export async function readImportFiles(files: File[]): Promise<string> {
  if (files.reduce((total, file) => total + file.size + 1, 0) > MAX_IMPORT_BYTES) throw new Error("large");
  const parts: string[] = [];
  for (const file of files) {
    const bytes = new Uint8Array(await file.arrayBuffer());
    const encoding = bytes[0] === 0xff && bytes[1] === 0xfe ? "utf-16le" :
      bytes[0] === 0xfe && bytes[1] === 0xff ? "utf-16be" : "utf-8";
    try {
      const content = new TextDecoder(encoding, { fatal: true }).decode(bytes);
      if (content.includes("\0")) throw new Error("binary");
      parts.push(content.trim());
    } catch {
      throw new Error(/\.npv$/i.test(file.name) ? "npv" : "binary");
    }
  }
  const text = parts.join("\n").trim();
  if (new TextEncoder().encode(text).length > MAX_IMPORT_BYTES) throw new Error("large");
  return text;
}
