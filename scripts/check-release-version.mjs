import { readFileSync } from "node:fs";

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
const config = "src-tauri/tauri.conf.json";
const { version } = JSON.parse(read(config));
if (!/^\d+\.\d+\.\d+$/.test(version)) throw new Error(`Invalid release version in ${config}`);

function check(file, actual) {
  if (actual !== version) throw new Error(`${file}: expected ${version}, found ${actual ?? "no version"}`);
}

check("package.json", JSON.parse(read("package.json")).version);
const npmLock = JSON.parse(read("package-lock.json"));
check("package-lock.json", npmLock.version);
check("package-lock.json root package", npmLock.packages?.[""]?.version);
check("packaging/arch/PKGBUILD", read("packaging/arch/PKGBUILD").match(/^pkgver=(\S+)$/m)?.[1]);

for (const [folder, name] of [["src-tauri", "phi2ray"], ["src-tauri/cli", "phi2ray-cli"], ["src-tauri/helper", "phi2ray-helper"]]) {
  for (const file of [`${folder}/Cargo.toml`, `${folder}/Cargo.lock`]) {
    const versionLine = new RegExp(`^name = "${name}"\\r?\\nversion = "([^"]+)"`, "m");
    check(file, read(file).match(versionLine)?.[1]);
  }
}

if (process.env.GITHUB_REF_TYPE === "tag" && process.env.GITHUB_REF_NAME !== `v${version}`) {
  throw new Error(`Tag ${process.env.GITHUB_REF_NAME} must be v${version}`);
}
console.log(`Release versions agree on ${version}`);
