use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use dbx_rs_config::load_effective_config;
use dbx_rs_secure_store::{DeploymentAuthority, read_private_limited, verify_deployment_envelope};
use flate2::{Compression, GzBuilder};
use ring::digest::{SHA256, digest};
use serde::Serialize;
use tar::{Builder as TarBuilder, EntryType, Header};

use crate::authority::{self, AuthorityMaterial};
use crate::{BuilderError, BuilderResult};

const MAX_BINARY_BYTES: u64 = 512 * 1024 * 1024;
const MAX_PACKAGE_FILE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_PRIVATE_KEY_BYTES: u64 = 4 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PlatformSelection {
    All,
    Linux,
    Windows,
}

impl PlatformSelection {
    pub(crate) fn parse(value: &str) -> BuilderResult<Self> {
        match value {
            "all" => Ok(Self::All),
            "linux" => Ok(Self::Linux),
            "windows" => Ok(Self::Windows),
            _ => Err(BuilderError::new(
                "--platform must be all, linux, or windows",
            )),
        }
    }

    fn platforms(self) -> &'static [Platform] {
        match self {
            Self::All => &[Platform::Linux, Platform::Windows],
            Self::Linux => &[Platform::Linux],
            Self::Windows => &[Platform::Windows],
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct BuildOptions {
    pub(crate) authority_dir: PathBuf,
    pub(crate) output_dir: PathBuf,
    pub(crate) template_dir: Option<PathBuf>,
    pub(crate) target_dir: Option<PathBuf>,
    pub(crate) config_dir: Option<PathBuf>,
    pub(crate) linux_overlay: Option<PathBuf>,
    pub(crate) windows_overlay: Option<PathBuf>,
    pub(crate) platforms: PlatformSelection,
    pub(crate) archive: bool,
}

pub(crate) struct BuildOutput {
    pub(crate) app_directory: PathBuf,
    pub(crate) archive: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Platform {
    Linux,
    Windows,
}

impl Platform {
    const fn app_id(self) -> &'static str {
        match self {
            Self::Linux => "TA-dbx-rs-linux-x86_64",
            Self::Windows => "TA-dbx-rs-windows-x86_64",
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Linux => "linux-x86_64",
            Self::Windows => "windows-x86_64",
        }
    }

    const fn target(self) -> &'static str {
        match self {
            Self::Linux => "x86_64-unknown-linux-musl",
            Self::Windows => "x86_64-pc-windows-msvc",
        }
    }

    const fn executable_suffix(self) -> &'static str {
        match self {
            Self::Linux => "",
            Self::Windows => ".exe",
        }
    }

    fn binary_name(self, base: &str) -> String {
        format!("{base}{}", self.executable_suffix())
    }
}

#[derive(Serialize)]
struct BuildManifest {
    schema_version: u8,
    app_id: String,
    platform: String,
    rust_target: String,
    version: String,
    authority_sha256: String,
    files: Vec<ManifestFile>,
}

#[derive(Serialize)]
struct ManifestFile {
    path: String,
    bytes: u64,
    sha256: String,
}

struct ResolvedBuild {
    repo_root: PathBuf,
    output_dir: PathBuf,
    template_dir: PathBuf,
    target_dir: PathBuf,
    config_dir: Option<PathBuf>,
    linux_overlay: Option<PathBuf>,
    windows_overlay: Option<PathBuf>,
    authority: AuthorityMaterial,
}

pub(crate) fn build(options: &BuildOptions) -> BuilderResult<Vec<BuildOutput>> {
    let resolved = resolve_build(options)?;
    let mut private_key =
        read_private_limited(&resolved.authority.private_key_file, MAX_PRIVATE_KEY_BYTES)
            .map_err(|error| BuilderError::new(error.to_string()))?;
    let result = build_platforms(options, &resolved, &private_key);
    private_key.fill(0);
    result
}

fn build_platforms(
    options: &BuildOptions,
    resolved: &ResolvedBuild,
    private_key: &[u8],
) -> BuilderResult<Vec<BuildOutput>> {
    let mut outputs = Vec::new();
    for platform in options.platforms.platforms() {
        compile(*platform, resolved)?;
        outputs.push(assemble(*platform, options.archive, resolved, private_key)?);
    }
    Ok(outputs)
}

fn resolve_build(options: &BuildOptions) -> BuilderResult<ResolvedBuild> {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| BuilderError::new("failed to resolve repository root"))?
        .canonicalize()
        .map_err(|_| BuilderError::new("repository root is unavailable"))?;
    let current = std::env::current_dir()
        .map_err(|_| BuilderError::new("failed to resolve current directory"))?;
    let output_dir = absolute_from(&options.output_dir, &current);
    fs::create_dir_all(&output_dir)
        .map_err(|_| BuilderError::new("failed to create build output directory"))?;
    let output_dir = output_dir
        .canonicalize()
        .map_err(|_| BuilderError::new("build output directory is unavailable"))?;
    let template_candidate = options.template_dir.as_ref().map_or_else(
        || repo_root.join("packaging/splunk/TA-dbx-rs"),
        |path| absolute_from(path, &current),
    );
    let template_dir = canonical_directory(&template_candidate, "Splunk app template")?;
    if output_dir.starts_with(&template_dir) {
        return Err(BuilderError::new(
            "build output directory cannot be inside the app template",
        ));
    }
    let target_dir = options.target_dir.as_ref().map_or_else(
        || repo_root.join("target"),
        |path| absolute_from(path, &current),
    );
    let config_dir = canonical_optional_directory(options.config_dir.as_ref(), &current, "config")?;
    let linux_overlay =
        canonical_optional_directory(options.linux_overlay.as_ref(), &current, "Linux overlay")?;
    let windows_overlay = canonical_optional_directory(
        options.windows_overlay.as_ref(),
        &current,
        "Windows overlay",
    )?;
    let authority = authority::load(&absolute_from(&options.authority_dir, &current))?;
    Ok(ResolvedBuild {
        repo_root,
        output_dir,
        template_dir,
        target_dir,
        config_dir,
        linux_overlay,
        windows_overlay,
        authority,
    })
}

fn compile(platform: Platform, build: &ResolvedBuild) -> BuilderResult<()> {
    let mut command = Command::new("cargo");
    if platform == Platform::Windows && !cfg!(windows) {
        command.arg("xwin");
    }
    command
        .arg("build")
        .arg("--locked")
        .arg("--release")
        .arg("--target")
        .arg(platform.target())
        .arg("--target-dir")
        .arg(&build.target_dir)
        .arg("--all-features")
        .arg("-p")
        .arg("dbx-rs-cli")
        .arg("-p")
        .arg("dbx-rs-daemon")
        .current_dir(&build.repo_root)
        .env(
            "DBX_RS_DEPLOYMENT_AUTHORITY_CERT_DER",
            &build.authority.certificate_der_file,
        )
        .env(
            "DBX_RS_DEPLOYMENT_AUTHORITY_PUBLIC_KEY",
            &build.authority.public_key_file,
        )
        .env("CARGO_INCREMENTAL", "0");
    let status = command.status().map_err(|_| {
        if platform == Platform::Windows && !cfg!(windows) {
            BuilderError::new(
                "failed to start Windows build; install cargo-xwin or build on Windows",
            )
        } else {
            BuilderError::new("failed to start Cargo release build")
        }
    })?;
    if !status.success() {
        return Err(if platform == Platform::Windows && !cfg!(windows) {
            BuilderError::new(
                "Windows release build failed; install cargo-xwin and run rustup target add x86_64-pc-windows-msvc",
            )
        } else {
            BuilderError::new(format!("{} release build failed", platform.label()))
        });
    }
    Ok(())
}

fn assemble(
    platform: Platform,
    create_archive: bool,
    build: &ResolvedBuild,
    private_key: &[u8],
) -> BuilderResult<BuildOutput> {
    let app_directory = build.output_dir.join(platform.app_id());
    let archive_path = build.output_dir.join(format!("{}.spl", platform.app_id()));
    if app_directory.exists() || (create_archive && archive_path.exists()) {
        return Err(BuilderError::new(format!(
            "output for {} already exists",
            platform.label()
        )));
    }
    let staging =
        build
            .output_dir
            .join(format!(".{}.{}.tmp", platform.app_id(), std::process::id()));
    if staging.exists() {
        return Err(BuilderError::new("app staging directory already exists"));
    }
    let result = assemble_staged(platform, build, &staging, private_key).and_then(|()| {
        fs::rename(&staging, &app_directory)
            .map_err(|_| BuilderError::new("failed to publish built app directory"))
    });
    if result.is_err() {
        let _ignored = fs::remove_dir_all(&staging);
    }
    result?;

    let archive = if create_archive {
        create_spl_archive(&app_directory, &archive_path)?;
        Some(archive_path)
    } else {
        None
    };
    Ok(BuildOutput {
        app_directory,
        archive,
    })
}

fn assemble_staged(
    platform: Platform,
    build: &ResolvedBuild,
    staging: &Path,
    private_key: &[u8],
) -> BuilderResult<()> {
    fs::create_dir(staging).map_err(|_| BuilderError::new("failed to create app staging area"))?;
    set_permissions(staging, 0o755)?;
    copy_tree(&build.template_dir, staging)?;
    if let Some(config_dir) = &build.config_dir {
        let local = staging.join("local");
        fs::create_dir_all(&local)
            .map_err(|_| BuilderError::new("failed to create app local directory"))?;
        copy_tree(config_dir, &local)?;
    }
    let overlay = match platform {
        Platform::Linux => build.linux_overlay.as_ref(),
        Platform::Windows => build.windows_overlay.as_ref(),
    };
    if let Some(overlay) = overlay {
        copy_tree(overlay, staging)?;
    }
    fs::create_dir_all(staging.join("deployment-secrets"))
        .map_err(|_| BuilderError::new("failed to create deployment credential directory"))?;
    write_platform_inputs(staging, platform)?;
    update_readme_app_id(staging, platform)?;
    update_app_version(staging)?;
    install_binaries(staging, platform, build, private_key)?;
    validate_config(staging, &build.output_dir)?;
    scan_app(staging, private_key, &build.authority.authority)?;
    write_manifest(staging, platform, &build.authority)?;
    scan_app(staging, private_key, &build.authority.authority)
}

fn install_binaries(
    staging: &Path,
    platform: Platform,
    build: &ResolvedBuild,
    private_key: &[u8],
) -> BuilderResult<()> {
    let binary_dir = staging.join("bin");
    fs::create_dir_all(&binary_dir)
        .map_err(|_| BuilderError::new("failed to create app binary directory"))?;
    for base in ["dbx-rs", "dbx-rs-daemon"] {
        let name = platform.binary_name(base);
        let source = build
            .target_dir
            .join(platform.target())
            .join("release")
            .join(&name);
        verify_binary(&source, platform, &build.authority, private_key)?;
        let destination = binary_dir.join(name);
        fs::copy(&source, &destination)
            .map_err(|_| BuilderError::new("failed to copy a release binary into the app"))?;
        set_permissions(&destination, 0o755)?;
    }
    Ok(())
}

fn write_platform_inputs(staging: &Path, platform: Platform) -> BuilderResult<()> {
    let daemon = platform.binary_name("dbx-rs-daemon");
    let contents = format!(
        "[monitor://$SPLUNK_HOME/var/log/splunk/dbx-trace.log*]\n\
disabled = false\n\
index = _internal\n\
sourcetype = dbx_rs:trace:json\n\
\n\
[script://$SPLUNK_HOME/etc/apps/{}/bin/{daemon} run]\n\
disabled = false\n\
interval = 0\n\
start_by_shell = false\n\
index = _internal\n\
sourcetype = dbx_rs:daemon:stdout\n",
        platform.app_id()
    );
    write_normalized(
        &staging.join("default/inputs.conf"),
        contents.as_bytes(),
        0o644,
    )
}

fn update_app_version(staging: &Path) -> BuilderResult<()> {
    let path = staging.join("default/app.conf");
    let contents =
        fs::read_to_string(&path).map_err(|_| BuilderError::new("failed to read app.conf"))?;
    let mut replaced = false;
    let mut output = String::new();
    for line in contents.lines() {
        if line.trim_start().starts_with("version =") {
            output.push_str("version = ");
            output.push_str(env!("CARGO_PKG_VERSION"));
            output.push('\n');
            replaced = true;
        } else {
            output.push_str(line);
            output.push('\n');
        }
    }
    if !replaced {
        return Err(BuilderError::new("app.conf has no launcher version"));
    }
    write_normalized(&path, output.as_bytes(), 0o644)
}

fn update_readme_app_id(staging: &Path, platform: Platform) -> BuilderResult<()> {
    let path = staging.join("README.md");
    let contents =
        fs::read_to_string(&path).map_err(|_| BuilderError::new("failed to read app README"))?;
    let updated = contents.replace("TA-dbx-rs", platform.app_id());
    write_normalized(&path, updated.as_bytes(), 0o644)
}

fn validate_config(app_home: &Path, output_dir: &Path) -> BuilderResult<()> {
    let validation_home = output_dir.join(".dbx-rs-validation-home");
    load_effective_config(app_home, &validation_home)
        .map(|_config| ())
        .map_err(|error| BuilderError::new(format!("app configuration is invalid: {error}")))
}

fn verify_binary(
    path: &Path,
    platform: Platform,
    authority: &AuthorityMaterial,
    private_key: &[u8],
) -> BuilderResult<()> {
    let bytes = read_bounded(path, MAX_BINARY_BYTES, "release binary")?;
    match platform {
        Platform::Linux if !bytes.starts_with(b"\x7fELF") => {
            return Err(BuilderError::new("Linux release binary is not ELF"));
        }
        Platform::Windows if !is_pe_binary(&bytes) => {
            return Err(BuilderError::new("Windows release binary is not PE/COFF"));
        }
        Platform::Linux | Platform::Windows => {}
    }
    let certificate = fs::read(&authority.certificate_der_file)
        .map_err(|_| BuilderError::new("failed to read authority certificate"))?;
    let public_key = fs::read(&authority.public_key_file)
        .map_err(|_| BuilderError::new("failed to read authority public key"))?;
    if !contains_bytes(&bytes, &certificate) || !contains_bytes(&bytes, &public_key) {
        return Err(BuilderError::new(
            "release binary does not contain the selected public authority",
        ));
    }
    if contains_bytes(&bytes, private_key) {
        return Err(BuilderError::new(
            "release binary contains deployment authority private material",
        ));
    }
    if platform == Platform::Linux {
        verify_static_elf(path)?;
    }
    Ok(())
}

fn verify_static_elf(path: &Path) -> BuilderResult<()> {
    let program_headers = Command::new("readelf")
        .arg("-l")
        .arg(path)
        .output()
        .map_err(|_| BuilderError::new("readelf is required to verify Linux artifacts"))?;
    let dynamic = Command::new("readelf")
        .arg("-d")
        .arg(path)
        .output()
        .map_err(|_| BuilderError::new("readelf is required to verify Linux artifacts"))?;
    if !program_headers.status.success()
        || !dynamic.status.success()
        || contains_bytes(&program_headers.stdout, b"INTERP")
        || contains_bytes(&dynamic.stdout, b"(NEEDED)")
    {
        return Err(BuilderError::new(
            "Linux release binary is not a static-musl artifact",
        ));
    }
    Ok(())
}

fn scan_app(root: &Path, private_key: &[u8], authority: &DeploymentAuthority) -> BuilderResult<()> {
    for path in collect_files(root)? {
        let relative = path
            .strip_prefix(root)
            .map_err(|_| BuilderError::new("failed to inspect staged app path"))?;
        reject_private_key_filename(relative)?;
        let bytes = read_bounded(&path, MAX_PACKAGE_FILE_BYTES, "app file")?;
        if contains_bytes(&bytes, private_key) {
            return Err(BuilderError::new(
                "app contains deployment or TLS private-key material",
            ));
        }
        if path.extension().and_then(OsStr::to_str) == Some("dbxsecret") {
            verify_deployment_envelope(&bytes, authority).map_err(|_| {
                BuilderError::new(
                    "deployment credential file is not signed by the selected authority",
                )
            })?;
        } else if std::str::from_utf8(&bytes).is_ok() {
            if contains_bytes(&bytes, b"-----BEGIN PRIVATE KEY-----")
                || contains_bytes(&bytes, b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
            {
                return Err(BuilderError::new(
                    "app contains deployment or TLS private-key material",
                ));
            }
            if contains_plaintext_credential_assignment(&bytes) {
                return Err(BuilderError::new(
                    "app text contains a forbidden plaintext credential assignment",
                ));
            }
        }
    }
    Ok(())
}

fn reject_private_key_filename(path: &Path) -> BuilderResult<()> {
    let file_name = path.file_name().and_then(OsStr::to_str).unwrap_or_default();
    let extension = path.extension().and_then(OsStr::to_str).unwrap_or_default();
    if file_name == authority::PRIVATE_KEY_FILE
        || matches!(extension, "key" | "p12" | "pfx" | "pk8")
    {
        return Err(BuilderError::new("app contains a private-key file"));
    }
    Ok(())
}

fn contains_plaintext_credential_assignment(bytes: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    text.lines().any(|line| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            return false;
        }
        line.split_once('=').is_some_and(|(key, _value)| {
            matches!(
                key.trim().to_ascii_lowercase().as_str(),
                "access_token"
                    | "api_key"
                    | "client_secret"
                    | "connection_string"
                    | "db_password"
                    | "password"
                    | "passwd"
                    | "passphrase"
                    | "secret"
                    | "token"
            )
        })
    })
}

fn write_manifest(
    app: &Path,
    platform: Platform,
    authority: &AuthorityMaterial,
) -> BuilderResult<()> {
    let files = collect_files(app)?
        .into_iter()
        .map(|path| manifest_file(app, &path))
        .collect::<BuilderResult<Vec<_>>>()?;
    let manifest = BuildManifest {
        schema_version: 1,
        app_id: platform.app_id().into(),
        platform: platform.label().into(),
        rust_target: platform.target().into(),
        version: env!("CARGO_PKG_VERSION").into(),
        authority_sha256: authority.authority.fingerprint_hex(),
        files,
    };
    let mut encoded = serde_json::to_vec_pretty(&manifest)
        .map_err(|_| BuilderError::new("failed to encode app build manifest"))?;
    encoded.push(b'\n');
    write_normalized(&app.join("dbx-rs-build-manifest.json"), &encoded, 0o644)
}

fn manifest_file(root: &Path, path: &Path) -> BuilderResult<ManifestFile> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| BuilderError::new("failed to create app manifest path"))?;
    let bytes = read_bounded(path, MAX_PACKAGE_FILE_BYTES, "app file")?;
    Ok(ManifestFile {
        path: portable_path(relative)?,
        bytes: bytes.len() as u64,
        sha256: lowercase_hex(digest(&SHA256, &bytes).as_ref()),
    })
}

fn create_spl_archive(app: &Path, output: &Path) -> BuilderResult<()> {
    let temporary = output.with_extension(format!("spl.{}.tmp", std::process::id()));
    if temporary.exists() {
        return Err(BuilderError::new("archive staging file already exists"));
    }
    let result = create_spl_archive_staged(app, &temporary).and_then(|()| {
        fs::rename(&temporary, output)
            .map_err(|_| BuilderError::new("failed to publish .spl archive"))
    });
    if result.is_err() {
        let _ignored = fs::remove_file(&temporary);
    }
    result
}

fn create_spl_archive_staged(app: &Path, output: &Path) -> BuilderResult<()> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .map_err(|_| BuilderError::new("failed to create .spl archive"))?;
    let encoder = GzBuilder::new().mtime(0).write(file, Compression::best());
    let mut archive = TarBuilder::new(encoder);
    archive.mode(tar::HeaderMode::Deterministic);
    append_archive_directory(&mut archive, app, app, true)?;
    let encoder = archive
        .into_inner()
        .map_err(|_| BuilderError::new("failed to finalize tar archive"))?;
    let file = encoder
        .finish()
        .map_err(|_| BuilderError::new("failed to finalize gzip archive"))?;
    file.sync_all()
        .map_err(|_| BuilderError::new("failed to synchronize .spl archive"))
}

fn append_archive_directory<W: Write>(
    archive: &mut TarBuilder<W>,
    root: &Path,
    directory: &Path,
    include_self: bool,
) -> BuilderResult<()> {
    if include_self {
        let archive_path = PathBuf::from(
            root.file_name()
                .ok_or_else(|| BuilderError::new("app directory has no name"))?,
        );
        append_directory_header(archive, &archive_path)?;
    }
    let mut entries = fs::read_dir(directory)
        .map_err(|_| BuilderError::new("failed to enumerate app for archive"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| BuilderError::new("failed to inspect app archive entry"))?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|_| BuilderError::new("failed to inspect app archive entry"))?;
        if metadata.file_type().is_symlink() {
            return Err(BuilderError::new(
                "app archive cannot contain symbolic links",
            ));
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|_| BuilderError::new("failed to create archive path"))?;
        let archive_path = PathBuf::from(
            root.file_name()
                .ok_or_else(|| BuilderError::new("app directory has no name"))?,
        )
        .join(relative);
        if metadata.is_dir() {
            append_directory_header(archive, &archive_path)?;
            append_archive_directory(archive, root, &path, false)?;
        } else if metadata.is_file() {
            append_file_header(archive, &archive_path, &path, metadata.len())?;
        } else {
            return Err(BuilderError::new("app archive entry has invalid type"));
        }
    }
    Ok(())
}

fn append_directory_header<W: Write>(
    archive: &mut TarBuilder<W>,
    path: &Path,
) -> BuilderResult<()> {
    let mut header = deterministic_header(0, 0o755, EntryType::Directory);
    archive
        .append_data(&mut header, path, std::io::empty())
        .map_err(|_| BuilderError::new("failed to append app directory to archive"))
}

fn append_file_header<W: Write>(
    archive: &mut TarBuilder<W>,
    archive_path: &Path,
    source: &Path,
    size: u64,
) -> BuilderResult<()> {
    let mode = if source
        .parent()
        .and_then(Path::file_name)
        .is_some_and(|name| name == "bin")
    {
        0o755
    } else {
        0o644
    };
    let mut header = deterministic_header(size, mode, EntryType::Regular);
    let mut file =
        File::open(source).map_err(|_| BuilderError::new("failed to open app file for archive"))?;
    archive
        .append_data(&mut header, archive_path, &mut file)
        .map_err(|_| BuilderError::new("failed to append app file to archive"))
}

fn deterministic_header(size: u64, mode: u32, entry_type: EntryType) -> Header {
    let mut header = Header::new_gnu();
    header.set_size(size);
    header.set_mode(mode);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_entry_type(entry_type);
    header.set_cksum();
    header
}

fn copy_tree(source: &Path, destination: &Path) -> BuilderResult<()> {
    let metadata = fs::symlink_metadata(source)
        .map_err(|_| BuilderError::new("failed to inspect app source directory"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(BuilderError::new("app source must be a regular directory"));
    }
    let mut entries = fs::read_dir(source)
        .map_err(|_| BuilderError::new("failed to enumerate app source"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| BuilderError::new("failed to inspect app source entry"))?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        if path.file_name() == Some(OsStr::new(".gitignore")) {
            continue;
        }
        let entry_metadata = fs::symlink_metadata(&path)
            .map_err(|_| BuilderError::new("failed to inspect app source entry"))?;
        if entry_metadata.file_type().is_symlink() {
            return Err(BuilderError::new(
                "app source cannot contain symbolic links",
            ));
        }
        let target = destination.join(entry.file_name());
        if entry_metadata.is_dir() {
            fs::create_dir_all(&target)
                .map_err(|_| BuilderError::new("failed to create staged app directory"))?;
            set_permissions(&target, 0o755)?;
            copy_tree(&path, &target)?;
        } else if entry_metadata.is_file() {
            fs::copy(&path, &target)
                .map_err(|_| BuilderError::new("failed to copy staged app file"))?;
            set_permissions(&target, source_file_mode(&entry_metadata))?;
        } else {
            return Err(BuilderError::new("app source entry has invalid type"));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn source_file_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;

    if metadata.permissions().mode() & 0o111 == 0 {
        0o644
    } else {
        0o755
    }
}

#[cfg(not(unix))]
const fn source_file_mode(_metadata: &fs::Metadata) -> u32 {
    0o644
}

fn write_normalized(path: &Path, bytes: &[u8], mode: u32) -> BuilderResult<()> {
    fs::write(path, bytes).map_err(|_| BuilderError::new("failed to write staged app file"))?;
    set_permissions(path, mode)
}

#[cfg(unix)]
fn set_permissions(path: &Path, mode: u32) -> BuilderResult<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|_| BuilderError::new("failed to normalize staged app permissions"))
}

#[cfg(not(unix))]
fn set_permissions(_path: &Path, _mode: u32) -> BuilderResult<()> {
    Ok(())
}

fn collect_files(root: &Path) -> BuilderResult<Vec<PathBuf>> {
    let mut files = Vec::new();
    collect_files_inner(root, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_files_inner(directory: &Path, files: &mut Vec<PathBuf>) -> BuilderResult<()> {
    let mut entries = fs::read_dir(directory)
        .map_err(|_| BuilderError::new("failed to enumerate staged app"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| BuilderError::new("failed to inspect staged app entry"))?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|_| BuilderError::new("failed to inspect staged app entry"))?;
        if metadata.file_type().is_symlink() {
            return Err(BuilderError::new(
                "staged app cannot contain symbolic links",
            ));
        }
        if metadata.is_dir() {
            collect_files_inner(&path, files)?;
        } else if metadata.is_file() {
            files.push(path);
        } else {
            return Err(BuilderError::new("staged app entry has invalid type"));
        }
    }
    Ok(())
}

fn read_bounded(path: &Path, max_bytes: u64, label: &str) -> BuilderResult<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| BuilderError::new(format!("{label} is unavailable")))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > max_bytes {
        return Err(BuilderError::new(format!(
            "{label} has an invalid type or size"
        )));
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len())
            .map_err(|_| BuilderError::new(format!("{label} is too large")))?,
    );
    File::open(path)
        .and_then(|file| file.take(max_bytes + 1).read_to_end(&mut bytes))
        .map_err(|_| BuilderError::new(format!("failed to read {label}")))?;
    if bytes.len() as u64 > max_bytes {
        return Err(BuilderError::new(format!("{label} exceeds its size limit")));
    }
    Ok(bytes)
}

fn is_pe_binary(bytes: &[u8]) -> bool {
    if bytes.len() < 0x40 || !bytes.starts_with(b"MZ") {
        return false;
    }
    let offset = u32::from_le_bytes([bytes[0x3c], bytes[0x3d], bytes[0x3e], bytes[0x3f]]) as usize;
    offset
        .checked_add(4)
        .is_some_and(|end| end <= bytes.len() && &bytes[offset..end] == b"PE\0\0")
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn portable_path(path: &Path) -> BuilderResult<String> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => parts.push(
                value
                    .to_str()
                    .ok_or_else(|| BuilderError::new("app path is not valid UTF-8"))?,
            ),
            _ => return Err(BuilderError::new("app path is not a safe relative path")),
        }
    }
    Ok(parts.join("/"))
}

fn lowercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn absolute_from(path: &Path, current: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        current.join(path)
    }
}

fn canonical_directory(path: &Path, label: &str) -> BuilderResult<PathBuf> {
    let path = path
        .canonicalize()
        .map_err(|_| BuilderError::new(format!("{label} directory is unavailable")))?;
    let metadata = fs::symlink_metadata(&path)
        .map_err(|_| BuilderError::new(format!("failed to inspect {label} directory")))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(BuilderError::new(format!(
            "{label} path is not a directory"
        )));
    }
    Ok(path)
}

fn canonical_optional_directory(
    path: Option<&PathBuf>,
    current: &Path,
    label: &str,
) -> BuilderResult<Option<PathBuf>> {
    path.map(|path| {
        let absolute = absolute_from(path, current);
        canonical_directory(&absolute, label)
    })
    .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_inputs_are_os_specific_and_stable() {
        let linux = Platform::Linux;
        let windows = Platform::Windows;

        assert_eq!(linux.binary_name("dbx-rs-daemon"), "dbx-rs-daemon");
        assert_eq!(windows.binary_name("dbx-rs-daemon"), "dbx-rs-daemon.exe");
        assert_ne!(linux.app_id(), windows.app_id());
    }

    #[test]
    fn password_assignments_are_rejected_but_secret_references_are_allowed() {
        assert!(contains_plaintext_credential_assignment(
            b"password = exposed"
        ));
        assert!(contains_plaintext_credential_assignment(b"TOKEN=value"));
        assert!(contains_plaintext_credential_assignment(
            b"connection_string = server=database"
        ));
        assert!(contains_plaintext_credential_assignment(
            b"client_secret = exposed"
        ));
        assert!(!contains_plaintext_credential_assignment(
            b"secret_ref = local:warehouse"
        ));
        assert!(!contains_plaintext_credential_assignment(
            b"# password = documented"
        ));
    }

    #[test]
    fn pe_signature_parser_checks_the_declared_header() {
        let mut valid = vec![0_u8; 0x84];
        valid[..2].copy_from_slice(b"MZ");
        valid[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
        valid[0x80..0x84].copy_from_slice(b"PE\0\0");

        assert!(is_pe_binary(&valid));
        valid[0x80] = b'X';
        assert!(!is_pe_binary(&valid));
    }
}
