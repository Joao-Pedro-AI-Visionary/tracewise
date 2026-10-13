//! `trace_dylib_resolution`: static dyld load-path resolution (port of REA
//! `domain/apple/dylibResolution.ts`, `dyldPaths.ts`, `dyldEnvironment.ts`,
//! `dylibResolutionFindings.ts` and `artifacts/apple/DylibResolutionReader.ts`).

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::error::{ArtifactReason, NativeError, NativeResult};
use crate::macho_dyld::{
    has_macho_magic, read_macho_image, ImageFacts, MachoDependency, MachoSlice,
};

const OPERATION: &str = "trace_dylib_resolution";

// ---------------------------------------------------------------------------
// Tree view
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum TreeEntry {
    File,
    Directory,
    Symlink(String),
}

/// Read-only, lazily probed view of the analyzed root. Paths are root-relative.
pub trait TreeView {
    fn entry(&self, path: &str) -> NativeResult<Option<TreeEntry>>;
    fn image(&self, path: &str) -> NativeResult<ImageFacts>;
}

type FileIdentity = (u64, u64, u64, i64, i64, i64, i64);

fn identity_of(metadata: &fs::Metadata) -> FileIdentity {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.size(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

pub struct FilesystemTreeView {
    root: PathBuf,
    entries: RefCell<HashMap<String, Option<TreeEntry>>>,
    images: RefCell<HashMap<String, ImageFacts>>,
    identities: RefCell<HashMap<String, FileIdentity>>,
}

impl FilesystemTreeView {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            entries: RefCell::new(HashMap::new()),
            images: RefCell::new(HashMap::new()),
            identities: RefCell::new(HashMap::new()),
        }
    }

    fn identity(&self, path: &str) -> Option<FileIdentity> {
        self.identities.borrow().get(path).copied()
    }
}

fn io_failure(error: &std::io::Error, path: &Path, root: &Path) -> NativeError {
    if matches!(error.kind(), std::io::ErrorKind::PermissionDenied) {
        let code = match error.raw_os_error() {
            Some(1) => "EPERM",
            _ => "EACCES",
        };
        let shown = match path.strip_prefix(root) {
            Ok(inside) if inside.as_os_str().is_empty() => path.display().to_string(),
            Ok(inside) => inside.display().to_string(),
            Err(_) => path.display().to_string(),
        };
        return NativeError::artifact(
            OPERATION,
            ArtifactReason::Unavailable,
            format!("Permission denied ({code}) reading {shown}"),
        );
    }
    NativeError::artifact_bare(OPERATION, ArtifactReason::Io)
}

impl TreeView for FilesystemTreeView {
    fn entry(&self, path: &str) -> NativeResult<Option<TreeEntry>> {
        if let Some(cached) = self.entries.borrow().get(path) {
            return Ok(cached.clone());
        }
        let absolute = self.root.join(path);
        let entry = match fs::symlink_metadata(&absolute) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    let target = fs::read_link(&absolute)
                        .map_err(|e| io_failure(&e, &absolute, &self.root))?;
                    Some(TreeEntry::Symlink(target.to_string_lossy().into_owned()))
                } else if metadata.is_dir() {
                    Some(TreeEntry::Directory)
                } else if metadata.is_file() {
                    Some(TreeEntry::File)
                } else {
                    None
                }
            }
            Err(error) => {
                // ENOENT / ENOTDIR mean the entry is absent.
                if matches!(error.kind(), std::io::ErrorKind::NotFound)
                    || error.raw_os_error() == Some(20)
                {
                    None
                } else {
                    return Err(io_failure(&error, &absolute, &self.root));
                }
            }
        };
        self.entries.borrow_mut().insert(path.to_string(), entry.clone());
        Ok(entry)
    }

    fn image(&self, path: &str) -> NativeResult<ImageFacts> {
        if let Some(cached) = self.images.borrow().get(path) {
            return Ok(cached.clone());
        }
        let absolute = self.root.join(path);
        let file = open_nofollow(&absolute).map_err(|e| io_failure(&e, &absolute, &self.root))?;
        let metadata = file.metadata().map_err(|e| io_failure(&e, &absolute, &self.root))?;
        let facts = read_macho_image(&file, metadata.len())
            .map_err(|e| io_failure(&e, &absolute, &self.root))?;
        self.identities
            .borrow_mut()
            .insert(path.to_string(), identity_of(&metadata));
        self.images.borrow_mut().insert(path.to_string(), facts.clone());
        Ok(facts)
    }
}

pub fn open_nofollow(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}


// ---------------------------------------------------------------------------
// Path helpers (dyldPaths.ts)
// ---------------------------------------------------------------------------

const MAX_SYMLINK_HOPS: usize = 32;

#[derive(Debug, PartialEq)]
pub enum PathLookup {
    File(String),
    Absent,
    Escapes,
    NotFile,
}

fn segments_of(path: &str) -> Vec<String> {
    let mut segments: Vec<String> = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(str::to_string)
        .collect();
    if path.ends_with('/') {
        segments.push(".".to_string());
    }
    segments
}

pub fn resolve_tree_path(view: &dyn TreeView, input: &str) -> NativeResult<PathLookup> {
    let mut pending: std::collections::VecDeque<String> = segments_of(input).into();
    let mut resolved: Vec<String> = Vec::new();
    let mut last: Option<TreeEntry> = None;
    let mut hops = 0usize;
    while let Some(segment) = pending.pop_front() {
        if segment == "." {
            continue;
        }
        if segment == ".." {
            if resolved.is_empty() {
                return Ok(PathLookup::Escapes);
            }
            resolved.pop();
            last = Some(TreeEntry::Directory);
            continue;
        }
        let mut path = resolved.clone();
        path.push(segment.clone());
        let entry = match view.entry(&path.join("/"))? {
            Some(entry) => entry,
            None => return Ok(PathLookup::Absent),
        };
        if let TreeEntry::Symlink(target) = &entry {
            hops += 1;
            if hops > MAX_SYMLINK_HOPS {
                return Ok(PathLookup::Absent);
            }
            if target.starts_with('/') {
                return Ok(PathLookup::Escapes);
            }
            for item in segments_of(target).into_iter().rev() {
                pending.push_front(item);
            }
            continue;
        }
        if entry == TreeEntry::File && !pending.is_empty() {
            return Ok(PathLookup::Absent);
        }
        resolved.push(segment);
        last = Some(entry);
    }
    Ok(match last {
        Some(TreeEntry::File) => PathLookup::File(resolved.join("/")),
        _ => PathLookup::NotFile,
    })
}

fn directory_of(path: &str) -> &str {
    match path.rfind('/') {
        Some(index) => &path[..index],
        None => "",
    }
}

fn join_path(directory: &str, rest: &str) -> String {
    if directory.is_empty() {
        rest.to_string()
    } else if rest.is_empty() {
        directory.to_string()
    } else {
        format!("{directory}/{rest}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Scope {
    Target,
    Outside,
    Undetermined,
}

#[derive(Debug, Clone)]
struct Expansion {
    scope: Scope,
    path: String,
}

/// JS `.` does not match line terminators.
fn has_line_terminator(text: &str) -> bool {
    text.chars().any(|c| matches!(c, '\n' | '\r' | '\u{2028}' | '\u{2029}'))
}

fn expand_prefix(raw: &str, owner_directory: &str, executable: Option<&str>) -> Expansion {
    for (prefix, is_loader) in [("@executable_path", false), ("@loader_path", true)] {
        if let Some(rest) = raw.strip_prefix(prefix) {
            let rest = if rest.is_empty() {
                Some("")
            } else {
                rest.strip_prefix('/')
            };
            if let Some(rest) = rest {
                if has_line_terminator(rest) {
                    continue;
                }
                if is_loader {
                    return Expansion {
                        scope: Scope::Target,
                        path: join_path(owner_directory, rest),
                    };
                }
                return match executable {
                    None => Expansion {
                        scope: Scope::Undetermined,
                        path: raw.to_string(),
                    },
                    Some(executable) => Expansion {
                        scope: Scope::Target,
                        path: join_path(directory_of(executable), rest),
                    },
                };
            }
        }
    }
    if raw.starts_with('/') {
        return Expansion {
            scope: Scope::Outside,
            path: raw.to_string(),
        };
    }
    Expansion {
        scope: Scope::Undetermined,
        path: raw.to_string(),
    }
}

fn compatible_slice<'a>(slices: &'a [MachoSlice], process: &str) -> Option<&'a MachoSlice> {
    let order: &[&str] = if process == "x86_64h" {
        &["x86_64h", "x86_64"]
    } else {
        &[]
    };
    if order.is_empty() {
        return slices.iter().find(|slice| slice.architecture == process);
    }
    for architecture in order {
        if let Some(slice) = slices.iter().find(|slice| slice.architecture == *architecture) {
            return Some(slice);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// dyldEnvironment.ts
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct DyldSearchOverride {
    phase: &'static str,
    scope: &'static str,
    variable: String,
    value: String,
}

fn override_effect(variable: &str, value: &str) -> Option<(&'static str, &'static str)> {
    match variable {
        "DYLD_LIBRARY_PATH" => Some(("override", "library")),
        "DYLD_FRAMEWORK_PATH" => Some(("override", "framework")),
        "DYLD_FALLBACK_LIBRARY_PATH" => Some(("fallback", "library")),
        "DYLD_FALLBACK_FRAMEWORK_PATH" => Some(("fallback", "framework")),
        "DYLD_VERSIONED_LIBRARY_PATH" | "DYLD_VERSIONED_FRAMEWORK_PATH" | "DYLD_IMAGE_SUFFIX" => {
            if value.chars().any(|c| c != ':') {
                Some(("override", "all"))
            } else {
                None
            }
        }
        "DYLD_INSERT_LIBRARIES" => {
            if value.is_empty() {
                None
            } else {
                Some(("override", "all"))
            }
        }
        "DYLD_ROOT_PATH" | "DYLD_OVERLAY_PATH" => {
            if value.is_empty() {
                None
            } else {
                Some(("override", "prefix"))
            }
        }
        _ => None,
    }
}

fn embedded_dyld_overrides(environment: &[String], platforms: &[u32]) -> Vec<DyldSearchOverride> {
    let mut overrides = Vec::new();
    for setting in environment {
        let delimiter = match setting.find('=') {
            Some(index) if index > 0 => index,
            _ => continue,
        };
        let variable = &setting[..delimiter];
        let value = &setting[delimiter + 1..];
        let Some((phase, scope)) = override_effect(variable, value) else {
            continue;
        };
        if variable == "DYLD_ROOT_PATH"
            && !platforms.is_empty()
            && platforms.iter().all(|p| (1..=12).contains(p))
            && !platforms.iter().any(|p| [7, 8, 9, 12].contains(p))
        {
            continue;
        }
        overrides.push(DyldSearchOverride {
            phase,
            scope,
            variable: variable.to_string(),
            value: value.to_string(),
        });
    }
    overrides
}

fn is_framework_install_name(name: &str, overrides: &[DyldSearchOverride]) -> bool {
    let Some(separator) = name.rfind(".framework/") else {
        return false;
    };
    let framework = name[..separator].split('/').next_back().unwrap_or("");
    let leaf = &name[name.rfind('/').map(|i| i + 1).unwrap_or(0)..];
    leaf == framework
        || overrides
            .iter()
            .any(|o| o.variable == "DYLD_IMAGE_SUFFIX" && leaf == format!("{framework}{}", o.value))
}

fn has_applicable_dyld_overrides(
    overrides: &[DyldSearchOverride],
    install_name: &str,
    ordinary_search_found_image: bool,
) -> bool {
    let kind = if is_framework_install_name(install_name, overrides) {
        "framework"
    } else {
        "library"
    };
    overrides.iter().any(|o| {
        (o.phase == "override" || !ordinary_search_found_image)
            && (o.scope == "all"
                || o.scope == kind
                || (o.scope == "prefix" && !install_name.starts_with('@')))
    })
}

// ---------------------------------------------------------------------------
// Result model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct Candidate {
    pub path: String,
    pub source: &'static str,
    pub rpath: Option<String>,
    pub rpath_owner: Option<String>,
    pub outcome: &'static str,
    pub resolved_path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Resolution {
    pub status: &'static str,
    pub image: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DylibEdge {
    pub root: String,
    pub architecture: String,
    pub loader: String,
    pub via: Vec<String>,
    #[serde(flatten)]
    pub dependency: MachoDependency,
    pub candidates: Vec<Candidate>,
    pub resolution: Resolution,
    pub install_name_matches: Option<bool>,
    pub loader_conditional: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct DylibFinding {
    pub kind: &'static str,
    pub edge_index: Option<usize>,
    pub image: Option<String>,
    pub basis: &'static str,
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RootRef {
    pub image: String,
    pub architecture: String,
}

pub struct DylibTrace {
    pub roots: Vec<RootRef>,
    pub images: Vec<(String, ImageFacts)>,
    pub edges: Vec<DylibEdge>,
    pub findings: Vec<DylibFinding>,
    pub unparsed_images: Vec<String>,
    pub roots_without_architecture: Vec<String>,
    pub complete: bool,
    pub limitations: Vec<String>,
}

struct LoadedImage {
    slice: MachoSlice,
    chain: Vec<String>,
    conditional: bool,
}

struct ProcessContext {
    root: String,
    architecture: String,
    search_overrides: Vec<DyldSearchOverride>,
    platforms: Vec<u32>,
    executable: Option<String>,
    loaded: HashMap<String, LoadedImage>,
    by_install_name: HashMap<String, String>,
}

struct CandidateTemplate {
    expansion: Expansion,
    source: &'static str,
    rpath: Option<String>,
    rpath_owner: Option<String>,
}

struct Tracer<'a> {
    view: &'a dyn TreeView,
    images: HashMap<String, ImageFacts>,
    image_order: Vec<String>,
    environment_roots: Vec<String>,
}

impl<'a> Tracer<'a> {
    fn set_image(&mut self, path: &str, facts: ImageFacts) {
        if !self.images.contains_key(path) {
            self.image_order.push(path.to_string());
        }
        self.images.insert(path.to_string(), facts);
    }

    fn image_facts(&mut self, path: &str) -> NativeResult<ImageFacts> {
        if let Some(known) = self.images.get(path) {
            return Ok(known.clone());
        }
        let facts = self.view.image(path)?;
        self.set_image(path, facts.clone());
        Ok(facts)
    }

    fn candidate_templates(
        &self,
        dependency: &MachoDependency,
        loader: &str,
        context: &ProcessContext,
    ) -> Vec<CandidateTemplate> {
        let name = &dependency.install_name;
        if !name.starts_with("@rpath/") {
            let source = if name.starts_with("@executable_path") {
                "executable_path"
            } else if name.starts_with("@loader_path") {
                "loader_path"
            } else {
                "literal"
            };
            return vec![CandidateTemplate {
                expansion: expand_prefix(name, directory_of(loader), context.executable.as_deref()),
                source,
                rpath: None,
                rpath_owner: None,
            }];
        }
        let rest = &name["@rpath/".len()..];
        let mut owners: Vec<String> = context
            .loaded
            .get(loader)
            .map(|l| l.chain.clone())
            .unwrap_or_else(|| vec![loader.to_string()]);
        owners.reverse();
        let mut templates = Vec::new();
        for owner in owners {
            let rpaths: Vec<String> = context
                .loaded
                .get(&owner)
                .map(|l| l.slice.rpaths.clone())
                .unwrap_or_default();
            for rpath in rpaths {
                let base = expand_prefix(&rpath, directory_of(&owner), context.executable.as_deref());
                let path = if base.scope == Scope::Outside {
                    format!("{}/{}", base.path.trim_end_matches('/'), rest)
                } else {
                    format!(
                        "{}{}{}",
                        base.path,
                        if base.path.is_empty() { "" } else { "/" },
                        rest
                    )
                };
                templates.push(CandidateTemplate {
                    expansion: Expansion { scope: base.scope, path },
                    source: "rpath",
                    rpath: Some(rpath),
                    rpath_owner: Some(owner.clone()),
                });
            }
        }
        templates
    }

    fn evaluate_candidate(
        &mut self,
        template: &CandidateTemplate,
        context: &ProcessContext,
    ) -> NativeResult<Candidate> {
        let base = |outcome: &'static str, resolved: Option<String>| Candidate {
            path: template.expansion.path.clone(),
            source: template.source,
            rpath: template.rpath.clone(),
            rpath_owner: template.rpath_owner.clone(),
            outcome,
            resolved_path: resolved,
        };
        match template.expansion.scope {
            Scope::Outside => return Ok(base("outside-target", None)),
            Scope::Undetermined => return Ok(base("undetermined", None)),
            Scope::Target => {}
        }
        let lookup = resolve_tree_path(self.view, &template.expansion.path)?;
        let resolved_path = match lookup {
            PathLookup::Escapes => return Ok(base("escapes-target", None)),
            PathLookup::File(path) => path,
            _ => return Ok(base("absent", None)),
        };
        let facts = self.image_facts(&resolved_path)?;
        let outcome: &'static str = match &facts {
            ImageFacts::Parsed(slices) => match compatible_slice(slices, &context.architecture) {
                None => "architecture-missing",
                Some(slice) if slice.file_type_code != 6 => "not-loadable",
                Some(slice) => match platform_loadability(
                    &context.platforms,
                    &slice.platforms,
                    slice.file_type_code,
                    &context.architecture,
                ) {
                    Loadability::Compatible => "resolved",
                    Loadability::Incompatible => "platform-mismatch",
                    Loadability::Unknown => "undetermined",
                },
            },
            ImageFacts::Malformed(_) => "malformed",
            ImageFacts::Unsupported(_) => "unsupported",
            ImageFacts::NotMachO => "not-mach-o",
        };
        Ok(base(outcome, Some(resolved_path)))
    }

    fn resolve_dependency(
        &mut self,
        dependency: &MachoDependency,
        loader: &str,
        context: &ProcessContext,
        environment_hit: &mut bool,
    ) -> NativeResult<DylibEdge> {
        let current = context.loaded.get(loader);
        let chain: Vec<String> = current
            .map(|c| c.chain.clone())
            .unwrap_or_else(|| vec![loader.to_string()]);
        let loaded = context.by_install_name.get(&dependency.install_name).cloned();
        let mut candidates: Vec<Candidate> = Vec::new();
        if let Some(loaded_path) = &loaded {
            candidates.push(Candidate {
                path: dependency.install_name.clone(),
                source: "already-loaded",
                rpath: None,
                rpath_owner: None,
                outcome: "resolved",
                resolved_path: Some(loaded_path.clone()),
            });
        } else {
            for template in self.candidate_templates(dependency, loader, context) {
                let candidate = self.evaluate_candidate(&template, context)?;
                let hit = candidate.outcome == "resolved";
                candidates.push(candidate);
                if hit {
                    break;
                }
            }
        }
        let modeled = resolution(&candidates);
        let search_unknown = loaded.is_none()
            && has_applicable_dyld_overrides(
                &context.search_overrides,
                &dependency.install_name,
                modeled.image.is_some(),
            );
        if search_unknown {
            *environment_hit = true;
        }
        let searched = if search_unknown {
            Resolution {
                status: if modeled.image.is_none() {
                    "undetermined"
                } else {
                    "conditional"
                },
                image: modeled.image.clone(),
            }
        } else {
            modeled
        };
        let resolved = match &loaded {
            Some(loaded_path)
                if context.loaded.get(loaded_path).map(|l| l.conditional) == Some(true)
                    && searched.status == "resolved" =>
            {
                Resolution {
                    status: "conditional",
                    image: searched.image.clone(),
                }
            }
            _ => searched,
        };
        let slice = resolved
            .image
            .as_ref()
            .and_then(|image| self.images.get(image))
            .and_then(|facts| match facts {
                ImageFacts::Parsed(slices) => compatible_slice(slices, &context.architecture),
                _ => None,
            });
        let install_name_matches = match slice {
            Some(slice) => slice
                .install_name
                .as_ref()
                .map(|name| name == &dependency.install_name),
            None => None,
        };
        Ok(DylibEdge {
            root: context.root.clone(),
            architecture: context.architecture.clone(),
            loader: loader.to_string(),
            via: chain,
            dependency: dependency.clone(),
            candidates,
            resolution: resolved,
            install_name_matches,
            loader_conditional: current.map(|c| c.conditional).unwrap_or(false),
        })
    }

    fn trace_process(
        &mut self,
        context: &mut ProcessContext,
        root_slice: &MachoSlice,
    ) -> NativeResult<(Vec<DylibEdge>, bool)> {
        let mut edges: Vec<DylibEdge> = Vec::new();
        let mut environment_hit = false;
        context.loaded.insert(
            context.root.clone(),
            LoadedImage {
                slice: root_slice.clone(),
                chain: vec![context.root.clone()],
                conditional: false,
            },
        );
        if let Some(name) = &root_slice.install_name {
            context.by_install_name.insert(name.clone(), context.root.clone());
        }
        let mut pending: Vec<String> = vec![context.root.clone()];
        while let Some(loader) = pending.pop() {
            crate::cancel::checkpoint("trace_dylib_resolution")?;
            let (dependencies, current_chain, current_conditional) = match context.loaded.get(&loader) {
                Some(current) => (
                    current.slice.dependencies.clone(),
                    current.chain.clone(),
                    current.conditional,
                ),
                None => continue,
            };
            let mut created: Vec<String> = Vec::new();
            for dependency in &dependencies {
                let edge = self.resolve_dependency(dependency, &loader, context, &mut environment_hit)?;
                let is_lazy = dependency.command == "LC_LAZY_LOAD_DYLIB";
                let image = edge.resolution.image.clone();
                let conditional_edge = edge.resolution.status == "conditional";
                edges.push(edge);
                if is_lazy {
                    continue;
                }
                let Some(image) = image else { continue };
                if context.loaded.contains_key(&image) {
                    continue;
                }
                let slice = match self.images.get(&image) {
                    Some(ImageFacts::Parsed(slices)) => {
                        compatible_slice(slices, &context.architecture).cloned()
                    }
                    _ => None,
                };
                let Some(slice) = slice else { continue };
                let mut chain = current_chain.clone();
                chain.push(image.clone());
                if let Some(name) = &slice.install_name {
                    if !context.by_install_name.contains_key(name) {
                        context.by_install_name.insert(name.clone(), image.clone());
                    }
                }
                context.loaded.insert(
                    image.clone(),
                    LoadedImage {
                        slice,
                        chain,
                        conditional: current_conditional || conditional_edge,
                    },
                );
                created.push(image);
            }
            created.reverse();
            pending.extend(created);
        }
        Ok((edges, environment_hit))
    }
}

fn resolution(candidates: &[Candidate]) -> Resolution {
    let mut external = false;
    for candidate in candidates {
        if candidate.outcome == "resolved" {
            return Resolution {
                status: if external { "conditional" } else { "resolved" },
                image: candidate.resolved_path.clone(),
            };
        }
        if matches!(
            candidate.outcome,
            "outside-target" | "escapes-target" | "unsupported" | "undetermined"
        ) {
            external = true;
        }
    }
    Resolution {
        status: if external { "undetermined" } else { "unresolved" },
        image: None,
    }
}

#[derive(PartialEq, Clone, Copy)]
enum Loadability {
    Compatible,
    Incompatible,
    Unknown,
}

fn platform_loadability(
    process_platforms: &[u32],
    image_platforms: &[u32],
    file_type: u32,
    architecture: &str,
) -> Loadability {
    if process_platforms.is_empty() || image_platforms.is_empty() {
        return Loadability::Unknown;
    }
    let outcomes: Vec<Loadability> = process_platforms
        .iter()
        .map(|p| image_loadability_for_platform(*p, image_platforms, file_type, architecture))
        .collect();
    if outcomes.iter().all(|o| *o == Loadability::Compatible) {
        return Loadability::Compatible;
    }
    if outcomes.iter().all(|o| *o == Loadability::Incompatible) {
        return Loadability::Incompatible;
    }
    Loadability::Unknown
}

fn image_loadability_for_platform(
    process_platform: u32,
    image_platforms: &[u32],
    file_type: u32,
    architecture: &str,
) -> Loadability {
    if image_platforms.contains(&process_platform) {
        return Loadability::Compatible;
    }
    if process_platform == 6 && image_platforms.contains(&1) {
        return Loadability::Compatible;
    }
    if process_platform == 2 && image_platforms.contains(&6) {
        return Loadability::Compatible;
    }
    if process_platform == 2 && image_platforms.contains(&11) {
        return Loadability::Compatible;
    }
    if process_platform == 7 && image_platforms.contains(&12) {
        return Loadability::Compatible;
    }
    if process_platform == 1 && file_type == 2 && image_platforms.contains(&6) {
        return Loadability::Compatible;
    }
    if (process_platform == 2 && image_platforms.contains(&1) && architecture.starts_with("arm64"))
        || ([7, 8, 9].contains(&process_platform) && image_platforms.contains(&1))
    {
        return Loadability::Unknown;
    }
    if (1..=12).contains(&process_platform) && image_platforms.iter().all(|p| (1..=12).contains(p)) {
        return Loadability::Incompatible;
    }
    Loadability::Unknown
}

// ---------------------------------------------------------------------------
// Findings (dylibResolutionFindings.ts)
// ---------------------------------------------------------------------------

pub const DYLIB_RESOLUTION_LIMITATIONS: [&str; 8] = [
    "LC_LAZY_LOAD_DYLIB dependencies are resolved but not traversed, because dyld loads them only on first use.",
    "Slices are matched by dyld's graded architectures (an x86_64h process also loads x86_64). arm64e processes that disable pointer authentication can also load arm64 slices; that fallback is not modeled.",
    "Absolute install names and rpaths are outside the analyzed root and are not evaluated, including /System and /usr/lib libraries that the dyld shared cache usually provides.",
    "Leaf and relative install names depend on dyld fallback paths, DYLD_* variables, and the working directory; they are undetermined.",
    "Load order follows dyld's dependents-first traversal in load-command order. An image reached through several chains is resolved once per process, with the rpath stack and conditionality of the first chain; a later request whose install name matches an already loaded image reuses it.",
    "@loader_path uses each image's symlink-resolved path within the analyzed root.",
    "Code-signing checks that can reject a found image, such as library validation and the hardened runtime, are not evaluated.",
    "Dylib compatibility versions are not compared. Apple's linker documentation describes a load-time rejection when an image's compatibility version is older than the loader requires, but dyld on macOS 26 was observed to load such an image.",
];

fn derive_findings(
    edges: &[DylibEdge],
    roots: &[RootRef],
    images: &HashMap<String, ImageFacts>,
) -> Vec<DylibFinding> {
    let mut findings = Vec::new();
    for (index, edge) in edges.iter().enumerate() {
        if edge.resolution.status == "unresolved" {
            findings.push(unresolved_finding(edge, index));
        }
        let resolved_at = edge.candidates.iter().position(|c| c.outcome == "resolved");
        let limit = resolved_at.unwrap_or(0);
        let earlier: Vec<&str> = edge
            .candidates
            .iter()
            .take(limit)
            .filter(|c| c.source == "rpath" && c.outcome == "absent")
            .map(|c| c.path.as_str())
            .collect();
        if resolved_at.map(|p| p > 0).unwrap_or(false) && !earlier.is_empty() {
            let target = edge
                .resolution
                .image
                .clone()
                .unwrap_or_else(|| edge.dependency.install_name.clone());
            let mut explanation = format!(
                "The modeled dyld search checks {} before {}. A compatible Mach-O placed at an earlier modeled path could take precedence over that fallback, subject to unmodeled search inputs and code-signing library validation; library validation is not evaluated here (see inspect_signature).",
                earlier.join(", "),
                target
            );
            if edge.loader_conditional {
                explanation.push_str(" This loader loads only conditionally; if it never loads, this search never occurs.");
            }
            if edge.resolution.status == "conditional" {
                explanation.push_str(" Unmodeled environment overrides or earlier unknown candidates may take precedence; placing an image at this rpath does not establish which image dyld will load.");
            }
            findings.push(DylibFinding {
                kind: "earlier-rpath-candidate-absent",
                edge_index: Some(index),
                image: Some(edge.loader.clone()),
                basis: "derived",
                explanation,
            });
        }
    }
    for root in roots {
        let slice = match images.get(&root.image) {
            Some(ImageFacts::Parsed(slices)) => {
                slices.iter().find(|s| s.architecture == root.architecture)
            }
            _ => None,
        };
        let environment: Vec<String> = slice.map(|s| s.dyld_environment.clone()).unwrap_or_default();
        if !environment.is_empty() {
            let explanation = if slice.map(|s| s.file_type) == Some("execute") {
                format!(
                    "{} ({}) sets dyld environment variables through LC_DYLD_ENVIRONMENT ({}); any image-selection overrides they request are not modeled. Diagnostic settings alone do not alter resolution.",
                    root.image, root.architecture, environment.join(", ")
                )
            } else {
                format!(
                    "{} ({}) contains LC_DYLD_ENVIRONMENT ({}). Dyld reads these commands only from the main executable; entries in this non-executable root are observations and do not alter resolution.",
                    root.image, root.architecture, environment.join(", ")
                )
            };
            findings.push(DylibFinding {
                kind: "dyld-environment-present",
                edge_index: None,
                image: Some(root.image.clone()),
                basis: "derived",
                explanation,
            });
        }
    }
    findings
}

fn unresolved_finding(edge: &DylibEdge, index: usize) -> DylibFinding {
    let command = edge.dependency.command;
    let prefix = if command == "LC_LAZY_LOAD_DYLIB" {
        "lazily loaded "
    } else if edge.dependency.weak {
        "weak dependency "
    } else {
        ""
    };
    let missing = format!(
        "No candidate for {}{} exists in the analyzed root",
        prefix, edge.dependency.install_name
    );
    let when = if edge.loader_conditional {
        format!(". {} loads only conditionally; if it loads, ", edge.loader)
    } else {
        "; ".to_string()
    };
    let (kind, explanation) = if command == "LC_LAZY_LOAD_DYLIB" {
        (
            "lazy-load-unresolved",
            format!("{missing}{when}dyld loads it on first use, which would fail unless the image is supplied elsewhere."),
        )
    } else if edge.dependency.weak {
        (
            "weak-load-unresolved",
            format!("{missing}{when}dyld continues without it."),
        )
    } else {
        (
            "required-load-unresolved",
            format!(
                "{missing}{when}dyld would fail to load this required dependency for {} ({}) unless the image is supplied elsewhere.",
                edge.root, edge.architecture
            ),
        )
    };
    DylibFinding {
        kind,
        edge_index: Some(index),
        image: Some(edge.loader.clone()),
        basis: "derived",
        explanation,
    }
}

// ---------------------------------------------------------------------------
// traceDylibLoading
// ---------------------------------------------------------------------------

pub struct TraceRequest<'a> {
    pub roots: &'a [String],
    pub unclassified: &'a [String],
    pub architecture: Option<&'a str>,
}

pub fn trace_dylib_loading(view: &dyn TreeView, request: &TraceRequest<'_>) -> NativeResult<DylibTrace> {
    let mut tracer = Tracer {
        view,
        images: HashMap::new(),
        image_order: Vec::new(),
        environment_roots: Vec::new(),
    };
    for path in request.unclassified {
        let facts = view.image(path)?;
        tracer.set_image(path, facts);
    }
    let mut roots: Vec<RootRef> = Vec::new();
    let mut edges: Vec<DylibEdge> = Vec::new();
    let mut without_architecture: Vec<String> = Vec::new();
    for root in request.roots {
        let facts = view.image(root)?;
        tracer.set_image(root, facts.clone());
        let ImageFacts::Parsed(all_slices) = facts else {
            continue;
        };
        let slices: Vec<&MachoSlice> = all_slices
            .iter()
            .filter(|s| request.architecture.map(|a| s.architecture == a).unwrap_or(true))
            .collect();
        if slices.is_empty() {
            without_architecture.push(root.clone());
        }
        for slice in slices {
            let executable = if slice.file_type == "execute" {
                Some(root.clone())
            } else {
                None
            };
            let search_overrides = if executable.is_none() {
                Vec::new()
            } else {
                embedded_dyld_overrides(&slice.dyld_environment, &slice.platforms)
            };
            if search_overrides
                .iter()
                .any(|o| o.variable == "DYLD_INSERT_LIBRARIES" && !o.value.is_empty())
                && !tracer.environment_roots.contains(root)
            {
                tracer.environment_roots.push(root.clone());
            }
            roots.push(RootRef {
                image: root.clone(),
                architecture: slice.architecture.clone(),
            });
            let mut context = ProcessContext {
                root: root.clone(),
                architecture: slice.architecture.clone(),
                search_overrides,
                platforms: slice.platforms.clone(),
                executable,
                loaded: HashMap::new(),
                by_install_name: HashMap::new(),
            };
            let (process_edges, environment_hit) = tracer.trace_process(&mut context, slice)?;
            if environment_hit && !tracer.environment_roots.contains(root) {
                tracer.environment_roots.push(root.clone());
            }
            edges.extend(process_edges);
        }
    }
    let mut reported: Vec<(String, ImageFacts)> = tracer
        .images
        .iter()
        .filter(|(_, facts)| **facts != ImageFacts::NotMachO)
        .map(|(path, facts)| (path.clone(), facts.clone()))
        .collect();
    reported.sort_by(|a, b| compare_utf16(&a.0, &b.0));
    let unparsed: Vec<String> = reported
        .iter()
        .filter(|(_, facts)| !matches!(facts, ImageFacts::Parsed(_)))
        .map(|(path, _)| path.clone())
        .collect();
    let findings = derive_findings(&edges, &roots, &tracer.images);
    let complete = unparsed.is_empty() && without_architecture.is_empty() && tracer.environment_roots.is_empty();
    let mut limitations: Vec<String> = DYLIB_RESOLUTION_LIMITATIONS.iter().map(|s| s.to_string()).collect();
    if !tracer.environment_roots.is_empty() {
        limitations.push(format!(
            "Roots {} request applicable image-selection inputs through LC_DYLD_ENVIRONMENT that are not modeled; affected dependencies or inserted images remain uncertain.",
            tracer.environment_roots.join(", ")
        ));
    }
    Ok(DylibTrace {
        roots,
        images: reported,
        edges,
        findings,
        unparsed_images: unparsed,
        roots_without_architecture: without_architecture,
        complete,
        limitations,
    })
}

/// JS `<` on strings compares UTF-16 code units.
pub fn compare_utf16(left: &str, right: &str) -> std::cmp::Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

// ---------------------------------------------------------------------------
// DylibResolutionReader.ts
// ---------------------------------------------------------------------------

fn sha256_file(absolute: &Path, path: &str, expected: Option<FileIdentity>) -> NativeResult<String> {
    let mut file = open_nofollow(absolute)
        .map_err(|e| io_failure(&e, absolute, absolute.parent().unwrap_or(absolute)))?;
    let changed = |file: &fs::File| -> NativeResult<()> {
        if let Some(expected) = expected {
            let metadata = file.metadata().map_err(|_| NativeError::artifact_bare(OPERATION, ArtifactReason::Io))?;
            if identity_of(&metadata) != expected {
                return Err(NativeError::artifact(
                    OPERATION,
                    ArtifactReason::Integrity,
                    format!("{path} changed while its dyld load commands were traced"),
                ));
            }
        }
        Ok(())
    };
    changed(&file)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| NativeError::artifact_bare(OPERATION, ArtifactReason::Io))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    changed(&file)?;
    Ok(hex::encode(hasher.finalize()))
}

fn starts_with_macho_magic(path: &Path) -> NativeResult<bool> {
    let mut file = open_nofollow(path)
        .map_err(|e| io_failure(&e, path, path.parent().unwrap_or(path)))?;
    let mut head = [0u8; 4];
    let mut filled = 0usize;
    while filled < 4 {
        let count = file
            .read(&mut head[filled..])
            .map_err(|_| NativeError::artifact_bare(OPERATION, ArtifactReason::Io))?;
        if count == 0 {
            break;
        }
        filled += count;
    }
    Ok(has_macho_magic(&head[..filled]))
}

/// Every non-symlink regular file below `root`, as `/`-joined relative paths.
fn walk_files(root: &Path) -> NativeResult<Vec<String>> {
    let mut files = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        crate::cancel::checkpoint("trace_dylib_resolution")?;
        let reader = fs::read_dir(&directory).map_err(|e| io_failure(&e, &directory, root))?;
        for child in reader {
            let child = child.map_err(|e| io_failure(&e, &directory, root))?;
            let absolute = child.path();
            let metadata = fs::symlink_metadata(&absolute).map_err(|e| io_failure(&e, &absolute, root))?;
            if metadata.file_type().is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                pending.push(absolute);
            } else if metadata.is_file() {
                let relative = absolute.strip_prefix(root).unwrap_or(&absolute);
                files.push(
                    relative
                        .components()
                        .map(|c| c.as_os_str().to_string_lossy().into_owned())
                        .collect::<Vec<_>>()
                        .join("/"),
                );
            }
        }
    }
    Ok(files)
}

fn executable_roots(root: &Path, view: &FilesystemTreeView) -> NativeResult<(Vec<String>, Vec<String>)> {
    let mut roots = Vec::new();
    let mut unclassified = Vec::new();
    for path in walk_files(root)? {
        if !starts_with_macho_magic(&root.join(&path))? {
            continue;
        }
        match view.image(&path)? {
            ImageFacts::Malformed(_) | ImageFacts::Unsupported(_) => unclassified.push(path),
            ImageFacts::Parsed(slices) if slices.iter().any(|s| s.file_type == "execute") => roots.push(path),
            _ => {}
        }
    }
    roots.sort_by(|a, b| compare_utf16(a, b));
    unclassified.sort_by(|a, b| compare_utf16(a, b));
    Ok((roots, unclassified))
}

fn require_macho_roots(
    view: &FilesystemTreeView,
    roots: &[String],
    caller_selected: bool,
) -> NativeResult<Vec<String>> {
    let mut resolved: Vec<String> = Vec::new();
    for (index, path) in roots.iter().enumerate() {
        let reject = |reason: ArtifactReason, message: String| {
            if caller_selected {
                NativeError::input(OPERATION, vec![json!("roots"), json!(index)], message)
            } else {
                NativeError::artifact(OPERATION, reason, message)
            }
        };
        let lookup = resolve_tree_path(view, path)?;
        match lookup {
            PathLookup::Escapes => {
                return Err(reject(
                    ArtifactReason::Path,
                    format!("Root {path} resolves outside the analyzed root"),
                ))
            }
            PathLookup::File(file) => {
                if view.image(&file)? == ImageFacts::NotMachO {
                    return Err(reject(ArtifactReason::Format, format!("Root {path} is not a Mach-O image")));
                }
                if !resolved.contains(&file) {
                    resolved.push(file);
                }
            }
            _ => {
                return Err(reject(
                    ArtifactReason::Path,
                    format!("Root {path} is not a regular file in the analyzed root"),
                ))
            }
        }
    }
    Ok(resolved)
}

pub struct DylibRequest<'a> {
    /// Directory to analyse (bundle directory or the executable's directory).
    pub root_path: &'a Path,
    pub target_path: &'a Path,
    pub target_sha256: &'a str,
    pub enumerate_roots: bool,
    pub roots: Option<Vec<String>>,
    pub architecture: Option<String>,
}

/// Full `trace_dylib_resolution` result (`normalized_result`) for a request.
pub fn trace_dylib_resolution(request: &DylibRequest<'_>) -> NativeResult<Value> {
    let root = fs::canonicalize(request.root_path)
        .map_err(|e| io_failure(&e, request.root_path, request.root_path))?;
    let target_real = fs::canonicalize(request.target_path)
        .map_err(|e| io_failure(&e, request.target_path, &root))?;
    let target = target_real
        .strip_prefix(&root)
        .map(|p| {
            p.components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/")
        })
        .unwrap_or_else(|_| target_real.to_string_lossy().into_owned());
    let view = FilesystemTreeView::new(root.clone());
    let caller_selected = request.roots.is_some();
    let (requested, unclassified) = match &request.roots {
        Some(roots) => (roots.clone(), Vec::new()),
        None if request.enumerate_roots => executable_roots(&root, &view)?,
        None => (vec![target.clone()], Vec::new()),
    };
    let roots = require_macho_roots(&view, &requested, caller_selected)?;
    let trace = trace_dylib_loading(
        &view,
        &TraceRequest {
            roots: &roots,
            unclassified: &unclassified,
            architecture: request.architecture.as_deref(),
        },
    )?;
    let mut digests: HashMap<String, String> = HashMap::new();
    for (path, _) in &trace.images {
        digests.insert(
            path.clone(),
            sha256_file(&root.join(path), path, view.identity(path))?,
        );
    }
    let target_digest = match digests.get(&target) {
        Some(digest) => digest.clone(),
        None => sha256_file(&root.join(&target), &target, None)?,
    };
    if target_digest != request.target_sha256 {
        return Err(NativeError::artifact(
            OPERATION,
            ArtifactReason::Integrity,
            format!(
                "Active target digest changed: expected {}, observed {}",
                request.target_sha256, target_digest
            ),
        ));
    }
    let images: Vec<Value> = trace
        .images
        .iter()
        .map(|(path, facts)| {
            let (status, reason, slices): (&str, Option<&String>, Vec<Value>) = match facts {
                ImageFacts::Parsed(slices) => ("parsed", None, slices.iter().map(slice_without_dependencies).collect()),
                ImageFacts::Malformed(reason) => ("malformed", Some(reason), Vec::new()),
                ImageFacts::Unsupported(reason) => ("unsupported", Some(reason), Vec::new()),
                ImageFacts::NotMachO => ("unsupported", None, Vec::new()),
            };
            json!({
                "path": path,
                "sha256": digests.get(path),
                "parse_status": status,
                "reason": reason,
                "slices": slices,
            })
        })
        .collect();
    Ok(json!({
        "root_path": request.root_path.to_string_lossy(),
        "target_sha256": request.target_sha256,
        "roots": trace.roots,
        "images": images,
        "edges": trace.edges,
        "findings": trace.findings,
        "coverage": {
            "status": if trace.complete { "complete" } else { "partial" },
            "unparsed_images": trace.unparsed_images,
            "roots_without_architecture": trace.roots_without_architecture,
        },
        "limitations": trace.limitations,
    }))
}

fn slice_without_dependencies(slice: &MachoSlice) -> Value {
    let mut value = serde_json::to_value(slice).unwrap_or(Value::Null);
    if let Some(map) = value.as_object_mut() {
        map.remove("dependencies");
    }
    value
}

/// Distinct set helper for callers that need insertion-ordered uniqueness.
#[allow(dead_code)]
fn unique_in_order(items: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    items.into_iter().filter(|item| seen.insert(item.clone())).collect()
}

#[cfg(test)]
mod cancel_tests {
    use super::*;

    #[test]
    fn a_cancelled_request_stops_the_directory_walk() {
        let root = std::env::temp_dir().join(format!("tracewise-cancel-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("a/b")).unwrap();
        fs::write(root.join("a/b/file"), b"x").unwrap();
        let token = crate::cancel::CancelToken::new();
        token.cancel();
        let result = crate::cancel::scope(token, || walk_files(&root));
        fs::remove_dir_all(&root).unwrap();
        match result {
            Err(NativeError::Cancelled { operation }) => assert_eq!(operation, "trace_dylib_resolution"),
            other => panic!("expected a cancellation, got {other:?}"),
        }
    }

    #[test]
    fn without_a_token_the_walk_completes() {
        let root = std::env::temp_dir().join(format!("tracewise-nocancel-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("a")).unwrap();
        fs::write(root.join("a/file"), b"x").unwrap();
        let files = walk_files(&root).unwrap();
        fs::remove_dir_all(&root).unwrap();
        assert_eq!(files, vec!["a/file".to_string()]);
    }
}
