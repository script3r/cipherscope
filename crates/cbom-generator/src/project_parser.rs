//! Generic project parsing for multiple build systems and languages

use anyhow::{Context, Result};
use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Information about a project dependency
#[derive(Debug, Clone)]
pub struct ProjectDependency {
    pub name: String,
    pub version: Option<String>,
    pub scope: Option<String>, // e.g., "dev", "test", "runtime"
    pub language: ProjectLanguage,
    pub is_crypto_related: bool,
}

/// Supported project languages/ecosystems
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ProjectLanguage {
    Rust,
    Java,
    Go,
    Python,
    JavaScript,
    C,
    Cpp,
    PHP,
    Ruby,
    Kotlin,
    Swift,
}

/// Information about a project
#[derive(Debug, Clone)]
pub struct ProjectInfo {
    pub name: String,
    pub version: Option<String>,
    pub language: ProjectLanguage,
    pub project_type: ProjectType,
}

/// Type of project configuration file
#[derive(Debug, Clone)]
pub enum ProjectType {
    Cargo,        // Cargo.toml
    Maven,        // pom.xml
    Gradle,       // build.gradle, build.gradle.kts
    GoMod,        // go.mod
    NPM,          // package.json
    Requirements, // requirements.txt
    Pipfile,      // Pipfile
    Gemfile,      // Gemfile
    Composer,     // composer.json
    Makefile,     // Makefile, makefile
    CMake,        // CMakeLists.txt
    Podspec,      // *.podspec
    Bazel,        // BUILD, BUILD.bazel, WORKSPACE
    Buck,         // BUCK, .buckconfig
}

/// Generic project parser for multiple build systems and languages
pub struct ProjectParser {
    /// Known cryptographic packages/libraries by language
    crypto_packages: HashMap<ProjectLanguage, HashMap<String, CryptoPackageInfo>>,
}

/// Information about a cryptographic package
#[derive(Debug, Clone)]
pub struct CryptoPackageInfo {
    pub algorithms: Vec<String>,
    pub is_pqc_vulnerable: bool,
    pub description: String,
}

impl ProjectParser {
    pub fn new() -> Self {
        let mut parser = Self {
            crypto_packages: HashMap::new(),
        };
        parser.populate_crypto_packages();
        parser
    }

    /// Parse project information and dependencies from a directory (non-recursive)
    pub fn parse_project(&self, scan_path: &Path) -> Result<(ProjectInfo, Vec<ProjectDependency>)> {
        // Try to detect project type by looking for common files
        if let Some((project_type, file_path)) = self.detect_project_type(scan_path) {
            match project_type {
                ProjectType::Cargo => self.parse_cargo_project(&file_path),
                ProjectType::Maven => self.parse_maven_project(&file_path),
                ProjectType::Gradle => self.parse_gradle_project(&file_path),
                ProjectType::GoMod => self.parse_go_project(&file_path),
                ProjectType::NPM => self.parse_npm_project(&file_path),
                ProjectType::Requirements => self.parse_requirements_project(&file_path, scan_path),
                ProjectType::Pipfile => self.parse_pipfile_project(&file_path),
                ProjectType::Gemfile => self.parse_gemfile_project(&file_path),
                ProjectType::Composer => self.parse_composer_project(&file_path),
                ProjectType::Makefile => self.parse_makefile_project(&file_path, scan_path),
                ProjectType::CMake => self.parse_cmake_project(&file_path, scan_path),
                ProjectType::Podspec => self.parse_podspec_project(&file_path),
                ProjectType::Bazel => self.parse_bazel_project(&file_path, scan_path),
                ProjectType::Buck => self.parse_buck_project(&file_path, scan_path),
            }
        } else {
            // Fallback: create minimal project info based on directory name
            let name = scan_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown-project")
                .to_string();

            let project_info = ProjectInfo {
                name,
                version: None,
                language: ProjectLanguage::C,        // Default fallback
                project_type: ProjectType::Makefile, // Generic fallback
            };

            Ok((project_info, Vec::new()))
        }
    }

    /// Recursively discover all projects in a directory tree
    pub fn discover_projects(
        &self,
        scan_path: &Path,
    ) -> Result<Vec<(PathBuf, ProjectInfo, Vec<ProjectDependency>)>> {
        let mut projects = Vec::new();

        // Use walkdir to recursively scan for project files
        for entry in walkdir::WalkDir::new(scan_path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let file_path = entry.path();
            let dir_path = file_path.parent().unwrap_or(scan_path);

            // Check if this file indicates a project root
            if let Some(project_type) = self.classify_project_file(file_path) {
                // Skip if we already found a project in this directory
                if projects.iter().any(|(path, _, _)| path == dir_path) {
                    continue;
                }

                // Parse the project
                match self.parse_project_from_file(file_path, dir_path, project_type) {
                    Ok((project_info, dependencies)) => {
                        projects.push((dir_path.to_path_buf(), project_info, dependencies));
                    }
                    Err(e) => {
                        eprintln!(
                            "Warning: Failed to parse project at {}: {}",
                            dir_path.display(),
                            e
                        );
                    }
                }
            }
        }

        // If no projects found, create a default one for the root
        if projects.is_empty() {
            let (project_info, dependencies) = self.parse_project(scan_path)?;
            projects.push((scan_path.to_path_buf(), project_info, dependencies));
        }

        Ok(projects)
    }

    /// Classify a file to determine if it's a project configuration file
    fn classify_project_file(&self, file_path: &Path) -> Option<ProjectType> {
        let file_name = file_path.file_name()?.to_str()?;

        match file_name {
            "Cargo.toml" => Some(ProjectType::Cargo),
            "pom.xml" => Some(ProjectType::Maven),
            "build.gradle" | "build.gradle.kts" => Some(ProjectType::Gradle),
            "go.mod" => Some(ProjectType::GoMod),
            "package.json" => Some(ProjectType::NPM),
            "requirements.txt" => Some(ProjectType::Requirements),
            "Pipfile" => Some(ProjectType::Pipfile),
            "Gemfile" => Some(ProjectType::Gemfile),
            "composer.json" => Some(ProjectType::Composer),
            "Makefile" | "makefile" => Some(ProjectType::Makefile),
            "CMakeLists.txt" => Some(ProjectType::CMake),
            "WORKSPACE" | "BUILD" | "BUILD.bazel" => Some(ProjectType::Bazel),
            "BUCK" | ".buckconfig" => Some(ProjectType::Buck),
            name if name.ends_with(".podspec") => Some(ProjectType::Podspec),
            _ => None,
        }
    }

    /// Parse a project from a specific file and directory
    fn parse_project_from_file(
        &self,
        file_path: &Path,
        dir_path: &Path,
        project_type: ProjectType,
    ) -> Result<(ProjectInfo, Vec<ProjectDependency>)> {
        match project_type {
            ProjectType::Cargo => self.parse_cargo_project(file_path),
            ProjectType::Maven => self.parse_maven_project(file_path),
            ProjectType::Gradle => self.parse_gradle_project(file_path),
            ProjectType::GoMod => self.parse_go_project(file_path),
            ProjectType::NPM => self.parse_npm_project(file_path),
            ProjectType::Requirements => self.parse_requirements_project(file_path, dir_path),
            ProjectType::Pipfile => self.parse_pipfile_project(file_path),
            ProjectType::Gemfile => self.parse_gemfile_project(file_path),
            ProjectType::Composer => self.parse_composer_project(file_path),
            ProjectType::Makefile => self.parse_makefile_project(file_path, dir_path),
            ProjectType::CMake => self.parse_cmake_project(file_path, dir_path),
            ProjectType::Podspec => self.parse_podspec_project(file_path),
            ProjectType::Bazel => self.parse_bazel_project(file_path, dir_path),
            ProjectType::Buck => self.parse_buck_project(file_path, dir_path),
        }
    }

    /// Detect project type by scanning for common configuration files
    fn detect_project_type(&self, scan_path: &Path) -> Option<(ProjectType, std::path::PathBuf)> {
        let candidates = vec![
            ("Cargo.toml", ProjectType::Cargo),
            ("pom.xml", ProjectType::Maven),
            ("build.gradle", ProjectType::Gradle),
            ("build.gradle.kts", ProjectType::Gradle),
            ("go.mod", ProjectType::GoMod),
            ("package.json", ProjectType::NPM),
            ("requirements.txt", ProjectType::Requirements),
            ("Pipfile", ProjectType::Pipfile),
            ("Gemfile", ProjectType::Gemfile),
            ("composer.json", ProjectType::Composer),
            ("Makefile", ProjectType::Makefile),
            ("makefile", ProjectType::Makefile),
            ("CMakeLists.txt", ProjectType::CMake),
            ("WORKSPACE", ProjectType::Bazel),
            ("BUILD", ProjectType::Bazel),
            ("BUILD.bazel", ProjectType::Bazel),
            ("BUCK", ProjectType::Buck),
            (".buckconfig", ProjectType::Buck),
        ];

        for (filename, project_type) in candidates {
            let path = scan_path.join(filename);
            if path.exists() {
                return Some((project_type, path));
            }
        }

        // Check for podspec files
        if let Ok(entries) = fs::read_dir(scan_path) {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    if name.ends_with(".podspec") {
                        return Some((ProjectType::Podspec, entry.path()));
                    }
                }
            }
        }

        None
    }

    /// Parse Rust Cargo.toml project
    fn parse_cargo_project(
        &self,
        cargo_path: &Path,
    ) -> Result<(ProjectInfo, Vec<ProjectDependency>)> {
        let content = fs::read_to_string(cargo_path).context("Failed to read Cargo.toml")?;

        let cargo_toml: CargoToml =
            toml::from_str(&content).context("Failed to parse Cargo.toml")?;

        let project_info = ProjectInfo {
            name: cargo_toml.package.name.clone(),
            version: Some(cargo_toml.package.version.clone()),
            language: ProjectLanguage::Rust,
            project_type: ProjectType::Cargo,
        };

        let mut dependencies = Vec::new();

        // Parse regular dependencies
        if let Some(deps) = cargo_toml.dependencies {
            for (name, _spec) in deps {
                dependencies.push(self.create_dependency(name, None, None, ProjectLanguage::Rust));
            }
        }

        // Parse dev dependencies
        if let Some(dev_deps) = cargo_toml.dev_dependencies {
            for (name, _spec) in dev_deps {
                dependencies.push(self.create_dependency(
                    name,
                    None,
                    Some("dev".to_string()),
                    ProjectLanguage::Rust,
                ));
            }
        }

        Ok((project_info, dependencies))
    }

    /// Parse Java Maven pom.xml project
    fn parse_maven_project(
        &self,
        pom_path: &Path,
    ) -> Result<(ProjectInfo, Vec<ProjectDependency>)> {
        let content = fs::read_to_string(pom_path).context("Failed to read pom.xml")?;

        // Simple regex-based XML parsing (could use a proper XML parser for production)
        let artifact_id_re = Regex::new(r"<artifactId>([^<]+)</artifactId>").unwrap();
        let version_re = Regex::new(r"<version>([^<]+)</version>").unwrap();
        let dependency_re = Regex::new(r"<dependency>[\s\S]*?<groupId>([^<]+)</groupId>[\s\S]*?<artifactId>([^<]+)</artifactId>[\s\S]*?(?:<version>([^<]+)</version>)?[\s\S]*?(?:<scope>([^<]+)</scope>)?[\s\S]*?</dependency>").unwrap();

        let project_name = artifact_id_re
            .find(&content)
            .map(|m| {
                content[m.range()]
                    .replace("<artifactId>", "")
                    .replace("</artifactId>", "")
            })
            .unwrap_or_else(|| "unknown-java-project".to_string());

        let project_version = version_re.find(&content).map(|m| {
            content[m.range()]
                .replace("<version>", "")
                .replace("</version>", "")
        });

        let project_info = ProjectInfo {
            name: project_name,
            version: project_version,
            language: ProjectLanguage::Java,
            project_type: ProjectType::Maven,
        };

        let mut dependencies = Vec::new();
        for caps in dependency_re.captures_iter(&content) {
            let group_id = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let artifact_id = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            let version = caps.get(3).map(|m| m.as_str().to_string());
            let scope = caps.get(4).map(|m| m.as_str().to_string());

            let name = if group_id.is_empty() {
                artifact_id.to_string()
            } else {
                format!("{}:{}", group_id, artifact_id)
            };

            dependencies.push(self.create_dependency(name, version, scope, ProjectLanguage::Java));
        }

        Ok((project_info, dependencies))
    }

    /// Parse Go go.mod project
    fn parse_go_project(
        &self,
        go_mod_path: &Path,
    ) -> Result<(ProjectInfo, Vec<ProjectDependency>)> {
        let content = fs::read_to_string(go_mod_path).context("Failed to read go.mod")?;

        let module_re = Regex::new(r"module\s+([^\s\n]+)").unwrap();
        let go_version_re = Regex::new(r"go\s+([0-9.]+)").unwrap();
        let require_re = Regex::new(r"require\s+([^\s]+)\s+([^\s\n]+)").unwrap();

        let module_name = module_re
            .captures(&content)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().to_string())
            .unwrap_or_else(|| "unknown-go-project".to_string());

        let go_version = go_version_re
            .captures(&content)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().to_string());

        let project_info = ProjectInfo {
            name: module_name
                .split('/')
                .last()
                .unwrap_or(&module_name)
                .to_string(),
            version: go_version,
            language: ProjectLanguage::Go,
            project_type: ProjectType::GoMod,
        };

        let mut dependencies = Vec::new();
        for caps in require_re.captures_iter(&content) {
            let name = caps
                .get(1)
                .map(|m| m.as_str().to_string())
                .unwrap_or_default();
            let version = caps.get(2).map(|m| m.as_str().to_string());
            dependencies.push(self.create_dependency(name, version, None, ProjectLanguage::Go));
        }

        Ok((project_info, dependencies))
    }

    /// Parse Python requirements.txt project
    fn parse_requirements_project(
        &self,
        req_path: &Path,
        scan_path: &Path,
    ) -> Result<(ProjectInfo, Vec<ProjectDependency>)> {
        let content = fs::read_to_string(req_path).context("Failed to read requirements.txt")?;

        let project_name = scan_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown-python-project")
            .to_string();

        let project_info = ProjectInfo {
            name: project_name,
            version: None,
            language: ProjectLanguage::Python,
            project_type: ProjectType::Requirements,
        };

        let mut dependencies = Vec::new();
        let requirement_re = Regex::new(r"^([a-zA-Z0-9_-]+)(?:[>=<~!]+([0-9.]+[^#\s]*))?").unwrap();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some(caps) = requirement_re.captures(line) {
                let name = caps
                    .get(1)
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default();
                let version = caps.get(2).map(|m| m.as_str().to_string());
                dependencies.push(self.create_dependency(
                    name,
                    version,
                    None,
                    ProjectLanguage::Python,
                ));
            }
        }

        Ok((project_info, dependencies))
    }

    /// Parse Node.js package.json project
    fn parse_npm_project(
        &self,
        package_path: &Path,
    ) -> Result<(ProjectInfo, Vec<ProjectDependency>)> {
        let content = fs::read_to_string(package_path).context("Failed to read package.json")?;

        let package_json: serde_json::Value =
            serde_json::from_str(&content).context("Failed to parse package.json")?;

        let project_name = package_json["name"]
            .as_str()
            .unwrap_or("unknown-js-project")
            .to_string();
        let project_version = package_json["version"].as_str().map(|s| s.to_string());

        let project_info = ProjectInfo {
            name: project_name,
            version: project_version,
            language: ProjectLanguage::JavaScript,
            project_type: ProjectType::NPM,
        };

        let mut dependencies = Vec::new();

        // Parse regular dependencies
        if let Some(deps) = package_json["dependencies"].as_object() {
            for (name, version) in deps {
                let version_str = version.as_str().map(|s| s.to_string());
                dependencies.push(self.create_dependency(
                    name.clone(),
                    version_str,
                    None,
                    ProjectLanguage::JavaScript,
                ));
            }
        }

        // Parse dev dependencies
        if let Some(dev_deps) = package_json["devDependencies"].as_object() {
            for (name, version) in dev_deps {
                let version_str = version.as_str().map(|s| s.to_string());
                dependencies.push(self.create_dependency(
                    name.clone(),
                    version_str,
                    Some("dev".to_string()),
                    ProjectLanguage::JavaScript,
                ));
            }
        }

        Ok((project_info, dependencies))
    }

    /// Parse Makefile project (simple heuristic-based parsing)
    fn parse_makefile_project(
        &self,
        makefile_path: &Path,
        scan_path: &Path,
    ) -> Result<(ProjectInfo, Vec<ProjectDependency>)> {
        let content = fs::read_to_string(makefile_path).context("Failed to read Makefile")?;

        let project_name = scan_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown-c-project")
            .to_string();

        // Detect language based on file extensions and makefile content
        let language = if content.contains("g++")
            || content.contains("clang++")
            || content.contains(".cpp")
            || content.contains(".cxx")
        {
            ProjectLanguage::Cpp
        } else {
            ProjectLanguage::C
        };

        let project_info = ProjectInfo {
            name: project_name,
            version: None,
            language: language.clone(),
            project_type: ProjectType::Makefile,
        };

        let mut dependencies = Vec::new();

        // Look for common crypto libraries linked in Makefiles
        let crypto_lib_re = Regex::new(r"-l(ssl|crypto|gcrypt|sodium|mbedtls|botan)").unwrap();
        for caps in crypto_lib_re.captures_iter(&content) {
            if let Some(lib_match) = caps.get(1) {
                let lib_name = lib_match.as_str().to_string();
                dependencies.push(self.create_dependency(lib_name, None, None, language.clone()));
            }
        }

        Ok((project_info, dependencies))
    }

    // Placeholder implementations for other project types
    fn parse_gradle_project(
        &self,
        _gradle_path: &Path,
    ) -> Result<(ProjectInfo, Vec<ProjectDependency>)> {
        // TODO: Implement Gradle parsing
        Ok((
            ProjectInfo {
                name: "gradle-project".to_string(),
                version: None,
                language: ProjectLanguage::Java,
                project_type: ProjectType::Gradle,
            },
            Vec::new(),
        ))
    }

    fn parse_pipfile_project(
        &self,
        _pipfile_path: &Path,
    ) -> Result<(ProjectInfo, Vec<ProjectDependency>)> {
        // TODO: Implement Pipfile parsing
        Ok((
            ProjectInfo {
                name: "pipfile-project".to_string(),
                version: None,
                language: ProjectLanguage::Python,
                project_type: ProjectType::Pipfile,
            },
            Vec::new(),
        ))
    }

    fn parse_gemfile_project(
        &self,
        _gemfile_path: &Path,
    ) -> Result<(ProjectInfo, Vec<ProjectDependency>)> {
        // TODO: Implement Gemfile parsing
        Ok((
            ProjectInfo {
                name: "ruby-project".to_string(),
                version: None,
                language: ProjectLanguage::Ruby,
                project_type: ProjectType::Gemfile,
            },
            Vec::new(),
        ))
    }

    fn parse_composer_project(
        &self,
        _composer_path: &Path,
    ) -> Result<(ProjectInfo, Vec<ProjectDependency>)> {
        // TODO: Implement composer.json parsing
        Ok((
            ProjectInfo {
                name: "php-project".to_string(),
                version: None,
                language: ProjectLanguage::PHP,
                project_type: ProjectType::Composer,
            },
            Vec::new(),
        ))
    }

    fn parse_cmake_project(
        &self,
        _cmake_path: &Path,
        scan_path: &Path,
    ) -> Result<(ProjectInfo, Vec<ProjectDependency>)> {
        let project_name = scan_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("cmake-project")
            .to_string();

        Ok((
            ProjectInfo {
                name: project_name,
                version: None,
                language: ProjectLanguage::Cpp,
                project_type: ProjectType::CMake,
            },
            Vec::new(),
        ))
    }

    fn parse_podspec_project(
        &self,
        _podspec_path: &Path,
    ) -> Result<(ProjectInfo, Vec<ProjectDependency>)> {
        // TODO: Implement podspec parsing
        Ok((
            ProjectInfo {
                name: "swift-project".to_string(),
                version: None,
                language: ProjectLanguage::Swift,
                project_type: ProjectType::Podspec,
            },
            Vec::new(),
        ))
    }

    /// Parse Bazel project (BUILD, BUILD.bazel, WORKSPACE files)
    fn parse_bazel_project(
        &self,
        bazel_path: &Path,
        scan_path: &Path,
    ) -> Result<(ProjectInfo, Vec<ProjectDependency>)> {
        let content = fs::read_to_string(bazel_path).context("Failed to read Bazel file")?;

        let project_name = scan_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("bazel-project")
            .to_string();

        // Detect primary language based on file patterns and rules
        let language = self.detect_bazel_language(&content, scan_path);

        let project_info = ProjectInfo {
            name: project_name,
            version: None, // Bazel doesn't typically have project versions
            language: language.clone(),
            project_type: ProjectType::Bazel,
        };

        let mut dependencies = Vec::new();

        // Parse common Bazel dependency patterns
        self.parse_bazel_dependencies(&content, &language, &mut dependencies)?;

        Ok((project_info, dependencies))
    }

    /// Parse BUCK project (BUCK, .buckconfig files)
    fn parse_buck_project(
        &self,
        buck_path: &Path,
        scan_path: &Path,
    ) -> Result<(ProjectInfo, Vec<ProjectDependency>)> {
        let content = fs::read_to_string(buck_path).context("Failed to read BUCK file")?;

        let project_name = scan_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("buck-project")
            .to_string();

        // Detect primary language based on BUCK rules
        let language = self.detect_buck_language(&content, scan_path);

        let project_info = ProjectInfo {
            name: project_name,
            version: None, // BUCK doesn't typically have project versions
            language: language.clone(),
            project_type: ProjectType::Buck,
        };

        let mut dependencies = Vec::new();

        // Parse common BUCK dependency patterns
        self.parse_buck_dependencies(&content, &language, &mut dependencies)?;

        Ok((project_info, dependencies))
    }

    /// Detect the primary language in a Bazel project
    fn detect_bazel_language(&self, content: &str, scan_path: &Path) -> ProjectLanguage {
        // Check for language-specific rules in BUILD files
        if content.contains("java_") || content.contains("kt_") {
            return ProjectLanguage::Java;
        }
        if content.contains("cc_") || content.contains("cpp_") {
            return ProjectLanguage::Cpp;
        }
        if content.contains("py_") || content.contains("python_") {
            return ProjectLanguage::Python;
        }
        if content.contains("go_") || content.contains("golang_") {
            return ProjectLanguage::Go;
        }
        if content.contains("rust_") {
            return ProjectLanguage::Rust;
        }
        if content.contains("swift_") {
            return ProjectLanguage::Swift;
        }
        if content.contains("js_") || content.contains("ts_") || content.contains("nodejs_") {
            return ProjectLanguage::JavaScript;
        }

        // Fallback: scan directory for common file types
        self.detect_language_from_files(scan_path)
    }

    /// Detect the primary language in a BUCK project
    fn detect_buck_language(&self, content: &str, scan_path: &Path) -> ProjectLanguage {
        // Check for language-specific rules in BUCK files
        if content.contains("java_") || content.contains("android_") {
            return ProjectLanguage::Java;
        }
        if content.contains("cxx_") || content.contains("cpp_") {
            return ProjectLanguage::Cpp;
        }
        if content.contains("python_") {
            return ProjectLanguage::Python;
        }
        if content.contains("go_") {
            return ProjectLanguage::Go;
        }
        if content.contains("rust_") {
            return ProjectLanguage::Rust;
        }
        if content.contains("swift_") {
            return ProjectLanguage::Swift;
        }

        // Fallback: scan directory for common file types
        self.detect_language_from_files(scan_path)
    }

    /// Detect language from files in the directory
    fn detect_language_from_files(&self, scan_path: &Path) -> ProjectLanguage {
        if let Ok(entries) = fs::read_dir(scan_path) {
            let mut file_counts = HashMap::new();

            for entry in entries.flatten() {
                if let Some(ext) = entry.path().extension().and_then(|e| e.to_str()) {
                    let lang = match ext {
                        "java" | "kt" => ProjectLanguage::Java,
                        "cpp" | "cc" | "cxx" | "c" | "h" | "hpp" => ProjectLanguage::Cpp,
                        "py" => ProjectLanguage::Python,
                        "go" => ProjectLanguage::Go,
                        "rs" => ProjectLanguage::Rust,
                        "swift" => ProjectLanguage::Swift,
                        "js" | "ts" => ProjectLanguage::JavaScript,
                        "php" => ProjectLanguage::PHP,
                        "rb" => ProjectLanguage::Ruby,
                        _ => continue,
                    };
                    *file_counts.entry(lang).or_insert(0) += 1;
                }
            }

            // Return the most common language
            if let Some((lang, _)) = file_counts.iter().max_by_key(|(_, count)| *count) {
                return lang.clone();
            }
        }

        // Default fallback
        ProjectLanguage::C
    }

    /// Parse Bazel dependencies from BUILD file content
    fn parse_bazel_dependencies(
        &self,
        content: &str,
        language: &ProjectLanguage,
        dependencies: &mut Vec<ProjectDependency>,
    ) -> Result<()> {
        // Parse deps = [...] patterns
        let deps_re = Regex::new(r#"deps\s*=\s*\[\s*([^\]]+)\]"#).unwrap();

        for caps in deps_re.captures_iter(content) {
            if let Some(deps_content) = caps.get(1) {
                // Extract individual dependency strings
                let dep_re = Regex::new(r#""([^"]+)""#).unwrap();
                for dep_cap in dep_re.captures_iter(deps_content.as_str()) {
                    if let Some(dep_name) = dep_cap.get(1) {
                        let name = dep_name.as_str().to_string();
                        dependencies.push(self.create_dependency(
                            name,
                            None,
                            None,
                            language.clone(),
                        ));
                    }
                }
            }
        }

        // Parse maven_jar and other external dependency patterns
        let maven_re = Regex::new(r#"maven_jar\s*\(\s*name\s*=\s*"([^"]+)""#).unwrap();
        for caps in maven_re.captures_iter(content) {
            if let Some(name_match) = caps.get(1) {
                let name = name_match.as_str().to_string();
                dependencies.push(self.create_dependency(name, None, None, language.clone()));
            }
        }

        Ok(())
    }

    /// Parse BUCK dependencies from BUCK file content
    fn parse_buck_dependencies(
        &self,
        content: &str,
        language: &ProjectLanguage,
        dependencies: &mut Vec<ProjectDependency>,
    ) -> Result<()> {
        // Parse deps = [...] patterns (similar to Bazel)
        let deps_re = Regex::new(r#"deps\s*=\s*\[\s*([^\]]+)\]"#).unwrap();

        for caps in deps_re.captures_iter(content) {
            if let Some(deps_content) = caps.get(1) {
                let dep_re = Regex::new(r#"['":]([^'"]+)['"]"#).unwrap();
                for dep_cap in dep_re.captures_iter(deps_content.as_str()) {
                    if let Some(dep_name) = dep_cap.get(1) {
                        let name = dep_name.as_str().to_string();
                        dependencies.push(self.create_dependency(
                            name,
                            None,
                            None,
                            language.clone(),
                        ));
                    }
                }
            }
        }

        // Parse prebuilt_jar and maven_jar patterns
        let jar_re =
            Regex::new(r#"(?:prebuilt_jar|maven_jar)\s*\(\s*name\s*=\s*['""]([^'"]+)['""]"#)
                .unwrap();
        for caps in jar_re.captures_iter(content) {
            if let Some(name_match) = caps.get(1) {
                let name = name_match.as_str().to_string();
                dependencies.push(self.create_dependency(name, None, None, language.clone()));
            }
        }

        Ok(())
    }

    /// Create a dependency with crypto detection
    fn create_dependency(
        &self,
        name: String,
        version: Option<String>,
        scope: Option<String>,
        language: ProjectLanguage,
    ) -> ProjectDependency {
        let is_crypto_related = self.is_crypto_package(&name, &language);

        ProjectDependency {
            name,
            version,
            scope,
            language,
            is_crypto_related,
        }
    }

    /// Check if a package is cryptography-related
    pub fn is_crypto_package(&self, package_name: &str, language: &ProjectLanguage) -> bool {
        if let Some(lang_packages) = self.crypto_packages.get(language) {
            lang_packages.contains_key(package_name)
        } else {
            false
        }
    }

    /// Get crypto package information
    pub fn get_crypto_package_info(
        &self,
        package_name: &str,
        language: &ProjectLanguage,
    ) -> Option<&CryptoPackageInfo> {
        self.crypto_packages.get(language)?.get(package_name)
    }

    /// Populate the database of known cryptographic packages
    fn populate_crypto_packages(&mut self) {
        // Rust packages
        let mut rust_packages = HashMap::new();
        rust_packages.insert(
            "rsa".to_string(),
            CryptoPackageInfo {
                algorithms: vec!["RSA".to_string()],
                is_pqc_vulnerable: true,
                description: "RSA implementation".to_string(),
            },
        );
        rust_packages.insert(
            "aes-gcm".to_string(),
            CryptoPackageInfo {
                algorithms: vec!["AES-GCM".to_string()],
                is_pqc_vulnerable: false,
                description: "AES-GCM AEAD".to_string(),
            },
        );
        rust_packages.insert(
            "sha2".to_string(),
            CryptoPackageInfo {
                algorithms: vec!["SHA-256".to_string(), "SHA-512".to_string()],
                is_pqc_vulnerable: false,
                description: "SHA-2 hash functions".to_string(),
            },
        );
        self.crypto_packages
            .insert(ProjectLanguage::Rust, rust_packages);

        // Java packages
        let mut java_packages = HashMap::new();
        java_packages.insert(
            "org.bouncycastle:bcprov-jdk15on".to_string(),
            CryptoPackageInfo {
                algorithms: vec!["RSA".to_string(), "ECDSA".to_string(), "AES".to_string()],
                is_pqc_vulnerable: true,
                description: "BouncyCastle Crypto Provider".to_string(),
            },
        );
        self.crypto_packages
            .insert(ProjectLanguage::Java, java_packages);

        // Python packages
        let mut python_packages = HashMap::new();
        python_packages.insert(
            "cryptography".to_string(),
            CryptoPackageInfo {
                algorithms: vec!["RSA".to_string(), "ECDSA".to_string(), "AES".to_string()],
                is_pqc_vulnerable: true,
                description: "PyCA Cryptography".to_string(),
            },
        );
        python_packages.insert(
            "pycryptodome".to_string(),
            CryptoPackageInfo {
                algorithms: vec!["RSA".to_string(), "AES".to_string()],
                is_pqc_vulnerable: true,
                description: "PyCryptodome".to_string(),
            },
        );
        self.crypto_packages
            .insert(ProjectLanguage::Python, python_packages);

        // JavaScript packages
        let mut js_packages = HashMap::new();
        js_packages.insert(
            "crypto-js".to_string(),
            CryptoPackageInfo {
                algorithms: vec!["AES".to_string(), "SHA-256".to_string()],
                is_pqc_vulnerable: false,
                description: "JavaScript crypto library".to_string(),
            },
        );
        self.crypto_packages
            .insert(ProjectLanguage::JavaScript, js_packages);

        // C/C++ libraries (detected from Makefiles)
        let mut c_packages = HashMap::new();
        c_packages.insert(
            "ssl".to_string(),
            CryptoPackageInfo {
                algorithms: vec!["RSA".to_string(), "ECDSA".to_string(), "AES".to_string()],
                is_pqc_vulnerable: true,
                description: "OpenSSL".to_string(),
            },
        );
        c_packages.insert(
            "crypto".to_string(),
            CryptoPackageInfo {
                algorithms: vec!["RSA".to_string(), "ECDSA".to_string(), "AES".to_string()],
                is_pqc_vulnerable: true,
                description: "OpenSSL Crypto".to_string(),
            },
        );
        c_packages.insert(
            "sodium".to_string(),
            CryptoPackageInfo {
                algorithms: vec!["ChaCha20Poly1305".to_string(), "Ed25519".to_string()],
                is_pqc_vulnerable: true, // Ed25519 is vulnerable
                description: "libsodium".to_string(),
            },
        );
        self.crypto_packages
            .insert(ProjectLanguage::C, c_packages.clone());
        self.crypto_packages
            .insert(ProjectLanguage::Cpp, c_packages);

        // Go packages
        let mut go_packages = HashMap::new();
        go_packages.insert(
            "golang.org/x/crypto".to_string(),
            CryptoPackageInfo {
                algorithms: vec!["RSA".to_string(), "ECDSA".to_string(), "AES".to_string()],
                is_pqc_vulnerable: true,
                description: "Go extended crypto".to_string(),
            },
        );
        self.crypto_packages
            .insert(ProjectLanguage::Go, go_packages);
    }
}

impl Default for ProjectParser {
    fn default() -> Self {
        Self::new()
    }
}

/// Simplified Cargo.toml structure for parsing
#[derive(Debug, Deserialize)]
struct CargoToml {
    package: CargoPackage,
    #[serde(default)]
    dependencies: Option<HashMap<String, toml::Value>>,
    #[serde(default, rename = "dev-dependencies")]
    dev_dependencies: Option<HashMap<String, toml::Value>>,
}

#[derive(Debug, Deserialize)]
struct CargoPackage {
    name: String,
    version: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_project_parser_creation() {
        let parser = ProjectParser::new();
        assert!(parser.is_crypto_package("rsa", &ProjectLanguage::Rust));
        assert!(parser.is_crypto_package("cryptography", &ProjectLanguage::Python));
        assert!(!parser.is_crypto_package("serde", &ProjectLanguage::Rust));
    }

    #[test]
    fn test_cargo_project_parsing() {
        let temp_dir = TempDir::new().unwrap();
        let cargo_path = temp_dir.path().join("Cargo.toml");

        let cargo_content = r#"
[package]
name = "test-project"
version = "0.1.0"

[dependencies]
rsa = "0.9"
serde = "1.0"

[dev-dependencies]
tokio = "1.0"
"#;

        std::fs::write(&cargo_path, cargo_content).unwrap();

        let parser = ProjectParser::new();
        let (project_info, dependencies) = parser.parse_cargo_project(&cargo_path).unwrap();

        assert_eq!(project_info.name, "test-project");
        assert_eq!(project_info.version, Some("0.1.0".to_string()));
        assert_eq!(project_info.language, ProjectLanguage::Rust);

        assert_eq!(dependencies.len(), 3);
        let rsa_dep = dependencies.iter().find(|d| d.name == "rsa").unwrap();
        assert!(rsa_dep.is_crypto_related);
    }

    #[test]
    fn test_requirements_parsing() {
        let temp_dir = TempDir::new().unwrap();
        let req_path = temp_dir.path().join("requirements.txt");

        let req_content = r#"
cryptography>=3.0.0
requests==2.25.1
# This is a comment
pycryptodome~=3.10.0
"#;

        std::fs::write(&req_path, req_content).unwrap();

        let parser = ProjectParser::new();
        let (project_info, dependencies) = parser
            .parse_requirements_project(&req_path, temp_dir.path())
            .unwrap();

        assert_eq!(project_info.language, ProjectLanguage::Python);

        let crypto_deps: Vec<_> = dependencies
            .iter()
            .filter(|d| d.is_crypto_related)
            .collect();
        assert_eq!(crypto_deps.len(), 2); // cryptography and pycryptodome
    }
}
