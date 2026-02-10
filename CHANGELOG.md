# Changelog

All notable changes to AgentShield will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Pre-commit hooks for automated quality checks
- GitHub Actions CI/CD pipeline
- Issue and PR templates
- Security policy and vulnerability reporting
- Dependency management with Dependabot
- Code scanning with CodeQL and Gosec
- OSSF Scorecard integration

### Changed
- Improved linting and error handling
- Enhanced build automation

### Security
- Added comprehensive security scanning
- Established vulnerability disclosure process

## [0.1.0] - 2026-02-10

### Added
- Initial release of AgentShield
- Runtime security gateway for LLM agents
- 6-layer analyzer pipeline (regex, structural, semantic, dataflow, stateful, guardian)
- OpenClaw integration with automatic hook installation
- Policy pack system with extensible YAML rules
- Comprehensive test suite (123 test cases)
- Homebrew formula for easy installation
- GitHub Actions for automated releases
- Taxonomy-based weakness classification
- Compliance mapping for OWASP LLM Top 10 2025

### Security
- BLOCK/AUDIT/ALLOW decision framework
- Protected paths and allow domains
- Command intent classification
- Data exfiltration detection
- Multi-step attack chain detection
- Prompt injection signal detection

### Documentation
- Complete README with quick start guide
- Policy guide with rule examples
- Threat modeling documentation
- API documentation

### Installation
- Binary releases for multiple platforms
- Homebrew tap integration
- Source installation support

## [Future Releases]

### Planned Features
- [ ] GUI configuration interface
- [ ] Real-time monitoring dashboard
- [ ] Advanced policy editor
- [ ] Integration with more LLM platforms
- [ ] Performance optimizations
- [ ] Extended compliance frameworks
- [ ] Machine learning for anomaly detection

---

**Note:** For security vulnerabilities, please see [SECURITY.md](.github/SECURITY.md) for responsible disclosure process.
