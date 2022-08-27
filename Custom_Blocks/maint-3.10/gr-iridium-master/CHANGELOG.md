# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Changed
- Indicate support for GNU Radio 3.10 in MANIFEST.md.
- Limit size of detected bursts to 90 ms for better frame sorting.
- Improve suppression of long lasting interference.

### Added
- Support for ZeroMQ sources.
- Support for USRP devices via UHD.

### Fixed
- Use single "system" gain in BladeRF example

## [1.0.0] - 2022-04-30
### Added
- A changelog

[Unreleased]: https://github.com/muccc/gr-iridium/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/muccc/gr-iridium/releases/tag/v1.0.0
