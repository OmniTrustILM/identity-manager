# CLAUDE.md

- Run `scripts/sonar-local.sh` with `env -u SONAR_TOKEN`, and never two runs at once: they share the container and
  port.
- The local `sonarqube:community` image does not analyse Rust. Locally, Clippy with warnings as errors
  (`scripts/verify.sh lint`) is the Rust gate; Rust issues show only in SonarCloud.
- The Sonar scope is written in `.github/workflows/sonar.yml`, `.github/workflows/build.yml` and
  `scripts/sonar-local.sh`; change all three together.
- The job in `sonar.yml` holds the Sonar secrets and must never run code from the pull request: no cargo, npm or
  repository script, and no Sonar property read from the checkout.
- `.github/CODEOWNERS`, `.github/release.yml`, `issue-automation.yml` and `release-automation.yml` come from the
  organization's template sync and are not edited here.
- Third-party actions are pinned by commit with a version comment.
