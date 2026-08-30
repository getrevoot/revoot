# mise release integration

After public GitHub release assets are available, run
`scripts/generate-package-manager-manifests.sh`. The output uses mise's native
`github:` backend with explicit platform assets and SHA-256 checksums. Submit
the project to the public mise registry for the eventual short `revoot` name;
do not use the deprecated `ubi:` backend.
