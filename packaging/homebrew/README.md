# Homebrew release integration

`scripts/generate-package-manager-manifests.sh` produces `revoot.rb` from the
verified release checksum manifest. Publish it in the selected tap, then smoke
it on native Apple Silicon, Linux AMD64, and Linux ARM64 hosts.

It is generated during the GitHub release workflow.
