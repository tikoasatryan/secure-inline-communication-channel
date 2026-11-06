# macOS development and Linux execution

macOS is suitable for editing C source, using Git, and managing the GitHub repo.
Linux network namespaces, veth devices, and NFQUEUE require a Linux kernel.

Recommended setup:
1. Install UTM from https://mac.getutm.app/
2. Download Ubuntu 24.04 ARM64 for Apple Silicon or x86_64 for Intel.
3. Create a VM with at least 2 CPU cores, 4 GB RAM, and 25 GB disk.
4. Install Ubuntu.
5. In Ubuntu, install packages listed in the root README.
6. Transfer this repository into the VM or clone it from GitHub.
7. Build and run all networking tests inside Ubuntu.

Do not expect `ip netns` or NFQUEUE to work natively in macOS Terminal.
