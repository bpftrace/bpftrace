FROM mcr.microsoft.com/vscode/devcontainers/base:bullseye

# Required nix install dependencies.
RUN apt-get update && apt-get install -y curl bzip2 adduser direnv vim
RUN su - vscode -c 'sh <(curl -L https://releases.nixos.org/nix/nix-2.26.3/install) --no-daemon'
RUN su - vscode -c 'mkdir -p ~/.config/nix && echo "extra-experimental-features = nix-command flakes" > ~/.config/nix/nix.conf'
RUN su - vscode -c 'nix-env -iA nixpkgs.direnv'
RUN su - vscode -c 'direnv hook bash >> ~/.bashrc'
USER vscode
