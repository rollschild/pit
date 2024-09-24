{
  description = "Git implemented in Python";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    poetry2nix.url = "github:nix-community/poetry2nix";
    utils.url = "github:numtide/flake-utils";
    utils.inputs.nixpkgs.follows = "nixpkgs";
  };
  outputs =
    {
      self,
      nixpkgs,
      poetry2nix,
      ...
    }@inputs:
    inputs.utils.lib.eachSystem
      [
        "x86_64-linux"
        "x86_64-darwin"
        "aarch64-linux"
        "aarch64-darwin"
      ]
      (
        system:
        let
          # inherit (poetry2nix.lib.mkPoetry2Nix { pkgs = pkgs.${system}; }) mkPoetryApplication;
          inherit (poetry2nix.lib.mkPoetry2Nix { inherit pkgs; }) mkPoetryEnv;
          pkgs = import nixpkgs { inherit system; };
        in
        {
          defaultPackage = poetry2nix.mkPoetryApplication {
            projectDir = self;
          };

          devShell = pkgs.mkShell rec {
            name = "git-py";
            packages = with pkgs; [
              (mkPoetryEnv { projectDir = self; })
              poetry
              ruff
              ruff-lsp
            ];
            shellHook =
              let
                icon = "f121";
              in
              ''
                export PS1="$(echo -e '\u${icon}') {\[$(tput sgr0)\]\[\033[38;5;228m\]\w\[$(tput sgr0)\]\[\033[38;5;15m\]} (${name}) \\$ \[$(tput sgr0)\]"
                export SHELL="${pkgs.zsh}/bin/zsh"
              '';
          };

        }

      );
  # {
  # packages = forAllSystems (
  # system:
  # let
  # inherit (poetry2nix.lib.mkPoetry2Nix { pkgs = pkgs.${system}; }) mkPoetryApplication;
  # pkgs = import nixpkgs { inherit system; };
  # llvm = pkgs.llvmPackages_18;
  # lib = nixpkgs.lib;
  # in
  # {
  # default = mkPoetryApplication { projectDir = self; };
  # }
  # );
  #
  # devShells = forAllSystems (
  # system:
  # let
  # inherit (poetry2nix.lib.mkPoetry2Nix { pkgs = pkgs.${system}; }) mkPoetryEnv;
  # in
  # {
  # default = pkgs.${system}.mkShellNoCC rec {
  # name = "git-py";
  # packages = with pkgs.${system}; [
  # (mkPoetryEnv { projectDir = self; })
  # poetry
  # ruff
  # ruff-lsp
  # ];
  # shellHook =
  # let
  # icon = "f121";
  # in
  # ''
  # export PS1="$(echo -e '\u${icon}') {\[$(tput sgr0)\]\[\033[38;5;228m\]\w\[$(tput sgr0)\]\[\033[38;5;15m\]} (${name}) \\$ \[$(tput sgr0)\]"
  # export SHELL="${pkgs.zsh}/bin/zsh"
  # '';
  # };
  # }
  # );
  # };
}
