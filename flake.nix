{
    inputs = {
        flake-utils.url = "github:numtide/flake-utils";
    };

    outputs = { self, nixpkgs, flake-utils }: flake-utils.lib.eachDefaultSystem(system:
        let
            pkgs = import nixpkgs { inherit system; };
        in {
            devShells.default = pkgs.mkShell {
                buildInputs = with pkgs; [
                    zola
                ];
                shellHook = ''
                    PS1="''${PS1/\\n/\\n(website) }"
                '';
            };

            packages.default = pkgs.stdenv.mkDerivation {
                pname = "website";
                version = "0.1.0";
                src = ./.;
                buildInputs = [ pkgs.zola ];
                buildPhase = ''
                    zola build --output-dir $out
                '';
                installPhase = "true"; # only rebuild on change
            };

            apps.default = {
                type = "app";
                program = "${pkgs.writeShellScriptBin "zola-serve" ''
                    exec ${pkgs.zola}/bin/zola serve --drafts "$@"
                ''}/bin/zola-serve";
            };
        }
    );
}

