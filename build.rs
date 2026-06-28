//! Build script: embute o ícone do Quarry no executável (Windows) e, em builds
//! de **release**, um manifesto que exige privilégios de Administrador — o
//! Quarry precisa deles (raw sockets, debugger, WinDivert). Em **debug** o
//! manifesto NÃO é aplicado, para não disparar UAC a cada `cargo run` durante o
//! desenvolvimento.

fn main() {
    #[cfg(windows)]
    {
        println!("cargo:rerun-if-changed=assets/quarry.ico");

        let mut res = winresource::WindowsResource::new();
        res.set_icon("assets/quarry.ico");

        // Só em release: força elevação (requireAdministrator).
        if std::env::var("PROFILE").as_deref() == Ok("release") {
            res.set_manifest(ADMIN_MANIFEST);
        }

        if let Err(e) = res.compile() {
            // Não falha o build por causa do recurso (ex.: rc.exe ausente em CI);
            // só avisa. O exe ainda compila, sem ícone embutido.
            println!("cargo:warning=winresource não embutiu o recurso: {e}");
        }
    }
}

#[cfg(windows)]
const ADMIN_MANIFEST: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false" />
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>
"#;
