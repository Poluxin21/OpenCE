//! Build script do instalador: dá ao `quarry-setup.exe` o ícone do Quarry e um
//! manifesto que exige Administrador (escreve em Program Files + HKLM).

fn main() {
    #[cfg(windows)]
    {
        println!("cargo:rerun-if-changed=../../assets/quarry.ico");
        let mut res = winresource::WindowsResource::new();
        res.set_icon("../../assets/quarry.ico");
        res.set_manifest(ADMIN_MANIFEST);
        if let Err(e) = res.compile() {
            println!("cargo:warning=winresource (setup): {e}");
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
