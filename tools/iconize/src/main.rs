//! Rasteriza `assets/quarry.svg` em `assets/quarry.ico` (multi-resolução) e
//! `assets/quarry-256.png`. Puro Rust (resvg), sem ferramenta externa.
//!
//! Uso (a partir da raiz do repo):
//!   cargo run --manifest-path tools/iconize/Cargo.toml

use std::path::Path;

const SIZES: &[u32] = &[16, 24, 32, 48, 64, 128, 256];

fn main() {
    // Resolve a raiz do repo: dois níveis acima de tools/iconize.
    let manifest = env!("CARGO_MANIFEST_DIR");
    let root = Path::new(manifest)
        .ancestors()
        .nth(2)
        .expect("raiz do repo");
    let svg_path = root.join("assets/quarry.svg");
    let ico_path = root.join("assets/quarry.ico");
    let png_path = root.join("assets/quarry-256.png");

    let svg = std::fs::read(&svg_path).expect("ler assets/quarry.svg");
    let tree = usvg::Tree::from_data(&svg, &usvg::Options::default()).expect("parsear SVG");
    let base = tree.size();

    let mut icon_dir = ico::IconDir::new(ico::ResourceType::Icon);

    for &size in SIZES {
        let mut pixmap = tiny_skia::Pixmap::new(size, size).expect("pixmap");
        let scale = size as f32 / base.width().max(base.height());
        let transform = tiny_skia::Transform::from_scale(scale, scale);
        resvg::render(&tree, transform, &mut pixmap.as_mut());

        // PNG de 256 para docs / instalador
        if size == 256 {
            pixmap.save_png(&png_path).expect("salvar quarry-256.png");
        }

        let image = ico::IconImage::from_rgba_data(size, size, pixmap.data().to_vec());
        icon_dir.add_entry(ico::IconDirEntry::encode(&image).expect("encode ico"));
    }

    let file = std::fs::File::create(&ico_path).expect("criar quarry.ico");
    icon_dir.write(file).expect("escrever quarry.ico");

    println!(
        "ok: {} ({} resoluções) + {}",
        ico_path.display(),
        SIZES.len(),
        png_path.display()
    );
}
