//! Embeds the app icon and manifest (per-monitor DPI v2, asInvoker) into Windows builds.

fn main() {
    println!("cargo:rerun-if-changed=assets");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        embed_resource::compile("assets/gatewizz.rc", embed_resource::NONE)
            .manifest_required()
            .unwrap();
    }
}
