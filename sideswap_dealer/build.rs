fn main() {
    let git = vergen_gitcl::GitclBuilder::default()
        .sha(true)
        .build()
        .unwrap();
    vergen_gitcl::Emitter::default()
        .add_instructions(&git)
        .unwrap()
        .emit()
        .unwrap();
}
