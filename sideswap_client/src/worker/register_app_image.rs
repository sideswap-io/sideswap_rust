#[cfg(target_os = "linux")]
fn try_register_desktop_entry() -> Result<(), anyhow::Error> {
    use anyhow::Context;

    // 1. Resolve HOME
    let home = std::env::var("HOME").context("no HOME")?;
    let home_path = std::path::PathBuf::from(&home);

    // 2. Prepare paths
    let applications_dir = home_path.join(".local/share/applications");
    let icons_dir = home_path.join(".local/share/icons");

    if !applications_dir.exists() {
        std::fs::create_dir_all(&applications_dir).context("creating applications dir")?;
    }
    if !icons_dir.exists() {
        std::fs::create_dir_all(&icons_dir).context("creating icons dir")?;
    }

    // 3. Resolve Executable Path (AppImage vs Binary)
    let exec_path = std::env::var("APPIMAGE").unwrap_or_else(|_| {
        std::env::current_exe()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "sideswap".to_string())
    });

    // 4. Write Icon File
    let icon_path = icons_dir.join("sideswap.png");
    if !icon_path.exists() {
        const ICON_BYTES: &[u8] = include_bytes!("../../data/icon_linux.png");
        std::fs::write(&icon_path, ICON_BYTES).context("failed to write icon")?;
    }

    // 5. Construct Desktop File
    let desktop_content = format!(
        "[Desktop Entry]\n\
        Name=SideSwap\n\
        Comment=Privacy-focused Liquid Network Wallet\n\
        Exec={exec_path} %u\n\
        Icon=sideswap\n\
        Type=Application\n\
        Terminal=false\n\
        Categories=Finance;Network;\n\
        MimeType=x-scheme-handler/liquidconnect;\n\
        StartupWMClass=SideSwap\n"
    );

    let dest_path = applications_dir.join("sideswap.desktop");

    log::debug!("desktop file path: {dest_path:?}");

    let old_desktop_content = std::fs::read_to_string(&dest_path).ok().unwrap_or_default();

    if old_desktop_content != desktop_content {
        std::fs::write(&dest_path, desktop_content).context("failed to write desktop file")?;

        // 6. Refresh Database (Best Effort)
        let res = std::process::Command::new("update-desktop-database")
            .arg(&applications_dir)
            .status();
        if let Err(err) = res {
            log::debug!("update-desktop-database failed: {err}");
        }
    }

    Ok(())
}

/// Registers the current AppImage as a desktop application to handle URI schemes.
#[cfg(target_os = "linux")]
pub fn register_desktop_entry() {
    let res = try_register_desktop_entry();

    if let Err(err) = res {
        log::error!("registering the desktop file failed: {err}");
    }
}
