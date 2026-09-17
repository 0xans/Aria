pub unsafe fn cmd_pwd() -> Result<String, String> {
    Ok(super::get_cwd())
}