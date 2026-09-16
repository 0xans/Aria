pub mod sysinfo;

fn split_command_line(input: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let bytes = input.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        let c = bytes[i];
        if c == b'"' {
            in_quotes = !in_quotes;
        } else if c == b' ' && in_quotes {
            if !current.is_empty() {
                parts.push(core::mem::take(&mut current));
            }
        } else {
            current.push(c as char);
        }
        i + 1;
    }
    if !current.is_empty() {
        parts.push(current);
    }
    parts
}

pub unsafe fn execute_command(cmd_type: &str, args: &[String]) -> Result<String, String> {
    if cmd_type == "shell" {
        if args.is_empty() {
            return Err(String::from("shell command requires arguments"))
        }

        // Check for pipe: e.g `ps | grep meoware`
        let full_cmd = &args[0];
        if let Some(pipe_pos) = full_cmd.find(" | ") {
            let left = full_cmd[..pipe_pos].trim();
            let right = full_cmd[pipe_pos + 3..].trim();
            
            // Parse left side as the command
            let parts = split_command_line(left);
            if parts.is_empty() {
                return Err(String::from("empty command before pipe"))
            }
            let real_cmd = parts[0].as_str();
            let real_args: Vec<String> = parts[1..].to_vec();

            // Run the command 
            let result = dispatch(real_cmd, &real_args)?;

            // Parse right side as filter
            let filter_parts = split_command_line(right);
            if filter_parts.is_empty() {
                return Ok(result);
            }

            return match filter_parts[0].as_str() {
                "grep" | "find" | "filter" => {
                    if filter_parts.len() < 2 {
                        Err(String::from("Usage: <cmd> | grep <pattern>"))
                    } else {
                        let pattern = filter_parts[1].to_lowercase();
                        let filtered: String = result.lines().filter(|line| line.to_lowercase().contains(&pattern)).map(|line| {
                            let mut s = String::from(line);
                            s.push('\n');
                            s
                        }).collect();
                        if filtered.is_empty() {
                            Ok(String::from("No matches"))
                        } else {
                            Ok(filtered)
                        }
                    }
                }
                "head" => {
                    let n: usize = filter_parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(10);
                    Ok(result.lines().take(n).map(|l| {
                        let mut s = String::from(l);
                        s.push('\n');
                        s
                    }).collect())
                }
                "tail" => {
                    let n: usize = filter_parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(10);
                    let lines: Vec<&str> = result.lines().collect();
                    let start = lines.len().saturating_sub(n);
                    Ok(lines[start..].iter().map(|l| {
                        let mut s = String::from(*l);
                        s.push('\n');
                        s
                    }).collect())
                },
                "wc" => {
                    let count = result.lines().count();
                    Ok(alloc::format!("{} lines\n", count))
                },
                _ => Err(alloc::format!("Unkown filter: {}", filter_parts[0])),
            }
        }

        // No pipe just run the command
        let parts = split_command_line(full_cmd);
        if parts.is_empty() {
            return Err(String::from("empty command"));
        }
        let real_cmd = parts[0].as_str();
        let mut real_args: Vec<String> = parts[1..].to_vec();
        for extra in &args[1..] {
            real_args.push(extra.clone());
        }
        return dispatch(real_cmd, &real_args)
    }
    dispatch(cmd_type, args)
}

unsafe fn dispatch(cmd: &str, args: &[String]) -> Result<String, String> {
    match cmd {
        "pwd"                   => todo!(),
        "cd"                    => todo!(),
        "ls"                    => todo!(),
        "cat"                   => todo!(),
        "rm"                    => todo!(),
        "mkdir"                 => todo!(),
        "cp"                    => todo!(),
        "mv"                    => todo!(),
        "download"              => todo!(),
        "upload"                => todo!(),
        "ps"                    => todo!(),
        "kill"                  => todo!(),
        "whoami"                => sysinfo::cmd_whoami(),
        "sysinfo"               => sysinfo::cmd_sysinfo(),
        "env"                   => sysinfo::cmd_env(),
        "netstat"               => todo!(),
        "ifconfig" | "ipconfig" => todo!(),
        //...
        //...
        //...
        _ => Err(alloc::format!("Unknown command: {}", cmd)),
    }
}