
use std::path::PathBuf;
use std::process::Command;
use std::io;


// Function to get the Git root directory
pub fn get_git_root() -> io::Result<PathBuf> {
    // Execute the git command to get the root directory
    let output = Command::new("git")
        .arg("rev-parse")
        .arg("--show-toplevel")
        .output()?;

    // Convert the stdout output to a String and trim it
    let git_root = String::from_utf8_lossy(&output.stdout).trim().to_string();

    // Convert the String to a PathBuf and return
    Ok(PathBuf::from(git_root))
}

pub fn generate_bindings(input_header: &str, output_file: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut builder = bindgen::Builder::default();
    
    let git_root: String = get_git_root()?.display().to_string();
    builder = builder.header(input_header);
    
    
    // let kernel_version = String::from_utf8(Command::new("sh").arg("-c").arg("uname -r").output().unwrap().stdout).unwrap();
    // let kernel_sources = format!("/usr/src/linux-headers-{}", kernel_version);
    let kernel_sources = format!("{}/linux", git_root);

    let bindings = builder.clang_args(&[
            // "-I/usr/include",      
            // format!("-I{}/arch/x86/include", kernel_sources).as_str(),
            // format!("-I{}/arch/asm-generic", kernel_sources).as_str(),
            // format!("-I{}/include", kernel_sources).as_str(),
            // format!("-I{}/arch/x86/include/uapi", kernel_sources).as_str(),
            "-D__KERNEL__",          
            "-D__LINUX_SPINLOCK_H",
            "-D_LINUX_JIFFIES_H",
            "-DMODULE",                    // Some headers expect this
            "-D__GENERATING_BINDINGS__", // Get rid of asmlinkage attribute
            // "-U__i386__",                 
            // "-Ux86_64",                   
            // "-D__x86_64__",    
            "-DCONFIG_64BIT",       
            "-D__ASM_SYSREG_H__",
            "--target=x86_64-linux-gnu"
    ]).generate().expect("Unable to generate bindings");
    
    // Generate bindings
    bindings.write_to_file(output_file).expect("Couldn't write bindings!");

    Ok(())
}