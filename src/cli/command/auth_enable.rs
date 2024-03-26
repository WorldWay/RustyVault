use clap::ArgMatches;
use sysexits::ExitCode;

use crate::{errors::RvError, EXIT_CODE_INSUFFICIENT_PARAMS, EXIT_CODE_OK};

pub fn main() -> Result<(), RvError> {
    println!("auth_enable: ok");
    Ok(())
}

#[inline]
pub fn execute(_matches: &ArgMatches) -> ExitCode {
    return (main().is_ok()).then(|| EXIT_CODE_OK).unwrap_or(EXIT_CODE_INSUFFICIENT_PARAMS);
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Command;

    #[test]
    fn test_execute() {
        let matches = Command::new("rvault")
            .subcommand(Command::new("auth").subcommand(Command::new("enable")))
            .get_matches_from(vec!["rvault", "auth", "enable"]);
        assert_eq!(crate::cli::run(&matches), EXIT_CODE_OK);
    }
}
