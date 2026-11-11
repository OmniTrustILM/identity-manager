#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Normal,
    SelfCheck,
}

impl Mode {
    /// Decides the mode from the arguments after the program name.
    pub fn from_args(args: impl IntoIterator<Item = String>) -> Mode {
        if args.into_iter().any(|arg| arg == "--self-check") {
            Mode::SelfCheck
        } else {
            Mode::Normal
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|arg| arg.to_string()).collect()
    }

    #[test]
    fn no_arguments_is_normal() {
        assert_eq!(Mode::from_args(args(&[])), Mode::Normal);
    }

    #[test]
    fn self_check_flag_is_self_check() {
        assert_eq!(Mode::from_args(args(&["--self-check"])), Mode::SelfCheck);
    }

    #[test]
    fn unknown_argument_is_normal() {
        assert_eq!(Mode::from_args(args(&["--unknown", "x"])), Mode::Normal);
    }
}
