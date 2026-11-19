//! When the application locks and unlocks, decided from what the system reports.

use std::time::Duration;

/// What decides whether the application can lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// The user asked to unlock before the application opens.
    pub require_unlock: bool,
    /// Lock after this much idle time; `None` never locks on idle.
    pub idle_limit: Option<Duration>,
    /// This system can verify the user.
    pub available: bool,
}

impl Config {
    fn enabled(&self) -> bool {
        self.require_unlock && self.available
    }
}

/// What the system reports at one moment; `None` means it could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sample {
    pub screen_locked: Option<bool>,
    pub idle: Option<Duration>,
}

/// Why the application locked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    Start,
    Computer,
    Idle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    Locked(Reason),
    Unlocked,
}

/// The lock of the application; it only decides, the caller reads the system and acts.
#[derive(Debug)]
pub struct Lock {
    config: Config,
    locked: bool,
    // After an unlock the screen and the idle time must be seen below their trigger
    // before they can lock again, so a state that persists does not relock at once.
    screen_seen_unlocked: bool,
    idle_seen_below_limit: bool,
}

impl Lock {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            locked: false,
            screen_seen_unlocked: true,
            idle_seen_below_limit: true,
        }
    }

    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// The application started; it locks when a saved sign-in exists.
    pub fn started(&mut self, signed_in: bool) -> Option<Change> {
        self.lock_if(signed_in, Reason::Start)
    }

    /// Takes a reading of the system; `signed_in` includes a saved sign-in being renewed.
    pub fn observe(&mut self, sample: Sample, signed_in: bool) -> Option<Change> {
        if sample.screen_locked == Some(false) {
            self.screen_seen_unlocked = true;
        }
        let idle_reached = match (sample.idle, self.config.idle_limit) {
            (Some(idle), Some(limit)) if idle < limit => {
                self.idle_seen_below_limit = true;
                false
            }
            (Some(_), Some(_)) => self.idle_seen_below_limit,
            _ => false,
        };
        let screen_locked = sample.screen_locked == Some(true) && self.screen_seen_unlocked;
        if screen_locked {
            self.lock_if(signed_in, Reason::Computer)
        } else if idle_reached {
            self.lock_if(signed_in, Reason::Idle)
        } else {
            None
        }
    }

    /// The user proved who they are; `sample` is the reading of the system at that moment, so a screen that is
    /// unlocked then, or an idle time below the limit, can lock again at once.
    pub fn unlocked(&mut self, sample: Sample) {
        self.locked = false;
        self.screen_seen_unlocked = sample.screen_locked != Some(true);
        self.idle_seen_below_limit = match (sample.idle, self.config.idle_limit) {
            (Some(idle), Some(limit)) => idle < limit,
            _ => true,
        };
    }

    /// Nothing personal is left once signed out.
    pub fn signed_out(&mut self) -> Option<Change> {
        self.unlock()
    }

    pub fn configure(&mut self, config: Config) -> Option<Change> {
        self.config = config;
        if config.enabled() {
            None
        } else {
            self.unlock()
        }
    }

    fn lock_if(&mut self, signed_in: bool, reason: Reason) -> Option<Change> {
        if self.locked || !signed_in || !self.config.enabled() {
            return None;
        }
        self.locked = true;
        Some(Change::Locked(reason))
    }

    fn unlock(&mut self) -> Option<Change> {
        if !self.locked {
            return None;
        }
        self.locked = false;
        Some(Change::Unlocked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMIT: Duration = Duration::from_secs(300);

    fn config() -> Config {
        Config {
            require_unlock: true,
            idle_limit: Some(LIMIT),
            available: true,
        }
    }

    fn sample(screen_locked: Option<bool>, idle: Option<u64>) -> Sample {
        Sample {
            screen_locked,
            idle: idle.map(Duration::from_secs),
        }
    }

    enum Step {
        Start(bool),
        Observe(Sample, bool),
        Unlocked(Sample),
        SignedOut,
        Configure(Config),
    }
    use Step::*;

    type Case = (&'static str, Config, Vec<(Step, Option<Change>)>);

    fn locked(reason: Reason) -> Option<Change> {
        Some(Change::Locked(reason))
    }

    #[test]
    fn transitions() {
        let off = Config {
            require_unlock: false,
            ..config()
        };
        let unavailable = Config {
            available: false,
            ..config()
        };
        let no_idle = Config {
            idle_limit: None,
            ..config()
        };
        let away = sample(Some(true), Some(900));
        let cases: Vec<Case> = vec![
            (
                "start with a saved sign-in",
                config(),
                vec![(Start(true), locked(Reason::Start))],
            ),
            (
                "start without a sign-in",
                config(),
                vec![(Start(false), None)],
            ),
            ("start with unlock off", off, vec![(Start(true), None)]),
            (
                "start with unlock unavailable",
                unavailable,
                vec![(Start(true), None)],
            ),
            (
                "screen locked",
                config(),
                vec![(
                    Observe(sample(Some(true), Some(0)), true),
                    locked(Reason::Computer),
                )],
            ),
            (
                "locked stays locked",
                config(),
                vec![
                    (
                        Observe(sample(Some(true), None), true),
                        locked(Reason::Computer),
                    ),
                    (Observe(away, true), None),
                    (Start(true), None),
                ],
            ),
            (
                "unreadable samples never lock",
                config(),
                vec![(Observe(sample(None, None), true), None)],
            ),
            (
                "idle below the limit",
                config(),
                vec![(Observe(sample(Some(false), Some(299)), true), None)],
            ),
            (
                "idle at the limit",
                config(),
                vec![(
                    Observe(sample(Some(false), Some(300)), true),
                    locked(Reason::Idle),
                )],
            ),
            (
                "idle limit off",
                no_idle,
                vec![(Observe(sample(Some(false), Some(86_400)), true), None)],
            ),
            (
                "unlock off never locks",
                off,
                vec![(Observe(away, true), None)],
            ),
            (
                "unavailable never locks",
                unavailable,
                vec![(Observe(away, true), None)],
            ),
            (
                "not signed in never locks",
                config(),
                vec![(Observe(away, false), None)],
            ),
            (
                "sign out unlocks",
                config(),
                vec![
                    (Start(true), locked(Reason::Start)),
                    (SignedOut, Some(Change::Unlocked)),
                    (SignedOut, None),
                ],
            ),
            (
                "configure off unlocks",
                config(),
                vec![
                    (Start(true), locked(Reason::Start)),
                    (Configure(off), Some(Change::Unlocked)),
                ],
            ),
            (
                "configure unavailable unlocks",
                config(),
                vec![
                    (Start(true), locked(Reason::Start)),
                    (Configure(unavailable), Some(Change::Unlocked)),
                ],
            ),
            (
                "configure while unlocked changes nothing",
                config(),
                vec![(Configure(off), None), (Configure(config()), None)],
            ),
            (
                "configure keeping unlock on keeps the lock",
                config(),
                vec![
                    (Start(true), locked(Reason::Start)),
                    (Configure(no_idle), None),
                ],
            ),
            (
                "still locked screen does not relock until seen unlocked",
                config(),
                vec![
                    (
                        Observe(sample(Some(true), Some(0)), true),
                        locked(Reason::Computer),
                    ),
                    (Unlocked(sample(Some(true), Some(0))), None),
                    (Observe(sample(Some(true), Some(0)), true), None),
                    (Observe(sample(None, Some(0)), true), None),
                    (Observe(sample(Some(false), Some(0)), true), None),
                    (
                        Observe(sample(Some(true), Some(0)), true),
                        locked(Reason::Computer),
                    ),
                ],
            ),
            (
                "a screen that is unlocked at the unlock locks again at once",
                config(),
                vec![
                    (
                        Observe(sample(Some(true), Some(0)), true),
                        locked(Reason::Computer),
                    ),
                    (Unlocked(sample(Some(false), Some(0))), None),
                    (
                        Observe(sample(Some(true), Some(0)), true),
                        locked(Reason::Computer),
                    ),
                ],
            ),
            (
                "idle below the limit at the unlock re-arms at once",
                config(),
                vec![
                    (
                        Observe(sample(Some(false), Some(400)), true),
                        locked(Reason::Idle),
                    ),
                    (Unlocked(sample(Some(false), Some(10))), None),
                    (
                        Observe(sample(Some(false), Some(300)), true),
                        locked(Reason::Idle),
                    ),
                ],
            ),
            (
                "idle does not relock until it dropped below the limit",
                config(),
                vec![
                    (
                        Observe(sample(Some(false), Some(400)), true),
                        locked(Reason::Idle),
                    ),
                    (Unlocked(sample(Some(false), Some(400))), None),
                    (Observe(sample(Some(false), Some(400)), true), None),
                    (Observe(sample(Some(false), None), true), None),
                    (Observe(sample(Some(false), Some(10)), true), None),
                    (
                        Observe(sample(Some(false), Some(300)), true),
                        locked(Reason::Idle),
                    ),
                ],
            ),
        ];

        for (name, config, steps) in cases {
            let mut lock = Lock::new(config);
            for (index, (step, expected)) in steps.into_iter().enumerate() {
                let change = match step {
                    Start(signed_in) => lock.started(signed_in),
                    Observe(sample, signed_in) => lock.observe(sample, signed_in),
                    Unlocked(sample) => {
                        lock.unlocked(sample);
                        None
                    }
                    SignedOut => lock.signed_out(),
                    Configure(config) => lock.configure(config),
                };
                assert_eq!(change, expected, "{name}, step {index}");
            }
        }
    }

    #[test]
    fn is_locked_follows_the_changes() {
        let mut lock = Lock::new(config());
        assert!(!lock.is_locked());
        lock.started(true);
        assert!(lock.is_locked());
        lock.unlocked(sample(Some(false), Some(0)));
        assert!(!lock.is_locked());
    }
}
