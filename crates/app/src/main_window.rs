//! Keeps the main window inside the work area of its monitor on Windows, which, unlike macOS and the Linux
//! window managers, does not move a new window there itself.
//!
//! Sizes are in the placement units of `summary`.

#[cfg(windows)]
use tauri::{AppHandle, Manager, PhysicalRect, PhysicalSize, Runtime};

use crate::summary::{Area, clamp};
#[cfg(windows)]
use crate::summary::{Screen, in_units, pixels_per_unit, place, units_per_logical};

#[cfg(windows)]
const LABEL: &str = "main";

/// The window's outer rectangle once it lies inside `work`, or `None` when it already does.
///
/// A window larger than the work area shrinks to it, but never below `min`; one that still does not fit is pinned
/// to the work area's top-left corner.
fn fit(window: Area, min: (u32, u32), work: Area) -> Option<Area> {
    let width = window.width.min(work.width).max(min.0);
    let height = window.height.min(work.height).max(min.1);
    let x = clamp(
        i64::from(window.x),
        i64::from(work.x),
        i64::from(work.x) + i64::from(work.width) - i64::from(width),
    ) as i32;
    let y = clamp(
        i64::from(window.y),
        i64::from(work.y),
        i64::from(work.y) + i64::from(work.height) - i64::from(height),
    ) as i32;
    let fitted = Area {
        x,
        y,
        width,
        height,
    };
    (fitted != window).then_some(fitted)
}

#[cfg(windows)]
/// Shrinks and moves the main window into the work area of the monitor it is on, if it extends beyond it.
pub fn fit_to_work_area<R: Runtime>(app: &AppHandle<R>) {
    let Some(window) = app.get_webview_window(LABEL) else {
        return;
    };
    let Some(monitor) = window.current_monitor().ok().flatten() else {
        log::debug!("the main window is on no monitor; leaving it where it is");
        return;
    };
    if window.is_maximized().unwrap_or(false) {
        return;
    }
    let screen = Screen::of(&monitor);
    let per_unit = pixels_per_unit(screen.scale);
    let (Ok(position), Ok(outer), Ok(inner)) = (
        window.outer_position(),
        window.outer_size(),
        window.inner_size(),
    ) else {
        return;
    };
    let current = in_units(
        PhysicalRect {
            position,
            size: outer,
        },
        per_unit,
    );
    let inner = in_units(
        PhysicalRect {
            position,
            size: inner,
        },
        per_unit,
    );
    let frame = (
        current.width.saturating_sub(inner.width),
        current.height.saturating_sub(inner.height),
    );
    let min = min_size(app, screen.scale);
    let Some(fitted) = fit(current, (min.0 + frame.0, min.1 + frame.1), screen.work) else {
        return;
    };
    let content = (
        fitted.width.saturating_sub(frame.0),
        fitted.height.saturating_sub(frame.1),
    );
    let _ = window.set_size(PhysicalSize::new(content.0, content.1));
    place(&window, (fitted.x, fitted.y));
    log::info!(
        "main window resized to {}x{} to fit the work area",
        fitted.width,
        fitted.height
    );
}

#[cfg(windows)]
/// The configured minimum content size in placement units on a monitor of scale factor `scale`.
fn min_size<R: Runtime>(app: &AppHandle<R>, scale: f64) -> (u32, u32) {
    let config = app
        .config()
        .app
        .windows
        .iter()
        .find(|window| window.label == LABEL);
    let units =
        |logical: Option<f64>| (logical.unwrap_or(0.0) * units_per_logical(scale)).round() as u32;
    (
        units(config.and_then(|window| window.min_width)),
        units(config.and_then(|window| window.min_height)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const WORK: Area = Area {
        x: 0,
        y: 0,
        width: 1024,
        height: 720,
    };
    const MIN: (u32, u32) = (760, 480);

    fn window(x: i32, y: i32, width: u32, height: u32) -> Area {
        Area {
            x,
            y,
            width,
            height,
        }
    }

    #[test]
    fn a_window_that_fits_is_unchanged() {
        assert_eq!(fit(window(10, 20, 800, 600), MIN, WORK), None);
    }

    #[test]
    fn a_window_too_tall_shrinks_and_moves_up() {
        assert_eq!(
            fit(window(20, 30, 800, 760), MIN, WORK),
            Some(window(20, 0, 800, 720))
        );
    }

    #[test]
    fn a_window_too_wide_shrinks_and_moves_left() {
        assert_eq!(
            fit(window(40, 0, 1100, 600), MIN, WORK),
            Some(window(0, 0, 1024, 600))
        );
    }

    #[test]
    fn a_window_too_large_both_ways_takes_the_work_area() {
        assert_eq!(
            fit(window(50, 50, 1200, 900), MIN, WORK),
            Some(window(0, 0, 1024, 720))
        );
    }

    #[test]
    fn a_window_hanging_over_an_edge_moves_in_without_resizing() {
        assert_eq!(
            fit(window(500, 300, 800, 600), MIN, WORK),
            Some(window(224, 120, 800, 600))
        );
    }

    #[test]
    fn a_negative_origin_work_area_is_respected() {
        let work = window(-1280, -100, 1280, 700);
        assert_eq!(
            fit(window(-1300, -90, 1080, 720), MIN, work),
            Some(window(-1280, -100, 1080, 700))
        );
        assert_eq!(fit(window(-1200, -50, 1080, 600), MIN, work), None);
    }

    #[test]
    fn a_window_never_shrinks_below_the_minimum() {
        let work = window(0, 0, 700, 400);
        assert_eq!(
            fit(window(0, 0, 1080, 720), MIN, work),
            Some(window(0, 0, 760, 480))
        );
    }
}
