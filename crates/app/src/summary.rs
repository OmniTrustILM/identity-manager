//! The tray summary window: where it goes, and showing and hiding it.
//!
//! Placement works in one unit throughout: logical points on macOS and Linux, physical pixels on Windows. Windows
//! reports one consistent physical desktop, while macOS and GTK scale each monitor's rectangle by its own scale
//! factor, so mixed-DPI monitors only line up in logical points. A monitor to the left of or above the primary
//! one has a negative origin.

use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use tauri::{
    AppHandle, Manager, Monitor, PhysicalRect, Rect, Runtime, WebviewWindow, Window, WindowEvent,
};

pub const LABEL: &str = "summary";

/// Gap between the summary and the work area's edge when no tray rectangle is known.
const CORNER_MARGIN: i32 = 12;

/// A rectangle in placement units.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Area {
    x: i32,
    y: i32,
    width: u32,
    height: u32,
}

impl Area {
    /// Whether the point is inside, the rectangle being half-open.
    fn contains(self, (x, y): (i32, i32)) -> bool {
        let (x, y) = (i64::from(x), i64::from(y));
        let (left, top) = (i64::from(self.x), i64::from(self.y));
        x >= left
            && y >= top
            && x < left + i64::from(self.width)
            && y < top + i64::from(self.height)
    }
}

/// How many placement units one logical point is on a monitor of scale factor `scale`.
fn units_per_logical(scale: f64) -> f64 {
    if cfg!(windows) { scale } else { 1.0 }
}

/// How many physical pixels one placement unit is on a monitor of scale factor `scale`.
fn pixels_per_unit(scale: f64) -> f64 {
    scale / units_per_logical(scale)
}

/// A physical rectangle in placement units, given the pixels per unit of the monitor that reported it.
fn in_units(rect: PhysicalRect<i32, u32>, pixels_per_unit: f64) -> Area {
    Area {
        x: (f64::from(rect.position.x) / pixels_per_unit).round() as i32,
        y: (f64::from(rect.position.y) / pixels_per_unit).round() as i32,
        width: (f64::from(rect.size.width) / pixels_per_unit).round() as u32,
        height: (f64::from(rect.size.height) / pixels_per_unit).round() as u32,
    }
}

/// A monitor's rectangles in placement units and its scale factor.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Screen {
    full: Area,
    work: Area,
    scale: f64,
}

impl Screen {
    fn new(full: PhysicalRect<i32, u32>, work: PhysicalRect<i32, u32>, scale: f64) -> Self {
        // Each monitor's own scale factor undoes the scaling the backend applied to its rectangles.
        let per_unit = pixels_per_unit(scale);
        Self {
            full: in_units(full, per_unit),
            work: in_units(work, per_unit),
            scale,
        }
    }

    fn of(monitor: &Monitor) -> Self {
        Self::new(
            PhysicalRect {
                position: *monitor.position(),
                size: *monitor.size(),
            },
            *monitor.work_area(),
            monitor.scale_factor(),
        )
    }
}

/// Where the top-left corner of the summary goes.
///
/// `icon` is the tray icon's rectangle, or `None` where the system reports none (Linux), which puts the summary at
/// the work area's top-right corner. Otherwise it sits beside, below or above the icon according to the bar's edge,
/// always inside `work_area`; a window larger than the work area is pinned to its top-left corner.
fn position(icon: Option<Area>, window: (u32, u32), work_area: Area) -> (i32, i32) {
    let (width, height) = (i64::from(window.0), i64::from(window.1));
    let left = i64::from(work_area.x);
    let top = i64::from(work_area.y);
    let right = left + i64::from(work_area.width);
    let bottom = top + i64::from(work_area.height);

    let (x, y) = match icon {
        None => (
            right - width - i64::from(CORNER_MARGIN),
            top + i64::from(CORNER_MARGIN),
        ),
        Some(icon) => {
            let icon_left = i64::from(icon.x);
            let icon_top = i64::from(icon.y);
            let icon_right = icon_left + i64::from(icon.width);
            let icon_bottom = icon_top + i64::from(icon.height);
            let centre_x = (icon_left + icon_right) / 2;
            let centre_y = (icon_top + icon_bottom) / 2;
            if centre_x < left {
                (icon_right, centre_y - height / 2)
            } else if centre_x >= right {
                (icon_left - width, centre_y - height / 2)
            } else if centre_y < (top + bottom) / 2 {
                (centre_x - width / 2, icon_bottom)
            } else {
                (centre_x - width / 2, icon_top - height)
            }
        }
    };

    (
        clamp(x, left, right - width) as i32,
        clamp(y, top, bottom - height) as i32,
    )
}

/// The summary's size in placement units on a monitor of scale factor `to`, given its physical size on one of scale
/// factor `from`. Moving to a monitor of another scale factor resizes the window.
fn placement_size(size: (u32, u32), from: f64, to: f64) -> (u32, u32) {
    let ratio = units_per_logical(to) / from;
    (
        (f64::from(size.0) * ratio).round() as u32,
        (f64::from(size.1) * ratio).round() as u32,
    )
}

/// How long a focus-loss hide still counts as the summary being visible at a tray press. On Windows the summary loses
/// focus just before the tray reports the press that dismissed it.
const DISMISS_WINDOW: Duration = Duration::from_millis(300);

/// A value recorded by one tray or window event and consumed by a later one.
pub struct Slot<T>(Mutex<Option<T>>);

impl<T> Default for Slot<T> {
    fn default() -> Self {
        Self(Mutex::new(None))
    }
}

/// Whether the summary was visible when the tray button went down.
pub type VisibleAtPress = Slot<bool>;

/// When the summary was last hidden because it lost focus.
pub type HiddenOnFocusLoss = Slot<Instant>;

impl<T> Slot<T> {
    fn set(&self, value: T) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = Some(value);
    }

    /// Returns the recorded value and clears it, so each value answers only one later event.
    fn take(&self) -> Option<T> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).take()
    }
}

/// Whether the summary counts as visible at a tray press: it is, or it was hidden on focus loss within
/// `DISMISS_WINDOW` before the press.
fn visible_at_press(visible: bool, hidden_ago: Option<Duration>) -> bool {
    visible || hidden_ago.is_some_and(|ago| ago < DISMISS_WINDOW)
}

/// Whether releasing the tray button opens the summary. Pressing the icon blurs a focused summary, which hides it
/// before the release, so the state at the press decides, however long the button is held.
pub fn opens_on_release(visible_at_press: Option<bool>, visible_now: bool) -> bool {
    visible_at_press.map_or(!visible_now, |visible| !visible)
}

/// Keeps `value` within `min..=max`, preferring `min` when the range is empty.
fn clamp(value: i64, min: i64, max: i64) -> i64 {
    value.min(max).max(min)
}

/// The tray icon's rectangle in physical pixels; tray-icon reports physical coordinates on every system.
pub fn physical(rect: Rect) -> PhysicalRect<i32, u32> {
    PhysicalRect {
        position: rect.position.to_physical(1.0),
        size: rect.size.to_physical(1.0),
    }
}

fn is_visible<R: Runtime>(window: &WebviewWindow<R>) -> bool {
    window.is_visible().unwrap_or(false)
}

/// Records whether the summary is visible as the tray button goes down.
pub fn press<R: Runtime>(app: &AppHandle<R>) {
    if let Some(window) = app.get_webview_window(LABEL) {
        let hidden_ago = app
            .state::<HiddenOnFocusLoss>()
            .take()
            .map(|at| at.elapsed());
        app.state::<VisibleAtPress>()
            .set(visible_at_press(is_visible(&window), hidden_ago));
    }
}

/// On the tray button's release, hides the summary if it was visible at the press; otherwise places it by the tray
/// icon, shows and focuses it. A focus loss during the click belongs to this click, so it is cleared here.
pub fn release<R: Runtime>(app: &AppHandle<R>, icon: Option<PhysicalRect<i32, u32>>) {
    let Some(window) = app.get_webview_window(LABEL) else {
        return;
    };
    app.state::<HiddenOnFocusLoss>().take();
    let at_press = app.state::<VisibleAtPress>().take();
    if opens_on_release(at_press, is_visible(&window)) {
        show_at(&window, icon);
    } else {
        let _ = window.hide();
    }
}

/// Shows the summary at the top-right corner of the work area, as it opens where no tray rectangle is known.
pub fn show_in_corner<R: Runtime>(app: &AppHandle<R>) {
    if let Some(window) = app.get_webview_window(LABEL) {
        show_at(&window, None);
    }
}

fn show_at<R: Runtime>(window: &WebviewWindow<R>, icon: Option<PhysicalRect<i32, u32>>) {
    match (
        locate(window, icon),
        window.outer_size(),
        window.scale_factor(),
    ) {
        (Some((screen, icon)), Ok(size), Ok(current)) => {
            let size = placement_size((size.width, size.height), current, screen.scale);
            place(window, position(icon, size, screen.work));
        }
        _ => log::warn!("no monitor found for the summary; showing it where it is"),
    }
    let _ = window.show();
    let _ = window.set_focus();
}

#[cfg(windows)]
fn place<R: Runtime>(window: &WebviewWindow<R>, (x, y): (i32, i32)) {
    let _ = window.set_position(tauri::PhysicalPosition::new(x, y));
}

// tao converts a physical position with the window's current scale factor, which is not the destination's.
#[cfg(not(windows))]
fn place<R: Runtime>(window: &WebviewWindow<R>, (x, y): (i32, i32)) {
    let _ = window.set_position(tauri::LogicalPosition::new(x, y));
}

/// The monitor holding the tray icon, or, without an icon, the cursor, or else the primary monitor; with the icon's
/// rectangle in placement units.
fn locate<R: Runtime>(
    window: &WebviewWindow<R>,
    icon: Option<PhysicalRect<i32, u32>>,
) -> Option<(Screen, Option<Area>)> {
    let screens: Vec<_> = window
        .available_monitors()
        .ok()?
        .iter()
        .map(Screen::of)
        .collect();
    let primary = window.primary_monitor().ok().flatten();
    let per_unit = primary
        .as_ref()
        .map_or(1.0, |m| pixels_per_unit(m.scale_factor()));
    let cursor = window.cursor_position().ok().map(|cursor| {
        (
            (cursor.x / per_unit).floor() as i32,
            (cursor.y / per_unit).floor() as i32,
        )
    });
    match icon {
        Some(icon) => {
            if let Some((index, icon)) = tray_monitor(icon, cursor, &screens) {
                return Some((screens[index], Some(icon)));
            }
        }
        None => {
            if let Some(index) = cursor.and_then(|point| monitor_at(point, &screens)) {
                return Some((screens[index], None));
            }
        }
    }
    Some((Screen::of(&primary?), None))
}

/// The monitor holding the tray icon and the icon's rectangle in placement units.
///
/// tray-icon scales the rectangle by the scale factor of the screen the icon is on, which it does not report, so the
/// rectangle cannot say which monitor that is. The cursor sits on the icon at a click, so its monitor is the icon's,
/// and that monitor's factor converts the rectangle. Without a cursor on any monitor, the monitor is the only one
/// whose own factor puts the icon's centre inside it; with none or several, there is no answer.
fn tray_monitor(
    icon: PhysicalRect<i32, u32>,
    cursor: Option<(i32, i32)>,
    screens: &[Screen],
) -> Option<(usize, Area)> {
    if let Some(index) = cursor.and_then(|point| monitor_at(point, screens)) {
        return Some((index, in_units(icon, pixels_per_unit(screens[index].scale))));
    }
    let mut holding = screens.iter().enumerate().filter_map(|(index, screen)| {
        let area = in_units(icon, pixels_per_unit(screen.scale));
        let centre = (
            area.x + i32::try_from(area.width / 2).unwrap_or(0),
            area.y + i32::try_from(area.height / 2).unwrap_or(0),
        );
        screen.full.contains(centre).then_some((index, area))
    });
    let only = holding.next()?;
    holding.next().is_none().then_some(only)
}

/// The index of the first monitor whose full rectangle holds `point`.
fn monitor_at(point: (i32, i32), screens: &[Screen]) -> Option<usize> {
    screens
        .iter()
        .position(|screen| screen.full.contains(point))
}

/// Hides the summary when it loses focus, and records when.
pub fn hide_on_focus_loss<R: Runtime>(window: &Window<R>, event: &WindowEvent) {
    if loses_focus(window.label(), event) {
        window.state::<HiddenOnFocusLoss>().set(Instant::now());
        let _ = window.hide();
    }
}

fn loses_focus(label: &str, event: &WindowEvent) -> bool {
    label == LABEL && matches!(event, WindowEvent::Focused(false))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tauri::test::{MockRuntime, mock_builder, mock_context, noop_assets};
    use tauri::{WebviewUrl, WebviewWindowBuilder};

    use tauri::{PhysicalPosition, PhysicalSize};

    fn area(x: i32, y: i32, width: u32, height: u32) -> Area {
        Area {
            x,
            y,
            width,
            height,
        }
    }

    fn physical_area(x: i32, y: i32, width: u32, height: u32) -> PhysicalRect<i32, u32> {
        PhysicalRect {
            position: PhysicalPosition::new(x, y),
            size: PhysicalSize::new(width, height),
        }
    }

    fn screen(full: Area, scale: f64) -> Screen {
        Screen {
            full,
            work: full,
            scale,
        }
    }

    const WINDOW: (u32, u32) = (340, 200);

    fn screens() -> [Screen; 3] {
        [
            screen(area(0, 0, 1920, 1080), 1.0),
            screen(area(-1280, 0, 1280, 1024), 1.0),
            screen(area(1920, 0, 2560, 1440), 2.0),
        ]
    }

    fn hit(x: i32, y: i32) -> Option<usize> {
        monitor_at((x, y), &screens())
    }

    #[test]
    fn a_point_on_the_primary_monitor_finds_it() {
        assert_eq!(hit(960, 540), Some(0));
    }

    #[test]
    fn a_point_on_a_monitor_with_a_negative_origin_finds_it() {
        assert_eq!(hit(-640, 512), Some(1));
    }

    #[test]
    fn a_point_on_a_doubled_monitor_to_the_right_finds_it() {
        assert_eq!(hit(2800, 100), Some(2));
    }

    #[test]
    fn a_point_on_a_shared_edge_belongs_to_the_monitor_it_starts() {
        assert_eq!(hit(1920, 0), Some(2));
        assert_eq!(hit(1919, 0), Some(0));
        assert_eq!(hit(0, 0), Some(0));
        assert_eq!(hit(-1, 0), Some(1));
    }

    #[test]
    fn a_point_outside_every_monitor_finds_none() {
        assert_eq!(hit(0, 1080), None);
        assert_eq!(hit(4480, 100), None);
        assert_eq!(hit(-1281, 0), None);
    }

    #[test]
    fn a_backend_rectangle_scaled_by_its_own_factor_returns_to_units() {
        // Adjacent 1920-wide displays at 2x and 1x: the backend reports 0..3840 and 1920..3840.
        let doubled = in_units(physical_area(0, 0, 3840, 2160), 2.0);
        let single = in_units(physical_area(1920, 0, 1920, 1080), 1.0);
        assert_eq!(doubled, area(0, 0, 1920, 1080));
        assert_eq!(single, area(1920, 0, 1920, 1080));
        let screens = [screen(doubled, 2.0), screen(single, 1.0)];
        assert_eq!(monitor_at((2500, 500), &screens), Some(1));
        assert_eq!(monitor_at((1000, 500), &screens), Some(0));
    }

    #[test]
    fn a_negative_origin_converts_with_the_monitors_own_factor() {
        let left = in_units(physical_area(-2560, -200, 2560, 1440), 2.0);
        assert_eq!(left, area(-1280, -100, 1280, 720));
    }

    #[cfg(not(windows))]
    #[test]
    fn a_screen_holds_logical_rectangles() {
        let screen = Screen::new(
            physical_area(0, 0, 3840, 2160),
            physical_area(0, 48, 3840, 2112),
            2.0,
        );
        assert_eq!(screen.full, area(0, 0, 1920, 1080));
        assert_eq!(screen.work, area(0, 24, 1920, 1056));
    }

    #[cfg(windows)]
    #[test]
    fn a_screen_holds_physical_rectangles() {
        let screen = Screen::new(
            physical_area(0, 0, 3840, 2160),
            physical_area(0, 48, 3840, 2112),
            2.0,
        );
        assert_eq!(screen.full, area(0, 0, 3840, 2160));
        assert_eq!(screen.work, area(0, 48, 3840, 2112));
    }

    #[cfg(not(windows))]
    #[test]
    fn the_tray_rectangle_is_logical_on_the_monitor_it_was_scaled_for() {
        // An icon at logical 3000 on the 2x monitor is reported at 6000 physical pixels.
        let found = tray_monitor(physical_area(6000, 0, 48, 48), Some((3000, 10)), &screens());
        assert_eq!(found, Some((2, area(3000, 0, 24, 24))));
        // On a 1x monitor the reported rectangle is already logical.
        let found = tray_monitor(physical_area(1500, 0, 24, 24), Some((1500, 10)), &screens());
        assert_eq!(found, Some((0, area(1500, 0, 24, 24))));
    }

    #[cfg(windows)]
    #[test]
    fn the_tray_rectangle_stays_physical() {
        let found = tray_monitor(physical_area(2100, 0, 48, 48), Some((2110, 10)), &screens());
        assert_eq!(found, Some((2, area(2100, 0, 48, 48))));
    }

    #[cfg(not(windows))]
    #[test]
    fn a_1x_monitor_right_of_a_2x_primary_gets_its_icon_converted_with_1x() {
        // The icon at logical 3700 is reported at 3700 physical; the primary's 2x would misread it as 1850.
        let screens = [
            screen(area(0, 0, 1920, 1080), 2.0),
            screen(area(1920, 0, 1920, 1080), 1.0),
        ];
        let found = tray_monitor(physical_area(3700, 0, 24, 24), Some((3710, 10)), &screens);
        assert_eq!(found, Some((1, area(3700, 0, 24, 24))));
    }

    #[cfg(not(windows))]
    #[test]
    fn a_2x_monitor_right_of_a_1x_primary_gets_its_icon_converted_with_2x() {
        let screens = [
            screen(area(0, 0, 1920, 1080), 1.0),
            screen(area(1920, 0, 1920, 1080), 2.0),
        ];
        let found = tray_monitor(physical_area(7400, 0, 48, 48), Some((3710, 10)), &screens);
        assert_eq!(found, Some((1, area(3700, 0, 24, 24))));
    }

    #[cfg(not(windows))]
    #[test]
    fn without_a_cursor_on_a_monitor_the_one_matching_monitor_is_used() {
        let found = tray_monitor(physical_area(6000, 0, 48, 48), None, &screens());
        assert_eq!(found, Some((2, area(3000, 0, 24, 24))));
        let found = tray_monitor(
            physical_area(6000, 0, 48, 48),
            Some((99_999, 0)),
            &screens(),
        );
        assert_eq!(found, Some((2, area(3000, 0, 24, 24))));
    }

    #[cfg(not(windows))]
    #[test]
    fn an_ambiguous_icon_without_a_cursor_on_a_monitor_finds_none() {
        let screens = [
            screen(area(0, 0, 1920, 1080), 2.0),
            screen(area(1920, 0, 1920, 1080), 1.0),
        ];
        assert_eq!(
            tray_monitor(physical_area(3700, 0, 24, 24), None, &screens),
            None
        );
    }

    #[test]
    fn an_icon_outside_every_monitor_finds_none() {
        assert_eq!(
            tray_monitor(physical_area(99_999, 0, 24, 24), None, &screens()),
            None
        );
    }

    fn at(icon: Option<Area>, work: Area) -> (i32, i32) {
        position(icon, WINDOW, work)
    }

    #[test]
    fn a_bar_at_the_top_puts_the_summary_below_the_icon_centred() {
        // macOS menu bar: the work area starts below the bar.
        let work = area(0, 24, 1920, 1056);
        assert_eq!(at(Some(area(1500, 0, 24, 24)), work), (1342, 24));
    }

    #[test]
    fn a_taskbar_at_the_top_puts_the_summary_below_the_icon() {
        let work = area(0, 48, 1920, 1032);
        assert_eq!(at(Some(area(1700, 8, 32, 32)), work), (1546, 48));
    }

    #[test]
    fn a_taskbar_at_the_bottom_puts_the_summary_above_the_icon() {
        let work = area(0, 0, 1920, 1032);
        assert_eq!(at(Some(area(1700, 1040, 32, 32)), work), (1546, 832));
    }

    #[test]
    fn a_bar_at_the_left_puts_the_summary_beside_the_icon() {
        let work = area(48, 0, 1872, 1080);
        assert_eq!(at(Some(area(8, 500, 32, 32)), work), (48, 416));
    }

    #[test]
    fn a_bar_at_the_right_puts_the_summary_beside_the_icon() {
        let work = area(0, 0, 1872, 1080);
        assert_eq!(at(Some(area(1880, 500, 32, 32)), work), (1532, 416));
    }

    #[test]
    fn an_icon_near_the_right_edge_keeps_the_summary_inside() {
        let work = area(0, 24, 1920, 1056);
        assert_eq!(at(Some(area(1890, 0, 24, 24)), work), (1580, 24));
    }

    #[test]
    fn an_icon_near_the_left_edge_keeps_the_summary_inside() {
        let work = area(0, 0, 1920, 1032);
        assert_eq!(at(Some(area(4, 1040, 32, 32)), work), (0, 832));
    }

    #[test]
    fn a_side_bar_icon_near_the_bottom_keeps_the_summary_inside() {
        let work = area(48, 0, 1872, 1080);
        assert_eq!(at(Some(area(8, 1060, 32, 32)), work), (48, 880));
    }

    #[test]
    fn a_second_monitor_left_of_the_primary_has_a_negative_origin() {
        let work = area(-1920, 24, 1920, 1056);
        assert_eq!(at(Some(area(-300, 0, 24, 24)), work), (-458, 24));
        // Near its left edge the summary stays on that monitor, not on the primary.
        assert_eq!(at(Some(area(-1915, 0, 24, 24)), work), (-1920, 24));
    }

    #[test]
    fn a_second_monitor_above_the_primary_has_a_negative_origin() {
        let work = area(0, -1080, 1920, 1032);
        assert_eq!(at(Some(area(1700, -40, 32, 32)), work), (1546, -248));
    }

    #[test]
    fn moving_to_a_monitor_of_another_scale_factor_resizes_the_summary() {
        let physical = |from, to| placement_size((510, 240), from, to);
        // Logical points on macOS and Linux do not change with the monitor; physical pixels on Windows do.
        if cfg!(windows) {
            assert_eq!(physical(1.5, 0.75), (255, 120));
            assert_eq!(placement_size((340, 160), 1.0, 2.0), (680, 320));
        } else {
            assert_eq!(physical(1.5, 0.75), (340, 160));
            assert_eq!(placement_size((680, 320), 2.0, 1.0), (340, 160));
        }
        assert_eq!(placement_size((340, 160), 1.0, 1.0), (340, 160));
    }

    #[test]
    fn without_an_icon_the_summary_goes_to_the_top_right_corner() {
        let work = area(100, 30, 1920, 1050);
        assert_eq!(at(None, work), (1668, 42));
    }

    #[test]
    fn a_work_area_smaller_than_the_summary_pins_it_to_the_top_left() {
        let work = area(10, 20, 200, 100);
        assert_eq!(at(Some(area(100, 0, 20, 20)), work), (10, 20));
    }

    #[test]
    fn the_tray_rectangle_converts_to_physical_pixels() {
        let rect = Rect {
            position: PhysicalPosition::new(10, 20).into(),
            size: PhysicalSize::new(30, 40).into(),
        };
        let physical = physical(rect);
        assert_eq!((physical.position.x, physical.position.y), (10, 20));
        assert_eq!((physical.size.width, physical.size.height), (30, 40));
    }

    fn app_with_summary() -> tauri::App<MockRuntime> {
        let app = mock_builder()
            .manage(VisibleAtPress::default())
            .manage(HiddenOnFocusLoss::default())
            .build(mock_context(noop_assets()))
            .expect("the mock app builds");
        WebviewWindowBuilder::new(&app, LABEL, WebviewUrl::default())
            .visible(false)
            .build()
            .expect("the summary is created");
        app
    }

    // The mock runtime keeps no window state (every window reports visible), so these check that each path
    // runs to its end; where the windows go is covered by the `position` tests.
    #[test]
    fn releasing_runs_to_its_end_for_a_window_that_reports_visible() {
        let app = app_with_summary();
        release(app.handle(), Some(physical_area(100, 0, 24, 24)));
    }

    #[test]
    fn a_press_is_recorded_once_and_consumed_by_the_release() {
        let app = app_with_summary();
        assert_eq!(app.state::<VisibleAtPress>().take(), None);
        press(app.handle());
        assert_eq!(app.state::<VisibleAtPress>().take(), Some(true));
        assert_eq!(app.state::<VisibleAtPress>().take(), None);
        press(app.handle());
        release(app.handle(), None);
        assert_eq!(app.state::<VisibleAtPress>().take(), None);
    }

    #[test]
    fn showing_without_any_monitor_still_shows_the_summary() {
        let app = app_with_summary();
        let window = app.get_webview_window(LABEL).unwrap();
        show_at(&window, None);
        show_at(&window, Some(physical_area(100, 0, 24, 24)));
    }

    #[test]
    fn showing_in_the_corner_works_with_and_without_a_summary() {
        show_in_corner(app_with_summary().handle());
        let bare = mock_builder()
            .build(mock_context(noop_assets()))
            .expect("the mock app builds");
        show_in_corner(bare.handle());
    }

    #[test]
    fn a_summary_visible_at_the_press_stays_hidden_on_release() {
        // The press blurred and hid it, whatever the hold time.
        assert!(!opens_on_release(Some(true), false));
        assert!(!opens_on_release(Some(true), true));
    }

    #[test]
    fn a_summary_hidden_at_the_press_opens_on_release() {
        assert!(opens_on_release(Some(false), false));
        assert!(opens_on_release(Some(false), true));
    }

    #[test]
    fn a_focus_loss_hide_just_before_the_press_counts_as_visible() {
        assert!(visible_at_press(true, None));
        assert!(visible_at_press(false, Some(Duration::from_millis(50))));
        assert!(!visible_at_press(false, Some(DISMISS_WINDOW)));
        assert!(!visible_at_press(false, None));
    }

    #[test]
    fn a_press_right_after_a_focus_loss_hide_records_the_summary_as_visible() {
        let app = app_with_summary();
        let window = app.get_webview_window(LABEL).unwrap();
        hide_on_focus_loss(&window.as_ref().window(), &WindowEvent::Focused(false));
        press(app.handle());
        assert_eq!(app.state::<VisibleAtPress>().take(), Some(true));
        assert_eq!(app.state::<HiddenOnFocusLoss>().take(), None);
    }

    #[test]
    fn a_focus_loss_during_a_click_does_not_carry_into_the_next_click() {
        let app = app_with_summary();
        let window = app.get_webview_window(LABEL).unwrap();
        press(app.handle());
        hide_on_focus_loss(&window.as_ref().window(), &WindowEvent::Focused(false));
        release(app.handle(), None);
        assert_eq!(app.state::<HiddenOnFocusLoss>().take(), None);
    }

    #[test]
    fn without_a_recorded_press_the_current_visibility_decides() {
        assert!(opens_on_release(None, false));
        assert!(!opens_on_release(None, true));
    }

    #[test]
    fn releasing_without_a_summary_does_nothing() {
        let app = mock_builder()
            .manage(VisibleAtPress::default())
            .manage(HiddenOnFocusLoss::default())
            .build(mock_context(noop_assets()))
            .expect("the mock app builds");
        press(app.handle());
        release(app.handle(), None);
    }

    #[test]
    fn only_the_summary_losing_focus_hides_it() {
        assert!(loses_focus(LABEL, &WindowEvent::Focused(false)));
        assert!(!loses_focus(LABEL, &WindowEvent::Focused(true)));
        assert!(!loses_focus("main", &WindowEvent::Focused(false)));
    }

    #[test]
    fn the_focus_handler_accepts_any_window_event() {
        let app = app_with_summary();
        let window = app.get_webview_window(LABEL).unwrap();
        hide_on_focus_loss(&window.as_ref().window(), &WindowEvent::Focused(false));
    }
}
