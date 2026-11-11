#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    identity_manager::run();
}
