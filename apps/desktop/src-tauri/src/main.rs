// Auf Windows ohne Konsolenfenster: ein Writer, der im Hintergrund eine
// Konsole aufzieht, zeigt Pfade, die dort nichts zu suchen haben.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    ea_desktop::run();
}
