use gtk4::prelude::*;
use gtk4::{Application, ApplicationWindow, Box, Button, Label, Orientation, ScrolledWindow, ListBox, Stack, StackSidebar, SearchEntry, Paned};
use libadwaita as adw;
use adw::prelude::*;

const APP_ID: &str = "com.brewhouse.BrewHouse";

fn main() {
    // Initialize libadwaita
    adw::init().expect("Failed to initialize libadwaita");

    let app = Application::builder()
        .application_id(APP_ID)
        .build();

    app.connect_activate(build_ui);
    app.run();
}

fn build_ui(app: &Application) {
    // Main window
    let window = ApplicationWindow::builder()
        .application(app)
        .title("BrewHouse")
        .default_width(1000)
        .default_height(700)
        .build();

    // Main horizontal box
    let main_box = Box::new(Orientation::Horizontal, 0);

    // Sidebar with navigation
    let sidebar = create_sidebar();
    
    // Stack for different views
    let stack = Stack::new();
    stack.add_titled(&create_installed_view(), Some("installed"), "Installed");
    stack.add_titled(&create_browse_view(), Some("browse"), "Browse");
    stack.add_titled(&create_updates_view(), Some("updates"), "Updates");
    
    // Connect sidebar to stack
    let stack_sidebar = StackSidebar::new();
    stack_sidebar.set_stack(&stack);
    stack_sidebar.set_width_request(200);

    main_box.append(&stack_sidebar);
    main_box.append(&stack);

    window.set_child(Some(&main_box));
    window.present();
}

fn create_sidebar() -> Box {
    let sidebar = Box::new(Orientation::Vertical, 0);
    sidebar.set_width_request(200);
    sidebar
}

fn create_installed_view() -> Box {
    let view = Box::new(Orientation::Vertical, 10);
    view.set_margin_start(10);
    view.set_margin_end(10);
    view.set_margin_top(10);
    view.set_margin_bottom(10);
    
    let label = Label::new(Some("Installed Packages"));
    view.append(&label);
    
    // TODO: Add list of installed packages
    let placeholder = Label::new(Some("Loading installed packages..."));
    view.append(&placeholder);
    
    view
}

fn create_browse_view() -> Box {
    let view = Box::new(Orientation::Vertical, 10);
    view.set_margin_start(10);
    view.set_margin_end(10);
    view.set_margin_top(10);
    view.set_margin_bottom(10);
    
    // Search bar at top
    let search_entry = SearchEntry::new();
    search_entry.set_placeholder_text(Some("Search packages..."));
    view.append(&search_entry);
    
    // Paned widget for split view: package list | details
    let paned = Paned::new(Orientation::Horizontal);
    paned.set_vexpand(true);
    paned.set_position(400);
    
    // Left side: Package list
    let list_scroll = ScrolledWindow::new();
    list_scroll.set_vexpand(true);
    let package_list = ListBox::new();
    list_scroll.set_child(Some(&package_list));
    
    // Right side: Package details
    let details_box = Box::new(Orientation::Vertical, 10);
    details_box.set_margin_start(10);
    details_box.set_margin_end(10);
    details_box.set_margin_top(10);
    let details_label = Label::new(Some("Select a package to view details"));
    details_box.append(&details_label);
    
    paned.set_start_child(Some(&list_scroll));
    paned.set_end_child(Some(&details_box));
    
    view.append(&paned);
    view
}

fn create_updates_view() -> Box {
    let view = Box::new(Orientation::Vertical, 10);
    view.set_margin_start(10);
    view.set_margin_end(10);
    view.set_margin_top(10);
    view.set_margin_bottom(10);
    
    let label = Label::new(Some("Available Updates"));
    view.append(&label);
    
    // TODO: Add list of packages with updates
    let placeholder = Label::new(Some("Checking for updates..."));
    view.append(&placeholder);
    
    view
}
