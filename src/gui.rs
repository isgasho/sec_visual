//! This module is used for sharing a few items between the `all_widgets.rs`, `glutin_glium.rs` and
//! `glutin_gfx.rs` examples.
//!
//! The module contains:
//!
//! - `pub struct DemoApp` as a demonstration of some state we want to change.
//! - `pub fn gui` as a demonstration of all widgets, some of which mutate our `DemoApp`.
//! - `pub struct Ids` - a set of all `widget::Id`s used in the `gui` fn.
//!
//! By sharing these items between these examples, we can test and ensure that the different events
//! and drawing backends behave in the same manner.
#![allow(dead_code)]
//use conrod;
use std;
extern crate rand;

use conrod;
use conrod::backend::glium::glium;
use conrod::Labelable;
use conrod::Borderable;
use conrod::backend::glium::glium::Surface;
use conrod::{color, widget, Colorable, Positionable, Sizeable, Widget};
use gui;
use executor;

/// In most of the examples the `glutin` crate is used for providing the window context and
/// events while the `glium` crate is used for displaying `conrod::render::Primitives` to the
/// screen.
///
/// This `Iterator`-like type simplifies some of the boilerplate involved in setting up a
/// glutin+glium event loop that works efficiently with conrod.
pub struct EventLoop {
    ui_needs_update: bool,
    last_update: std::time::Instant,
}

impl EventLoop {
    pub fn new() -> Self {
        EventLoop {
            last_update: std::time::Instant::now(),
            ui_needs_update: true,
        }
    }

    /// Produce an iterator yielding all available events.
    pub fn next(
        &mut self,
        events_loop: &mut glium::glutin::EventsLoop,
    ) -> Vec<glium::glutin::Event> {
        // We don't want to loop any faster than 60 FPS, so wait until it has been at least 16ms
        // since the last yield.
        let last_update = self.last_update;
        let sixteen_ms = std::time::Duration::from_millis(20);
        let duration_since_last_update = std::time::Instant::now().duration_since(last_update);
        if duration_since_last_update < sixteen_ms {
            std::thread::sleep(sixteen_ms - duration_since_last_update);
        }

        // Collect all pending events.
        let mut events = Vec::new();
        events_loop.poll_events(|event| events.push(event));

        // If there are no events and the `Ui` does not need updating, wait for the next event.
        if events.is_empty() && !self.ui_needs_update {
            events_loop.run_forever(|event| {
                events.push(event);
                glium::glutin::ControlFlow::Break
            });
        }

        self.ui_needs_update = false;
        self.last_update = std::time::Instant::now();

        events
    }

    /// Notifies the event loop that the `Ui` requires another update whether or not there are any
    /// pending events.
    ///
    /// This is primarily used on the occasion that some part of the `Ui` is still animating and
    /// requires further updates to do so.
    pub fn needs_update(&mut self) {
        self.ui_needs_update = true;
    }
}

struct Fonts {
    regular: conrod::text::font::Id,
    mono: conrod::text::font::Id,
}

pub fn main(exp: &mut executor::Exploit) {
    const WIDTH: u32 = 1280;
    const HEIGHT: u32 = 800;

    // Build the window.
    let mut events_loop = glium::glutin::EventsLoop::new();
    let window = glium::glutin::WindowBuilder::new()
        .with_title("Software Vulnerability and Exploit Visualization")
        .with_dimensions(WIDTH, HEIGHT);
    let context = glium::glutin::ContextBuilder::new()
        .with_vsync(true)
        .with_multisampling(4);
    let display = glium::Display::new(window, context, &events_loop).unwrap();

    // Construct our `Ui`.
    let mut ui = conrod::UiBuilder::new([WIDTH as f64, HEIGHT as f64]).build();

    // A unique identifier for each widget.
    let ids = Ids::new(ui.widget_id_generator());

    // Add a `Font` to the `Ui`'s `font::Map` from file.
    let fonts_path: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/assets/fonts/");

    // Store our `font::Id`s in a struct for easy access in the `set_ui` function.
    let fonts = Fonts {
        regular: ui.fonts
            .insert_from_file(format!("{}{}", fonts_path, "NotoSans-Regular.ttf"))
            .unwrap(),
        mono: ui.fonts
            .insert_from_file(format!("{}{}", fonts_path, "Inconsolata-Regular.ttf"))
            .unwrap(),
    };

    // Specify the default font to use when none is specified by the widget.
    //
    // By default, the theme's font_id field is `None`. In this case, the first font that is found
    // within the `Ui`'s `font::Map` will be used.
    ui.theme.font_id = Some(fonts.regular);

    // A type used for converting `conrod::render::Primitives` into `Command`s that can be used
    // for drawing to the glium `Surface`.
    let mut renderer = conrod::backend::glium::Renderer::new(&display).unwrap();

    // The image map describing each of our widget->image mappings (in our case, none).
    let image_map = conrod::image::Map::<glium::texture::Texture2d>::new();

    // Poll events from the window.
    let mut event_loop = gui::EventLoop::new();
    'main: loop {
        // Handle all events.
        for event in event_loop.next(&mut events_loop) {
            // Use the `winit` backend feature to convert the winit event to a conrod one.
            if let Some(event) = conrod::backend::winit::convert_event(event.clone(), &display) {
                ui.handle_event(event);
            }

            match event {
                glium::glutin::Event::WindowEvent { event, .. } => match event {
                    // Break from the loop upon `Escape`.
                    glium::glutin::WindowEvent::Closed
                    | glium::glutin::WindowEvent::KeyboardInput {
                        input:
                            glium::glutin::KeyboardInput {
                                virtual_keycode: Some(glium::glutin::VirtualKeyCode::Escape),
                                ..
                            },
                        ..
                    } => break 'main,
                    _ => (),
                },
                _ => (),
            }
        }

        set_ui(&mut ui.set_widgets(), &ids, &fonts, exp);

        // Render the `Ui` and then display it on the screen.
        if let Some(primitives) = ui.draw_if_changed() {
            renderer.fill(&display, primitives, &image_map);
            let mut target = display.draw();
            target.clear_color(0.0, 0.0, 0.0, 1.0);
            renderer.draw(&display, &mut target, &image_map).unwrap();
            target.finish().unwrap();
        }
    }
}

// Generate a unique const `WidgetId` for each widget.
widget_ids!{
    struct Ids {
        master,
        header,
        body,
        footer,
        col_code,
        col_code_title,
        col_code_main,
        col_mem,
        col_mem_title,
        col_mem_main,
        col_stack,
        col_stack_title,
        col_stack_main,
        col_reg,
        col_reg_title,
        col_reg_top,
        col_reg_bottom,
        label_code,
        label_stack,
        label_mem,
        label_reg,
        list_code,
        list_mem,
        list_stack,
        list_reg,
        text_explain,
        btn_next,
        btn_run,
    }
}

fn set_ui(ui: &mut conrod::UiCell, ids: &Ids, fonts: &Fonts, exp: &mut executor::Exploit) {
    // Our `Canvas` tree, upon which we will place our text widgets.
    widget::Canvas::new()
        .flow_down(&[
            (
                ids.header, //header to hold buttons
                widget::Canvas::new().length(50.0).color(color::LIGHT_BLUE),
            ),
            (
                ids.body,
                widget::Canvas::new().flow_right(&[
                    (
                        ids.col_code, // the canvas to show the code
                        widget::Canvas::new().length_weight(52.0).flow_down(&[
                            (
                                ids.col_code_title,
                                widget::Canvas::new().length(36.0).color(color::BLUE),
                            ),
                            (ids.col_code_main, widget::Canvas::new().color(color::WHITE)),
                        ]),
                    ),
                    (
                        ids.col_mem,
                        widget::Canvas::new().length_weight(16.0).flow_down(&[
                            (
                                ids.col_mem_title,
                                widget::Canvas::new().length(36.0).color(color::BLUE),
                            ),
                            (ids.col_mem_main, widget::Canvas::new().color(color::WHITE)),
                        ]),
                    ),
                    (
                        ids.col_stack,
                        widget::Canvas::new().length_weight(16.0).flow_down(&[
                            (
                                ids.col_stack_title,
                                widget::Canvas::new().length(36.0).color(color::BLUE),
                            ),
                            (
                                ids.col_stack_main,
                                widget::Canvas::new().color(color::WHITE),
                            ),
                        ]),
                    ),
                    (
                        ids.col_reg,
                        widget::Canvas::new().length_weight(16.0).flow_down(&[
                            (
                                ids.col_reg_title,
                                widget::Canvas::new().length(36.0).color(color::BLUE),
                            ),
                            (
                                ids.col_reg_top,
                                widget::Canvas::new()
                                    .length_weight(50.0)
                                    .color(color::WHITE),
                            ),
                            (
                                ids.col_reg_bottom,
                                widget::Canvas::new()
                                    .length_weight(50.0)
                                    .color(color::LIGHT_YELLOW),
                            ),
                        ]),
                    ),
                ]),
            ),
        ])
        .set(ids.master, ui);

    // Creat buttons to control the execution
    let btn = widget::Button::new()
        .color(color::LIGHT_GREY)
        .w_h(50.0, 36.0);
    let btn_next = btn.clone().label("Next").middle_of(ids.header);
    let btn_run = btn.label("Run").right_from(ids.btn_next, 10.0);

    for _click in btn_next.set(ids.btn_next, ui) {
        println!("Next instruction");
    }

    for _click in btn_run.set(ids.btn_run, ui) {
        println!("Run until end");
    }

    set_panel(
        ui,
        ids.col_code_title,
        ids.label_code,
        "Code",
        ids.col_code_main,
        ids.list_code,
        &exp.ins,
        fonts,
        |i, ins| {
            (format!("{:<4}{}", i, ins.dis), color::LIGHT_GREEN)
        },
    );

    let mems = vec![
        Line::Mem(1023),
        Line::Mem(1024),
        Line::Mem(1025),
        Line::Mem(1026),
        Line::Mem(1027),
        Line::Mem(1028),
        Line::Mem(1029),
    ];

/*
    set_panel(
        ui,
        ids.col_mem_title,
        ids.label_mem,
        "Memory",
        ids.col_mem_main,
        ids.list_mem,
        &mems,
        fonts,
        |i, line| {
            if let &Line::Mem(c) = line {
                (format!("{:<4}| {:0>8x}", i, c), color::WHITE)
            } else {
                panic!("Expect mem");
            }
        },
    );

    set_panel(
        ui,
        ids.col_stack_title,
        ids.label_stack,
        "Stack",
        ids.col_stack_main,
        ids.list_stack,
        &mems,
        fonts,
        |i, line| {
            if let &Line::Mem(c) = line {
                (format!("{:<4}| {:0>8x}", 511 - i, c), color::GREY)
            } else {
                panic!("Expect mem");
            }
        },
    );

    let regs = vec![
        Line::Reg("EAX", 0),
        Line::Reg("EBX", 0),
        Line::Reg("ECX", 0),
        Line::Reg("EDX", 0),
        Line::Reg("ESI", 0),
        Line::Reg("EDI", 0),
        Line::Reg("EBP", 0),
        Line::Reg("ESP", 0),
    ];

    set_panel(
        ui,
        ids.col_reg_title,
        ids.label_reg,
        "Registers",
        ids.col_reg_top,
        ids.list_reg,
        &regs,
        fonts,
        |_i, line| {
            if let &Line::Reg(name, val) = line {
                (format!("{:<4}| {:0>8x}", name, val), color::WHITE)
            } else {
                panic!("Expect reg");
            }
        },
    );*/
}

enum Line {
    Code(String),
    Mem(i32),
    Reg(&'static str, i32),
}

// setup the panel
fn set_panel<T, F>(
    ui: &mut conrod::UiCell,
    canvas_title: widget::Id,
    id_title: widget::Id,
    title: &str,
    canvas_main: widget::Id,
    id_main: widget::Id,
    data: &Vec<T>,
    fonts: &Fonts,
    fmt: F,
) where
    F: Fn(usize, &T) -> (String, conrod::Color),
{
    widget::Text::new(title)
        .center_justify()
        .font_size(20)
        .middle_of(canvas_title)
        .color(color::WHITE)
        .set(id_title, ui);

    let (mut items, scrollbar) = widget::List::flow_down(data.len())
        .scrollbar_on_top()
        .item_size(22.0)
        .middle_of(canvas_main)
        .padded_wh_of(canvas_main, 2.0)
        .set(id_main, ui);

    while let Some(item) = items.next(ui) {
        let i = item.i;
        let (content, color) = fmt(i, &data[i]);
        item.set(
            widget::TextBox::new(&content)
                .font_id(fonts.mono)
                .font_size(16)
                .border(0.0)
                .color(color),
            ui,
        );
    }

    if let Some(sbar) = scrollbar {
        sbar.set(ui);
    }
}
