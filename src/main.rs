#[macro_use]
extern crate conrod;
mod gui;

fn main() {
    feature::main();
}

mod feature {
    use conrod;
    use conrod::backend::glium::glium;
    use conrod::Labelable;
    use conrod::Borderable;
    use conrod::backend::glium::glium::Surface;
    use gui;

    struct Fonts {
        regular: conrod::text::font::Id,
        mono: conrod::text::font::Id,
    }

    pub fn main() {
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
                if let Some(event) = conrod::backend::winit::convert_event(event.clone(), &display)
                {
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

            set_ui(ui.set_widgets(), &ids, &fonts);

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

    fn set_ui(ref mut ui: conrod::UiCell, ids: &Ids, fonts: &Fonts) {
        use conrod::{color, widget, Colorable, Positionable, Sizeable, Widget};

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
                                (
                                    ids.col_code_main,
                                    widget::Canvas::new().color(color::LIGHT_CHARCOAL),
                                ),
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
                                        .color(color::LIGHT_BLUE),
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

        fn title(txt: widget::Text, parent_id: widget::Id) -> widget::Text {
            txt.color(color::WHITE)
                .center_justify()
                .font_size(20)
                .middle_of(parent_id)
        };

        title(widget::Text::new("Code"), ids.col_code_title).set(ids.label_code, ui);
        title(widget::Text::new("Stack"), ids.col_stack_title).set(ids.label_stack, ui);
        title(widget::Text::new("Mem"), ids.col_mem_title).set(ids.label_mem, ui);
        title(widget::Text::new("Registers"), ids.col_reg_title).set(ids.label_reg, ui);

        let code_lines = [
            "if let Some(primitives) = ui.draw_if_changed() {".to_string(),
            "    renderer.fill(&display, primitives, &image_map);".to_string(),
            "    let mut target = display.draw();".to_string(),
            "    target.clear_color(0.0, 0.0, 0.0, 1.0);".to_string(),
            "    renderer.draw(&display, &mut target, &image_map).unwrap();".to_string(),
            "    target.finish().unwrap();".to_string(),
            "}".to_string(),
        ];

        // Create a list to show the code
        let (mut items, scrollbar) = widget::List::flow_down(code_lines.len())
            .scrollbar_on_top()
            .item_size(20.0)
            .middle_of(ids.col_code_main)
            .padded_wh_of(ids.col_code_main, 10.0)
            .set(ids.list_code, ui);

        while let Some(item) = items.next(ui) {
            let i = item.i;
            item.set(
                widget::Text::new(&code_lines[i])
                    .font_id(fonts.mono)
                    .font_size(16)
                    .color(color::WHITE),
                ui,
            );
        }

        if let Some(sbar) = scrollbar {
            sbar.set(ui);
        }

        let (mut items, scrollbar) = widget::List::flow_down(512)
            .scrollbar_on_top()
            .item_size(20.0)
            .middle_of(ids.col_mem_main)
            .padded_wh_of(ids.col_mem_main, 10.0)
            .set(ids.list_mem, ui);

        while let Some(item) = items.next(ui) {
            let i = item.i;
            item.set(
                widget::TextBox::new(&format!("{:<6} 0000_0000", i))
                    .font_id(fonts.mono)
                    .font_size(16)
                    .border(0.0)
                    .color(color::WHITE),
                ui,
            );
        }

        if let Some(sbar) = scrollbar {
            sbar.set(ui);
        }

        let (mut items, scrollbar) = widget::List::flow_down(512)
            .scrollbar_on_top()
            .item_size(20.0)
            .middle_of(ids.col_stack_main)
            .padded_wh_of(ids.col_stack_main, 10.0)
            .set(ids.list_stack, ui);

        while let Some(item) = items.next(ui) {
            let i = item.i;
            item.set(
                widget::TextBox::new(&format!("{:<6} 0000_0000", i))
                    .font_id(fonts.mono)
                    .font_size(16)
                    .border(0.0)
                    .color(color::WHITE),
                ui,
            );
        }

        if let Some(sbar) = scrollbar {
            sbar.set(ui);
        }
    }

}
