#[macro_use] extern crate conrod;
mod gui;

fn main() {
    feature::main();
}


mod feature {
    use conrod;
    use conrod::backend::glium::glium;
    use conrod::Labelable;
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
       let noto_sans: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/assets/fonts/NotoSans/");


        // Store our `font::Id`s in a struct for easy access in the `set_ui` function.
        let fonts = Fonts {
            regular: ui.fonts.insert_from_file(format!("{}{}", noto_sans, "NotoSans-Regular.ttf")).unwrap(),
            mono: ui.fonts.insert_from_file(format!("{}{}", noto_sans, "NotoSans-Italic.ttf")).unwrap(),
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
                        glium::glutin::WindowEvent::Closed |
                        glium::glutin::WindowEvent::KeyboardInput {
                            input: glium::glutin::KeyboardInput {
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
            col_mem,
            col_stack,
            col_reg,
            label_code,
            label_stack,
            label_mem,
            label_reg,
            left_text,
            middle_text,
            right_text,
            float_reg,
            text_reg,
            btn_next,
            btn_run,
        }
    }

    fn set_ui(ref mut ui: conrod::UiCell, ids: &Ids, _fonts: &Fonts) {
        use conrod::{color, widget, Colorable, Positionable, Sizeable, Widget};

        // Our `Canvas` tree, upon which we will place our text widgets.
        widget::Canvas::new().flow_down(&[
            (ids.header, widget::Canvas::new().length(50.0).color(color::LIGHT_BLUE)),
            (ids.body, widget::Canvas::new().flow_right(&[
                (ids.col_code, widget::Canvas::new().length_weight(52.0).color(color::LIGHT_CHARCOAL)),
                (ids.col_mem, widget::Canvas::new().length_weight(16.0).color(color::WHITE)),
                (ids.col_stack, widget::Canvas::new().length_weight(16.0).color(color::WHITE)),
                (ids.col_reg, widget::Canvas::new().length_weight(16.0).color(color::WHITE)),
            ])),
        ]).set(ids.master, ui);


        // Creat buttons to control the execution
        let btn = widget::Button::new().color(color::LIGHT_GREY).w_h(50.0, 36.0);
        let btn_next = btn.clone().label("Next").middle_of(ids.header);
        let btn_run = btn.label("Run").right_from(ids.btn_next, 10.0);        

        for _click in btn_next.set(ids.btn_next, ui) {
            println!("Next instruction");
        }

        for _click in btn_run.set(ids.btn_run, ui) {
            println!("Run until end");
        }
        
        fn title (tb: widget::TextBox, parent_id: widget::Id) -> widget::TextBox { 
            tb.color(color::DARK_BLUE).center_justify().text_color(color::WHITE).
                font_size(20).w_of(parent_id).mid_top_of(parent_id)
        };

        title(widget::TextBox::new("Code"), ids.col_code).set(ids.label_code, ui);
        title(widget::TextBox::new("Stack"), ids.col_stack).set(ids.label_stack, ui);
        title(widget::TextBox::new("Mem"), ids.col_mem).set(ids.label_mem, ui);
        title(widget::TextBox::new("Registers"), ids.col_reg).set(ids.label_reg, ui);

        let _code_lines = [
            "if let Some(primitives) = ui.draw_if_changed() {".to_string(),
            "    renderer.fill(&display, primitives, &image_map);".to_string(),
            "    let mut target = display.draw();".to_string(),
            "    target.clear_color(0.0, 0.0, 0.0, 1.0);".to_string(),
            "    renderer.draw(&display, &mut target, &image_map).unwrap();".to_string(),
            "    target.finish().unwrap();".to_string(),
            "}".to_string(),
        ];
    }

}
