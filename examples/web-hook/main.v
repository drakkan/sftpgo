module main
import time
import vweb
import os
import json

struct App {
    vweb.Context
}

struct Object {
    title       string
    description string
}

fn main() {
    vweb.run_at(new_app(), vweb.RunParams{
        port: 8081
    }) or { panic(err) }
}


struct FileEvent {
	user_name string
	event string
	status int
	status_string string
	error_string string
	virtual_path string
	virtual_dir_path string
	virtual_target_path string
	fs_path string
	fs_target_path string
	file_size i64
	elapsed i64
	protocol string
	ip string
	role string
	timestamp i64
	object_name string
	object_type string
	object_data string
}

fn new_app() &App {
    mut app := &App{}
    // makes all static files available.
    app.mount_static_folder_at(os.resource_abs_path('.'), '/')
    return app
}


['/do'; post]
pub fn (mut app App) ppost() vweb.Result {
	file_event := json.decode(FileEvent, app.req.data) or {
		eprintln("Failed to decode json, error: $err")
		app.set_status(400, '')
		return app.text("Failed to decode json, error: $err")
	}
	println("Event ($file_event.event) Recived")
	println("User: $file_event.user_name")
	println("File Name: $file_event.object_name")
	println("FS Path: $file_event.fs_path")
	println("File Size: $file_event.file_size")
	// this script can be executed sync or async, depend on the event and the `Execute sync` option.
	// For pre-* events this will block the file operation till it return with OK response given that `Execute sync` option is mandatory.
	println("do something first ..")
	time.sleep(2 * time.second) 
	println("done!")

    return app.text('Ok')
}
