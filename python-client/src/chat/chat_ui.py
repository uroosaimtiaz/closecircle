
import os
import time
from threading import Thread

from prompt_toolkit import Application
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import Layout, HSplit
from prompt_toolkit.widgets import Frame, TextArea
from prompt_toolkit.widgets import Label


class ChatUI:
    def __init__(self, connection, peer_socket):
        self.connection = connection
        self.peer_socket = peer_socket

        # Message display area
        self.message_area = TextArea(
            text="Welcome to the chat!",
            style="bg:#073642 #eee8d5",  # Dark background with light text
            read_only=False,
            scrollbar=True,
            wrap_lines=True,
        )

        # User input area
        self.input_area = TextArea(
            height=3,
            prompt="Enter your message: ",
            style="bg:#002b36 #FFFFFF",  # Darker background with grey text
            multiline=True,
            wrap_lines=True,
        )

        self.toolbar = Label(
            text="Enter: Send message, Ctrl-F: Send file, Enter 'exit' to leave chat.",
            style="bg:#073642 #eee8d5",  # Dark background with light text
        )

        # Frame to make it look like a dialog box
        self.frame = Frame(self.message_area, title="Chat Box", style="class:frame")

        # Layout
        self.layout = Layout(
            container=HSplit([self.frame, self.input_area, self.toolbar]),
            focused_element=self.input_area,
        )

        # Key bindings
        self.bindings = KeyBindings()

        @self.bindings.add('enter')
        def _enter(event):
            # Process input when the Enter key is pressed
            input_text = self.input_area.text.strip()
            if input_text:
                if input_text == "exit":  # Exit command
                    self.connection.send_messages("exit1", self.peer_socket)
                else:
                    self.connection.send_messages(input_text, self.peer_socket)
                    self.update_chat(f"You: {input_text}")
                self.input_area.text = ''  # Clear input area after sending

        @self.bindings.add('c-f')
        def _send_file(event):
            # Process input when the Ctrl-F key is pressed
            file_path = self.input_area.text.strip()
            if file_path:
                try:
                    self.connection.send_file(file_path, self.peer_socket)
                    self.update_chat(f"You sent a file: {file_path}")
                except FileNotFoundError:
                    self.update_chat(f"File not found: {file_path}")
                self.input_area.text = ''  # Clear input area after sending

        @self.bindings.add('c-c')
        def _exit(event):
            # Exit on Ctrl-C
            self.application.exit()

        # Application
        self.application = Application(
            layout=self.layout,
            key_bindings=self.bindings,
            full_screen=True,
            mouse_support=True,
        )

    def update_chat(self, message):
        # Safely update the TextArea content from another thread or event
        
        def update_text(message):
            self.message_area.text += ("\n" + message) if self.message_area.text else message
            self.application.invalidate()  # Invalidate to redraw the interface

        self.application.loop.call_soon_threadsafe(lambda: update_text(message))

    def run_chat(self):
        os.system('clear')

        # Run the application in a separate thread
        app_thread = Thread(target=self.application.run, daemon=True)
        app_thread.start()

        # Wait a brief moment to ensure the application event loop is running
        time.sleep(1)  

        # Wait for the application thread to finish (which it won't until the application exits)
        app_thread.join()
        return True