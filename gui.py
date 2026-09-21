import customtkinter as ctk
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
from tkinter import messagebox

import threading
import socket
import time
import os

from scanner import (
    scan_target,
    save_txt_report,
    save_csv_report
)




ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")




class NetScanX(ctk.CTk):

    def __init__(self):

        super().__init__()

   

        self.title(
            "NetScanX - Network Port Scanner"
        )

        self.geometry(
            "1000x1000"
        )

        self.minsize(
            900,
            600
        )



        self.scan_thread = None

        self.stop_event = threading.Event()

        self.scan_results = []

        self.scan_start_time = None

        self.scan_duration = 0

        self.current_target = ""

        self.current_start_port = 0

        self.current_end_port = 0



        self.title_label = ctk.CTkLabel(
            self,
            text="NETSCANX",
            font=ctk.CTkFont(
                size=32,
                weight="bold"
            )
        )

        self.title_label.pack(
            pady=(20, 0)
        )

        self.subtitle_label = ctk.CTkLabel(
            self,
            text="Network Port Scanner",
            font=ctk.CTkFont(
                size=15
            )
        )

        self.subtitle_label.pack(
            pady=(0, 15)
        )


        self.input_frame = ctk.CTkFrame(
            self
        )

        self.input_frame.pack(
            padx=25,
            pady=10,
            fill="x"
        )



        self.target_label = ctk.CTkLabel(
            self.input_frame,
            text="Target:"
        )

        self.target_label.grid(
            row=0,
            column=0,
            padx=(20, 10),
            pady=15
        )

        self.target_entry = ctk.CTkEntry(
            self.input_frame,
            placeholder_text="127.0.0.1 or localhost",
            width=250
        )

        self.target_entry.grid(
            row=0,
            column=1,
            padx=10,
            pady=15
        )



        self.port_label = ctk.CTkLabel(
            self.input_frame,
            text="Port Range:"
        )

        self.port_label.grid(
            row=0,
            column=2,
            padx=(20, 10),
            pady=15
        )

        self.port_entry = ctk.CTkEntry(
            self.input_frame,
            placeholder_text="1-1000",
            width=180
        )

        self.port_entry.grid(
            row=0,
            column=3,
            padx=10,
            pady=15
        )



        self.error_label = ctk.CTkLabel(
            self,
            text="",
            text_color="#FF5555",
            font=ctk.CTkFont(
                size=13
            )
        )

        self.error_label.pack(
            pady=(0, 5)
        )



        self.button_frame = ctk.CTkFrame(
            self,
            fg_color="transparent"
        )

        self.button_frame.pack(
            pady=5
        )


        self.start_button = ctk.CTkButton(
            self.button_frame,
            text="START SCAN",
            width=150,
            command=self.start_scan
        )

        self.start_button.grid(
            row=0,
            column=0,
            padx=5
        )



        self.stop_button = ctk.CTkButton(
            self.button_frame,
            text="STOP SCAN",
            width=150,
            fg_color="#C62828",
            hover_color="#8E1B1B",
            command=self.stop_scan,
            state="disabled"
        )

        self.stop_button.grid(
            row=0,
            column=1,
            padx=5
        )



        self.clear_button = ctk.CTkButton(
            self.button_frame,
            text="CLEAR RESULTS",
            width=150,
            fg_color="#555555",
            hover_color="#333333",
            command=self.clear_results
        )

        self.clear_button.grid(
            row=0,
            column=2,
            padx=5
        )



        self.status_label = ctk.CTkLabel(
            self,
            text="Ready",
            font=ctk.CTkFont(
                size=14,
                weight="bold"
            )
        )

        self.status_label.pack(
            pady=(10, 5)
        )


        self.progress_bar = ctk.CTkProgressBar(
            self,
            width=700,
            height=18
        )

        self.progress_bar.pack(
            pady=5
        )

        self.progress_bar.set(0)

        self.progress_label = ctk.CTkLabel(
            self,
            text="0%"
        )

        self.progress_label.pack(
            pady=(0, 10)
        )



        self.results_frame = ctk.CTkFrame(
            self
        )

        self.results_frame.pack(
            padx=25,
            pady=5,
            fill="both",
            expand=True
        )

        self.results_title = ctk.CTkLabel(
            self.results_frame,
            text="SCAN RESULTS",
            font=ctk.CTkFont(
                size=17,
                weight="bold"
            )
        )

        self.results_title.pack(
            pady=10
        )



        style = ttk.Style()

        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(
            "Treeview",
            rowheight=30,
            font=("Arial", 12)
        )

        style.configure(
            "Treeview.Heading",
            font=("Arial", 12, "bold")
        )



        self.table_frame = ctk.CTkFrame(
            self.results_frame,
            fg_color="transparent"
        )

        self.table_frame.pack(
            fill="both",
            expand=True,
            padx=15,
            pady=5
        )

        columns = (
            "port",
            "service",
            "status"
        )

        self.results_table = ttk.Treeview(
            self.table_frame,
            columns=columns,
            show="headings"
        )

        self.results_table.heading(
            "port",
            text="PORT"
        )

        self.results_table.heading(
            "service",
            text="SERVICE"
        )

        self.results_table.heading(
            "status",
            text="STATUS"
        )

        self.results_table.column(
            "port",
            width=150,
            anchor="center"
        )

        self.results_table.column(
            "service",
            width=300,
            anchor="center"
        )

        self.results_table.column(
            "status",
            width=200,
            anchor="center"
        )

        self.results_table.pack(
            side="left",
            fill="both",
            expand=True
        )


        self.scrollbar = ttk.Scrollbar(
            self.table_frame,
            orient="vertical",
            command=self.results_table.yview
        )

        self.results_table.configure(
            yscrollcommand=self.scrollbar.set
        )

        self.scrollbar.pack(
            side="right",
            fill="y"
        )



        self.stats_label = ctk.CTkLabel(
            self,
            text="Open Ports: 0    |    Ports Scanned: 0    |    Time: 0.00s",
            font=ctk.CTkFont(
                size=13
            )
        )

        self.stats_label.pack(
            pady=8
        )



        self.report_frame = ctk.CTkFrame(
            self,
            fg_color="transparent"
        )

        self.report_frame.pack(
            pady=(0, 15)
        )

        self.txt_button = ctk.CTkButton(
            self.report_frame,
            text="SAVE TXT REPORT",
            width=180,
            command=self.save_txt
        )

        self.txt_button.grid(
            row=0,
            column=0,
            padx=5
        )

        self.csv_button = ctk.CTkButton(
            self.report_frame,
            text="SAVE CSV REPORT",
            width=180,
            command=self.save_csv
        )

        self.csv_button.grid(
            row=0,
            column=1,
            padx=5
        )




    def validate_input(self):

        self.error_label.configure(
            text=""
        )

        target = self.target_entry.get().strip()

        port_range = self.port_entry.get().strip()

    

        if not target:

            self.error_label.configure(
                text="❌ Target is required."
            )

            return None

       

        if not port_range:

            self.error_label.configure(
                text="❌ Port range is required."
            )

            return None

 

        if "-" not in port_range:

            self.error_label.configure(
                text="❌ Invalid port format. Use: 1-1000"
            )

            return None

        parts = port_range.split("-")

        if len(parts) != 2:

            self.error_label.configure(
                text="❌ Invalid port format. Use: 1-1000"
            )

            return None

        try:

            start_port = int(
                parts[0]
            )

            end_port = int(
                parts[1]
            )

        except ValueError:

            self.error_label.configure(
                text="❌ Ports must contain numbers only."
            )

            return None



        if not (
            1 <= start_port <= 65535
            and
            1 <= end_port <= 65535
        ):

            self.error_label.configure(
                text="❌ Ports must be between 1 and 65535."
            )

            return None



        if start_port > end_port:

            self.error_label.configure(
                text="❌ Starting port must be smaller than ending port."
            )

            return None



        try:

            socket.gethostbyname(
                target
            )

        except socket.gaierror:

            self.error_label.configure(
                text="❌ Invalid IP address or hostname."
            )

            return None

        return (
            target,
            start_port,
            end_port
        )




    def start_scan(self):

        validation = self.validate_input()

        if validation is None:
            return

        target, start_port, end_port = validation



        if (
            self.scan_thread
            and
            self.scan_thread.is_alive()
        ):

            return

  

        self.current_target = target

        self.current_start_port = start_port

        self.current_end_port = end_port



        self.stop_event.clear()



        self.clear_table()



        self.progress_bar.set(0)

        self.progress_label.configure(
            text="0%"
        )

        self.status_label.configure(
            text="Scanning..."
        )

        self.stats_label.configure(
            text="Open Ports: 0    |    Ports Scanned: 0    |    Time: 0.00s"
        )



        self.start_button.configure(
            state="disabled"
        )

        self.stop_button.configure(
            state="normal"
        )



        self.scan_start_time = time.perf_counter()



        self.scan_thread = threading.Thread(
            target=self.run_scan,
            args=(
                target,
                start_port,
                end_port
            ),
            daemon=True
        )

        self.scan_thread.start()



    def run_scan(
        self,
        target,
        start_port,
        end_port
    ):

        try:

            results = scan_target(
                target,
                start_port,
                end_port,
                progress_callback=self.update_progress,
                stop_event=self.stop_event
            )

            duration = (
                time.perf_counter()
                -
                self.scan_start_time
            )

            self.scan_duration = duration



            self.after(
                0,
                self.scan_finished,
                results,
                duration
            )

        except Exception as error:

            self.after(
                0,
                self.scan_error,
                str(error)
            )




    def update_progress(
        self,
        progress
    ):

        self.after(
            0,
            self._update_progress_ui,
            progress
        )


    def _update_progress_ui(
        self,
        progress
    ):

        self.progress_bar.set(
            progress / 100
        )

        self.progress_label.configure(
            text=f"{progress}%"
        )



    def scan_finished(
        self,
        results,
        duration
    ):

        self.scan_results = results



        self.display_results(
            results
        )

        total_ports = (
            self.current_end_port
            -
            self.current_start_port
            +
            1
        )



        if self.stop_event.is_set():

            self.status_label.configure(
                text="Scan stopped."
            )

        else:

            self.progress_bar.set(1)

            self.progress_label.configure(
                text="100%"
            )

            self.status_label.configure(
                text="Scan completed."
            )



        self.stats_label.configure(
            text=(
                f"Open Ports: {len(results)}"
                f"    |    "
                f"Ports Scanned: {total_ports}"
                f"    |    "
                f"Time: {duration:.2f}s"
            )
        )



        self.start_button.configure(
            state="normal"
        )

        self.stop_button.configure(
            state="disabled"
        )




    def display_results(
        self,
        results
    ):

        self.clear_table()

        for item in results:

            self.results_table.insert(
                "",
                "end",
                values=(
                    item["port"],
                    item["service"],
                    item["status"]
                )
            )




    def clear_table(self):

        for item in self.results_table.get_children():

            self.results_table.delete(
                item
            )




    def stop_scan(self):

        if (
            not self.scan_thread
            or
            not self.scan_thread.is_alive()
        ):

            return

        self.stop_event.set()

        self.status_label.configure(
            text="Stopping scan..."
        )

        self.stop_button.configure(
            state="disabled"
        )




    def clear_results(self):

      

        if (
            self.scan_thread
            and
            self.scan_thread.is_alive()
        ):

            messagebox.showwarning(
                "Scan Running",
                "Please stop the scan before clearing the results."
            )

            return

        self.clear_table()

        self.scan_results = []

        self.progress_bar.set(0)

        self.progress_label.configure(
            text="0%"
        )

        self.status_label.configure(
            text="Ready"
        )

        self.stats_label.configure(
            text="Open Ports: 0    |    Ports Scanned: 0    |    Time: 0.00s"
        )

        self.error_label.configure(
            text=""
        )




    def save_txt(self):

        if not self.scan_results:

            messagebox.showwarning(
                "No Results",
                "There are no scan results to save."
            )

            return

        filename = filedialog.asksaveasfilename(
            title="Save TXT Report",
            defaultextension=".txt",
            filetypes=[
                (
                    "Text Files",
                    "*.txt"
                )
            ],
            initialfile="netscanx_report.txt"
        )

        if not filename:
            return

        try:

            save_txt_report(
                filename,
                self.current_target,
                self.current_start_port,
                self.current_end_port,
                self.scan_results,
                self.scan_duration
            )

            messagebox.showinfo(
                "Report Saved",
                f"TXT report saved successfully.\n\n{filename}"
            )

        except Exception as error:

            messagebox.showerror(
                "Save Error",
                str(error)
            )




    def save_csv(self):

        if not self.scan_results:

            messagebox.showwarning(
                "No Results",
                "There are no scan results to save."
            )

            return

        filename = filedialog.asksaveasfilename(
            title="Save CSV Report",
            defaultextension=".csv",
            filetypes=[
                (
                    "CSV Files",
                    "*.csv"
                )
            ],
            initialfile="netscanx_report.csv"
        )

        if not filename:
            return

        try:

            save_csv_report(
                filename,
                self.current_target,
                self.current_start_port,
                self.current_end_port,
                self.scan_results
            )

            messagebox.showinfo(
                "Report Saved",
                f"CSV report saved successfully.\n\n{filename}"
            )

        except Exception as error:

            messagebox.showerror(
                "Save Error",
                str(error)
            )



if __name__ == "__main__":

    app = NetScanX()

    app.mainloop()
