import tkinter as tk
import ctypes  # An included library with Python install.
import packetCapture
import featureExtract
import reporting
import classifier
import numpy as np
from tkinter import messagebox

LARGE_FONT = ('Comic Sans MS', 30)
f= np.empty([1,76])
class gui(tk.Frame):
    def __init__(self):
        self.root = tk.Tk()
        self.root.geometry("620x480")
        self.root.wm_title("Intrusion Detection System")
        self.root.iconbitmap('Hopstarter-Soft-Scraps-Document-Preview.ico')

        tk.Frame.config(self.root, background="orange")

        self.v = tk.IntVar()


        tk.Label(self.root, text="Network Intrusion Detection", background="black", font=LARGE_FONT,
                 anchor="w", fg="white").grid(row=1, column=3, columnspan=50, pady=15, padx=35)

        tk.Label(self.root, height=2, font=('Comic Sans MS', 15), text="file path", bg="orange",
                 anchor="w", fg="purple").grid(row=3, column=15)
        self.file_path = tk.Entry(self.root, width=30)
        self.file_path.grid(row=3, column=35)
        tk.Button(self.root, text='Intercept', height=1,width=10, font=('Comic Sans MS', 15), command=self.PacketCaptureCall).grid(row=20,
                                                                                                                  column=15)

        tk.Button(self.root, text="Reporting", height=1,width=10, font=('Comic Sans MS', 15), command=self.reportCall).grid(row=20,
                                                                                                                 column=35)
        tk.Label(self.root, background="orange", font=LARGE_FONT, height=1,
                 anchor="w", fg="white").grid(row=22, column=3, columnspan=50)

        tk.Button(self.root, text="analyse", height=1,width=10, font=('Comic Sans MS', 15), command=self.featureExtractionCall).grid(row=21,
                                                                                                                 column=25)
        self.root.mainloop()

    def PacketCaptureCall(self):
        var = packetCapture.cap()
        tk.Label(self.root, background="white", text=var, font=('Comic Sans MS', 15), bg="orange",
                 anchor="w", fg="black").grid(row=9, column=3, columnspan=50)
        messagebox.showinfo("Intercept","Done!!")

    def featureExtractionCall(self):
        f=featureExtract.FeatureExtraction('TCP.pcap','features.csv')
       # result = classifier.classify(f)
       # reporting.report(result)


        messagebox.showinfo("Analysis", "Done!!")
        #print(f.shape)
    def reportCall(self):
         #messagebox.showinfo("FLOW result", "Flow contains malicious traffic ")
         messagebox.showinfo("FLOW result", "Flow is clean traffic ")



Gui = gui()
