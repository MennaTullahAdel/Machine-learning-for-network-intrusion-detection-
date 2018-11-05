import csv
from collections import defaultdict

from tkinter import messagebox

columns = defaultdict(list) # each value in each column is appended to a list
def report(result):
    with open('feature.csv', newline='') as csvfile:
        reader = csv.DictReader(csvfile) # read rows into a dictionary format
        for row in reader: # read a row as {column1: value1, column2: value2,...}
            for (k,v) in row.items(): # go over each column name and value
                columns[k].append(v) # append the value into the appropriate list
                                     # based on column name k

    f = open('file.doc', "w")
    f.write("                             Detection Report                "+'\n\n\n')
    f.write("Source IP"+"     " +str(columns['Source IP'])+"\r\n\n")
    f.write("Destination IP"+"    "+str(columns['Destination IP'])+"\r\n\n")
    f.write("Flow Duration"+"   "+str(columns['Flow Duration'])+"\r\n\n")
    if(result==1):
        messagebox.showinfo("FLOW result", "Flow is clean")
        f.write("Flow Result : Normal traffic" "\r\n\n")
    elif(result==0):
        messagebox.showinfo("FLOW result", "Flow contains malicious traffic  ")
        f.write("Flow Result : malicious traffic"  "\r\n\n")
    f.close()