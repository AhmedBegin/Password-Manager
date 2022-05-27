import sqlite3, hashlib
from tkinter import *
from tkinter import simpledialog, messagebox
from functools import partial
import uuid
import pyperclip
import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from passgen import passGenerator
import tkinter.messagebox as mbox
from tkinter import ttk

backend = default_backend()
salt = b"2444"

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=backend
)

encryptionKey = 0


def encrypt(message: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(message)


def decrypt(message: bytes, token: bytes) -> bytes:
    return Fernet(token).decrypt(message)


# Database Code
with sqlite3.connect("main.db") as db:
    cursor = db.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS masterpassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL,
recoveryKey TEXT NOT NULL);
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS manager(
id INTEGER PRIMARY KEY,
website TEXT NOT NULL,
email TEXT NOT NULL,
password TEXT NOT NULL);
""")


# Popup

def popUp(text):
    answer = simpledialog.askstring("input string", text)

    return answer


def showPop(text):
    answer = simpledialog.askstring("input string", text, show="*")

    return answer


# Create Window
window = Tk()

window.title("Safe Password")
window.iconbitmap('Password key.ico')


def hashPassword(input):
    hash = hashlib.sha256(input)
    hash = hash.hexdigest()

    return hash


def RegisterScreen():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry('925x500+300+200')
    window.configure(bg='#fff')
    window.resizable(False, False)

    img = PhotoImage(file='login (1).png')
    Label(window, image=img, bg='white').place(x=50, y=50)

    frame = Frame(window, width=350, height=390, bg='#fff')
    frame.place(x=480, y=50)

    heading = Label(frame, text='Sign up', fg="#57a1f8", bg='white', font=('Microsoft Yahei UI Light', 23, 'bold'))
    heading.place(x=100, y=5)

    def on_enter(e):
        user.delete(0, 'end')

    def on_leave(e):
        if user.get() == '':
            user.insert(0, 'Choose a master Password')

    user = Entry(frame, width=25, fg='black', border=0, bg='white', font=('Microsoft Yahei UI Light', 11))
    user.place(x=30, y=80)
    user.insert(0, 'Choose a master Password')
    user.bind("<FocusIn>", on_enter)
    user.bind("<FocusOut>", on_leave)

    Frame(frame, width=295, height=2, bg='black').place(x=25, y=107)

    def on_enter1(e):
        Pass.delete(0, 'end')

    def on_leave1(e):
        if Pass.get() == '':
            Pass.insert(0, 'Re-write master Password')

    Pass = Entry(frame, width=25, fg='black', border=0, bg='white', font=('Microsoft Yahei UI Light', 11))
    Pass.place(x=30, y=150)
    Pass.insert(0, 'Re-write master Password')
    Pass.bind("<FocusIn>", on_enter1)
    Pass.bind("<FocusOut>", on_leave1)

    Frame(frame, width=295, height=2, bg='black').place(x=25, y=177)

    label = Label(frame, text="Recovery text will appear after signing up", fg='black', bg='white',
                  font=('Microsoft YaHei UI Light', 9))
    label.place(x=90, y=340)

    pic = PhotoImage(file='login (1).png')
    Label(window, image=pic).place(x=50, y=90)

    lbl2 = Label(window)
    lbl2.pack()
    lbl2.config(font=('Microsoft YaHei UI Light', 12, 'bold'), fg="Red", bg="white")
    lbl2.place(x=550, y=290)

    def SavePassword():
        if user.get() == Pass.get():
            sql = "DELETE FROM masterpassword WHERE id = 1"

            cursor.execute(sql)

            hashedPassword = hashPassword(Pass.get().encode("utf-8"))
            key = str(uuid.uuid4().hex)
            recoveryKey = hashPassword(key.encode('utf-8'))

            global encryptionKey
            encryptionKey = base64.urlsafe_b64encode(kdf.derive(user.get().encode()))

            insert_password = """INSERT INTO masterpassword(password, recoveryKey)
            VALUES(?, ?) """
            cursor.execute(insert_password, ((hashedPassword), (recoveryKey)))
            db.commit()

            recoveryScreen(key)
        else:
            lbl2.config(text="The passwords are not the same")

    special_ch = ['~', '`', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_', '+', '=', '{', '}', '[', ']',
                  '|', '\\', '/', ':', ';', '"', "'", '<', '>', ',', '.', '?']

    def validation():
        Checkuser = user.get()
        msg = ""

        if len(Checkuser) == 0:
            msg = 'Password can\'t be empty'
        else:
            try:
                if not any(ch in special_ch for ch in Checkuser):
                    msg = 'Atleast 1 special character required!'
                elif not any(ch.isupper() for ch in Checkuser):
                    msg = 'Atleast 1 uppercase character required!'
                elif not any(ch.islower() for ch in Checkuser):
                    msg = 'Atleast 1 lowercase character required!'
                elif not any(ch.isdigit() for ch in Checkuser):
                    msg = 'Atleast 1 number required!'
                elif len(Checkuser) < 8:
                    msg = 'Password must be minimum of 8 characters!'
                else:
                    SavePassword()
            except Exception as ep:
                messagebox.showerror('error', ep)
        messagebox.showinfo('message', msg)

    Button(frame, width=39, pady=7, text='Register', bg='#57a1f8', fg='white', border=0,
           command=validation).place(x=35, y=280)


def recoveryScreen(key):
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry('600x400')
    lbl = Label(window, text="Save the key that appear below to recover the account if you want ",bg='white',fg="purple", font=('Microsoft Yahei UI Light', 13,"bold"))
    lbl.config(anchor=CENTER)
    lbl.pack()

    lbl1 = Label(window, text=key)
    lbl1.config(anchor=CENTER)
    lbl1.pack()

    def copyKey():
        pyperclip.copy(lbl1.cget("text"))

    btn = Button(window, text="Copy the key", bg='Orange', fg='white', border=0, command=copyKey)
    btn.pack(pady=5)

    def done():
        passwordManager()

    btn = Button(window, text="Okay",bg='Green', fg='white', border=0, command=done)
    btn.pack(pady=5)


def resetScreen():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry('925x500+300+200')
    window.configure(bg='#fff')
    window.resizable(False, False)

    frame = Frame(window, width=350, height=390, bg='#fff')
    frame.place(x=480, y=50)

    heading = Label(frame, text='Recovery Page', fg="#57a1f8", bg='white', font=('Microsoft Yahei UI Light', 23, 'bold'))
    heading.place(x=100, y=5)

    def on_enter(e):
        txt.delete(0, 'end')

    def on_leave(e):
        if txt.get() == '':
            txt.insert(0, 'Put the Recovery key')

    txt = Entry(frame, width=25, fg='black', border=0, bg='white', font=('Microsoft Yahei UI Light', 11))
    txt.place(x=30, y=80)
    txt.insert(0, 'Put the Recovery key')
    txt.bind("<FocusIn>", on_enter)
    txt.bind("<FocusOut>", on_leave)

    Frame(frame, width=295, height=2, bg='black').place(x=25, y=107)

    lbl1 = Label(window)
    lbl1.config(anchor=CENTER)
    lbl1.pack()
    lbl1.place(x=550, y=230)

    def getRecoveryKey():
        recoveryKeyCheck = hashPassword(str(txt.get()).encode('utf-8'))
        cursor.execute('SELECT * FROM masterpassword WHERE id = 1 AND recoveryKey = ?', [(recoveryKeyCheck)])
        return cursor.fetchall()

    def checkRecoveryKey():
        checked = getRecoveryKey()

        if checked:
            RegisterScreen()
        else:
            txt.delete(0, 'end')
            lbl1.config(text='Wrong Recovery Key Entered')

    Button(frame, width=39, pady=7, text='Check key', bg='#57a1f8', fg='white', border=0,
           command=checkRecoveryKey).place(x=35, y=280)

    pic = PhotoImage(file='login (1).png')
    Label(window, image=pic).place(x=50, y=90)


def loginPage():
    window.geometry('925x500+300+200')
    window.configure(bg="#fff")
    window.resizable(False, False)

    frame = Frame(window, width=350, height=350, bg="white")
    frame.place(x=480, y=70)

    heading = Label(window, text='Sign Account', fg='#57a1f8', bg='white',
                    font=('Microsoft YaHei UI Light', 23, 'bold'))
    heading.place(x=500, y=10)

    def on_enter(e):
        Password.delete(0, 'end')

    def on_leave(e):
        name = Password.get()
        if name == '':
            Password.insert(0, 'Master Password')

    Password = Entry(frame, width=25, fg="black", border=0, bg="white", font=('Microsoft YaHei UI Light', 11))
    Password.place(x=30, y=80)
    Password.insert(0, 'Master Password')
    Password.bind('<FocusIn>', on_enter)
    Password.bind('<FocusOut>', on_leave)

    Frame(frame, width=295, height=2, bg="black").place(x=25, y=107)

    label = Label(frame, text="Forgot Password?", fg='black', bg="white", font=('Microsoft YaHei UI Light', 9))
    label.place(x=75, y=270)

    lbl1 = Label(window)
    lbl1.pack()
    lbl1.config(fg="red",bg="white", font=('Microsoft YaHei UI Light', 12))
    lbl1.place(x=550, y=230)

    pic = PhotoImage(file='login (2).png')
    Label(window, image=pic).place(x=50, y=90)

    def getMasterPassword():
        checkHashedPassword = hashPassword(Password.get().encode("utf-8"))
        global encryptionKey
        encryptionKey = base64.urlsafe_b64encode(kdf.derive(Password.get().encode()))
        cursor.execute("SELECT * FROM masterpassword WHERE id = 1 AND password = ?", [(checkHashedPassword)])
        print(checkHashedPassword)
        return cursor.fetchall()

    def VerifyPassword():
        match = getMasterPassword()

        print(match)

        if match:
            passwordManager()
        else:
            Password.delete(0, 'end')
            lbl1.config(text="Incorrect Password")

    def resetPassword():
        resetScreen()

    Button(frame, width=39, pady=7, text='Login', bg='#57a1f8', fg='white', border=0, command=VerifyPassword).place(
        x=15, y=204)

    sign_up = Button(frame, width=6, text='Click here', border=0, bg='white', cursor='hand2', fg='#57a1f8',
                     command=resetPassword)
    sign_up.place(x=185, y=270)


def passwordManager():
    for widget in window.winfo_children():
        widget.destroy()

    def addEntry():
        text1 = "Website"
        text2 = "Email"
        text3 = "Password"

        website = encrypt(popUp(text1).encode(), encryptionKey)
        email = encrypt(popUp(text2).encode(), encryptionKey)
        password = encrypt(showPop(text3).encode(), encryptionKey)

        insert_fields = """INSERT INTO manager(website,email,password)
        VALUES(?, ?, ?)"""

        cursor.execute(insert_fields, (website, email, password))
        db.commit()

        passwordManager()

    def removeEntry(input):
        ans = mbox.askyesno('Delete Account', 'Are you sure?')
        if ans:
            cursor.execute("DELETE FROM manager WHERE id = ?", (input,))
            db.commit()

            passwordManager()
        else:
            pass

    def copyAcc(input):
        window.clipboard_clear()
        window.clipboard_append(input)

    def copyPass(input):
        window.clipboard_clear()
        window.clipboard_append(input)

    window.geometry("1400x500")

    lbl = Label(window, text='Safe Password', fg="#57a1f8", bg='white', font=('Microsoft Yahei UI Light', 23, 'bold'))
    lbl.grid(column=1)

    btn = Button(window, text="Add New Account",  bg='light Green', fg='white', border=0, command=addEntry)
    btn.grid(column=1, pady=10)

    btn2 = Button(window, text="Generate Password",  bg='Brown', fg='white', border=0, command=passGenerator)
    btn2.grid(column=3, pady=10, row=2)

    lbl = Label(window, text="Website", fg="#57a1f8", bg='white', font=('Microsoft Yahei UI Light', 23))
    lbl.grid(row=2, column=0, padx=80)
    lbl = Label(window, text="Email", fg="#57a1f8", bg='white', font=('Microsoft Yahei UI Light', 23))
    lbl.grid(row=2, column=1, padx=80)
    lbl = Label(window, text="Password", fg="#57a1f8", bg='white', font=('Microsoft Yahei UI Light', 23))
    lbl.grid(row=2, column=2, padx=80)

    cursor.execute("SELECT * FROM manager")
    if (cursor.fetchall() != None):
        i = 0
        while True:
            cursor.execute("SELECT * FROM manager")
            array = cursor.fetchall()

            if (len(array) == 0):
                break

            lbl1 = Label(window, text=(decrypt(array[i][1], encryptionKey)), font=("Time New Roman", 12, "bold"))
            lbl1.grid(column=0, row=i + 3)
            lbl2 = Label(window, text=(decrypt(array[i][2], encryptionKey)), font=("Time New Roman", 12, "bold"))
            lbl2.grid(column=1, row=i + 3)
            lbl3 = Label(window, text=(decrypt(array[i][3], encryptionKey)), font=("Time New Roman", 12, "bold"))
            lbl3.grid(column=2, row=i + 3)

            btn = Button(window, text="Erase Account", bg='Red', fg='white', border=0, command=partial(removeEntry, array[i][0]))
            btn.grid(column=3, row=i + 3, pady=10)
            btn2 = Button(window, text="Copy Account",bg='Orange', fg='white', border=0, command=partial(copyAcc, array[i][2]))
            btn2.grid(column=4, row=i + 3, pady=10)
            btn3 = Button(window, text="Copy Password",bg='Orange', fg='white', border=0, command=partial(copyPass, array[i][3]))
            btn3.grid(column=5, row=i + 3, pady=10)

            i = i + 1

            cursor.execute("SELECT * FROM manager")
            if (len(cursor.fetchall()) <= i):
                break


cursor.execute("SELECT * FROM masterpassword")
if cursor.fetchall():
    loginPage()
else:
    RegisterScreen()
window.mainloop()
