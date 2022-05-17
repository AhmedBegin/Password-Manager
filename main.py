import hashlib
import sqlite3
import tkinter.messagebox as mbox
import uuid
from functools import partial
from tkinter import *
from tkinter import simpledialog

import pyperclip

from Encryption import EncrypTool
from passgen import passGenerator

# Database Code
with sqlite3.connect("database.db") as db:
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

canvas = Canvas(height=300, width=300)
photo = PhotoImage(file="change-password-icon-11.png")
canvas.create_image(150, 150, image=photo)
canvas.pack()


def hashPassword(input):
    hash = hashlib.sha256(input)
    hash = hash.hexdigest()

    return hash


def RegisterScreen():
    window.geometry("900x800")
    window.config(bg='blue')
    window.config(padx=145, pady=49)

    lbl = Label(window, text="Create a password to login to the application", font=('Helvetica', 16, 'bold'))
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window, width=30, show="*")
    txt.pack()
    txt.focus()

    lbl1 = Label(window, text="Enter the password again")
    lbl1.pack()
    lbl1.config(font=('Helvetica', 16, 'bold'))

    txt1 = Entry(window, width=30, show="*")
    txt1.pack()
    txt1.focus()

    lbl2 = Label(window)
    lbl2.pack()
    lbl2.config(font=('Time New Roman', 12, 'bold'), fg="Red")

    def SavePassword():
        if txt.get() == txt1.get():
            sql = "DELETE FROM masterpassword WHERE id = 1"

            cursor.execute(sql)

            hashedPassword = hashPassword(txt.get().encode("utf-8"))
            key = str(uuid.uuid4().hex)
            recoveryKey = hashPassword(key.encode('utf-8'))

            insert_password = """INSERT INTO masterpassword(password, recoveryKey)
            VALUES(?, ?) """
            cursor.execute(insert_password, ((hashedPassword), (recoveryKey)))
            db.commit()

            recoveryScreen(key)
        else:
            lbl2.config(text="The passwords are not the same")

    btn = Button(window, text="Sign up", bg="Orange", command=SavePassword)
    btn.pack()


def recoveryScreen(key):
    window.geometry('500x300')
    lbl = Label(window, text="Save the key that appear below to recover the account if you want ")
    lbl.config(anchor=CENTER)
    lbl.pack()

    lbl1 = Label(window, text=key)
    lbl1.config(anchor=CENTER)
    lbl1.pack()

    def copyKey():
        pyperclip.copy(lbl1.cget("text"))

    btn = Button(window, text="Copy the key", command=copyKey)
    btn.pack(pady=5)

    def done():
        passwordManager()

    btn = Button(window, text="Okay", command=done)
    btn.pack(pady=5)


def resetScreen():
    window.geometry('500x300')
    lbl = Label(window, text="Put Recovery Key that you received before")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window, width=30)
    txt.pack()
    txt.focus()

    lbl1 = Label(window)
    lbl1.config(anchor=CENTER)
    lbl1.pack()

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

    btn = Button(window, text="Check Key", command=checkRecoveryKey)
    btn.pack(pady=5)


def loginPage():
    window.geometry("900x800")
    window.config(bg='blue')
    window.config(padx=145, pady=49)

    lbl = Label(window, text="Enter Master Password", font=('Helvetica', 18, 'bold'))
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window, width=30, show="*")
    txt.pack()
    txt.focus()

    lbl1 = Label(window)
    lbl1.pack()
    lbl1.config(fg="red", font=('Times New Roman', 12))

    def getMasterPassword():
        checkHashedPassword = hashPassword(txt.get().encode("utf-8"))
        cursor.execute("SELECT * FROM masterpassword WHERE id = 1 AND password = ?", [(checkHashedPassword)])
        print(checkHashedPassword)
        return cursor.fetchall()

    def VerifyPassword():
        match = getMasterPassword()

        print(match)

        if match:
            passwordManager()
        else:
            txt.delete(0, 'end')
            lbl1.config(text="Incorrect Password")

    def resetPassword():
        resetScreen()

    btn = Button(window, text="Sign in", bg='Yellow', command=VerifyPassword)
    btn.pack(pady=10)

    btn = Button(window, text="Forgot Password?", bg='Red', command=resetPassword)
    btn.pack(pady=5)


def passwordManager():
    for widget in window.winfo_children():
        widget.destroy()

    def addEntry():
        text1 = "Website"
        text2 = "Email"
        text3 = "Password"

        website = popUp(text1)
        email = popUp(text2)
        password = showPop(text3)

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

    def updateEntry(input):
        update = "Type new password"
        password = showPop(update)

        cursor.execute("UPDATE manager SET password = ? WHERE id = ?", (password, input,))
        db.commit()
        passwordManager()

    def updateUser(input):
        update = "Type new Email"
        email = popUp(update)

        cursor.execute("UPDATE manager SET email = ? WHERE id = ?", (email, input,))
        db.commit()
        passwordManager()

    def updateWeb(input):
        update = "Type new Website"
        website = popUp(update)

        cursor.execute("UPDATE manager SET website = ? WHERE id = ?", (website, input,))
        db.commit()
        passwordManager()

    window.geometry("900x500")

    lbl = Label(window, text="Welcome!!!", bg="Light Green", font=('Times new Roman', 12))
    lbl.grid(column=1)

    btn = Button(window, text="Add New Account", bg="Light blue", command=addEntry)
    btn.grid(column=1, pady=10)

    btn3 = Button(window, text="Encrypt and decrypt", bg="Green", command=EncrypTool)
    btn3.grid(column=5, pady=10, row=2)

    btn2 = Button(window, text="Generate Password", bg="brown", command=passGenerator)
    btn2.grid(column=3, pady=10, row=2)

    lbl = Label(window, text="Website", font=("Arial", 16))
    lbl.grid(row=2, column=0, padx=80)
    lbl = Label(window, text="Email", font=("Arial", 16))
    lbl.grid(row=2, column=1, padx=80)
    lbl = Label(window, text="Password", font=("Arial", 16))
    lbl.grid(row=2, column=2, padx=80)

    cursor.execute("SELECT * FROM manager")
    if (cursor.fetchall() != None):
        i = 0
        while True:
            cursor.execute("SELECT * FROM manager")
            array = cursor.fetchall()

            lbl1 = Label(window, text=(array[i][1]), font=("Time New Roman", 12, "bold"))
            lbl1.grid(column=0, row=i + 3)
            lbl2 = Label(window, text=(array[i][2]), font=("Time New Roman", 12, "bold"))
            lbl2.grid(column=1, row=i + 3)
            lbl3 = Label(window, text=(array[i][3]), font=("Time New Roman", 12, "bold"))
            lbl3.grid(column=2, row=i + 3)

            btn1 = Button(window, text="Update password", command=partial(updateEntry, array[i][0]))
            btn1.grid(column=6, row=i + 3, pady=10)
            btn4 = Button(window, text="Update Email", command=partial(updateUser, array[i][0]))
            btn4.grid(column=7, row=i + 3, pady=10)
            btn5 = Button(window, text="Update Website", command=partial(updateWeb, array[i][0]))
            btn5.grid(column=8, row=i + 3, pady=10)
            btn = Button(window, text="Erase Account", command=partial(removeEntry, array[i][0]))
            btn.grid(column=3, row=i + 3, pady=10)
            btn2 = Button(window, text="Copy Account", command=partial(copyAcc, array[i][2]))
            btn2.grid(column=4, row=i + 3, pady=10)
            btn3 = Button(window, text="Copy Password", command=partial(copyPass, array[i][3]))
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
