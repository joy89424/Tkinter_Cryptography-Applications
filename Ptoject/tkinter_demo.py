import tkinter.messagebox
import tkinter as tk
import os
from tkinter import ttk,filedialog,messagebox
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP,AES
from Crypto.Random import get_random_bytes
from PIL import Image,ImageTk

#------STEP ONE:登入頁面------
def UI_for_sign_in():
    global cipherUI,textbox1,btn_1
    if cipher_flag == 0:
        cipherUI=tk.Tk()
    else:
        cipherUI=tk.Toplevel()
    cipherUI.geometry("1000x600")
    cipherUI.title('帳號密碼管理系統')
    cipherUI.configure(bg='#d9dded')
    
    #產生container並且置中
    div_container = tk.Frame(cipherUI, width=500, height=348, bg='white',highlightbackground="black", highlightthickness=1)
    div_container.grid(row=0, column=0, padx=250, pady=126)
    
    #頁面分成3大塊(上、中、下)
    div_top = tk.Frame(div_container, width=500, height=100, bg='#262626')
    div_medium = tk.Frame(div_container, width=500, height=238, bg='Ivory')
    div_bottom = tk.Frame(div_container, width=500, height=10, bg='#262626')
    div_top.grid(row=0, column=0)
    div_medium.grid(row=1, column=0)
    div_bottom.grid(row=2, column=0)

    #添加標題
    L1=tk.Label(div_top,text='使用者登入',bg='#262626',fg='#FFFFFF',font=('標楷體',20))
    L1.grid(row=0, column=0, ipadx=177, ipady=10)

    #添加圖片
    im = Image.open("img/user.png")
    img = im.resize((20, 20), Image.ANTIALIAS) #調整大小
    img = ImageTk.PhotoImage(img)
    imLabel1=tk.Label(cipherUI,image=img,bg='Ivory').place(x=366,y=222)

    im2 = Image.open("img/padlock.png")
    img2 = im2.resize((20, 20), Image.ANTIALIAS) #調整大小
    img2 = ImageTk.PhotoImage(img2)
    imLabel2=tk.Label(cipherUI,image=img2,bg='Ivory').place(x=366,y=282)
    
    #添加文字框
    textbox1=tk.Text(cipherUI,show=None,width=20,height=1,font=('標楷體', 15))
    textbox1.place(x=406,y=222)
    
    #添加按鈕
    btn=tk.Button(cipherUI,text='AES密碼載入',bg='#c2cad0',font=('標楷體',12),width=24,relief='groove',command=key_in)
    btn.place(x=406,y=282)
    btn_1=tk.Button(cipherUI,text='登入',bg='#f7ebb5',activebackground='#fcf7e3',font=('標楷體',12),width=10,relief='groove',command=log_in)
    #注意：未放上因為key_in()成功才觸發
    btn_2=tk.Button(cipherUI,text='註冊',bg='#adcde5',activebackground='#e7f0f7',font=('標楷體',12),width=10,relief='groove',command=registered)
    btn_2.place(x=518,y=345)

    cipherUI.mainloop()
    

def key_in():#第一步->測試金鑰可用、載入金鑰
    global key#載入金鑰
    file_path=filedialog.askopenfilename()
    f=open(file_path,"rb")
    key=f.read()
    f.close()
    try:#測試金鑰可用與否
        AESkey=AES.new(key,AES.MODE_EAX)
        btn_1.place(x=406,y=345)
    except:
        messagebox.showinfo("Pop up", "請載入正確的AES key")


def log_in():#第二步->按登入
    enterAccount=textbox1.get('1.0','end')[:-1]
    if enterAccount == SUname:
        index=-1
        if check_cipher(index):
            #SU登入成功
            cipherUI.destroy()
            UI_for_SU()
        else:
            #SU登入失敗
            messagebox.showinfo("Pop up", "帳號密碼不正確 請重新輸入")
    elif enterAccount in name:
        index=name.index(enterAccount)
        if check_cipher(index):
            #User登入成功
            cipherUI.destroy()
            UI_for_User(index)
        else:
            #User登入失敗
            messagebox.showinfo("Pop up", "帳號密碼不正確 請重新輸入")
    else:
        messagebox.showinfo("Pop up", "名稱錯誤,請重新輸入")

def check_cipher(num):#num=-1->SU 、 num>0->user
    global cipher_data                              ##變數 global
    #定義路徑
    if num==-1:
        path="database/acccount_data/ShiXun.bin"                            #@@
    else:
        path="database/acccount_data/"+str(name[num])+".bin"                #@@
    #檢查是否成功
    f=open(path,"rb")
    nonce,tag,ciphertext=[f.read(x) for x in (16, 16, -1)]
    f.close()
    try:
        AESkey=AES.new(key,AES.MODE_EAX,nonce)
        cipher_data=AESkey.decrypt_and_verify(ciphertext,tag)
        cipher_data=cipher_data.decode()
        return 1
    except:
        return 0
    
#***註冊區***   
def registered():
    global regist_UI,regist_textbox1,regist_textbox2    ##UI global
    cipherUI.destroy()

    regist_UI=tk.Tk()
    regist_UI.geometry("1000x600")
    regist_UI.title('帳號密碼管理系統')
    regist_UI.configure(bg='#d9dded')

    #產生container並且置中
    regist_div_container = tk.Frame(regist_UI, width=500, height=348, bg='white',highlightbackground="black", highlightthickness=1)
    regist_div_container.grid(row=0, column=0, padx=250, pady=126)
    
    
    #頁面分成3大塊(上、中、下)
    regist_div_top = tk.Frame(regist_div_container, width=500, height=100, bg='#262626')
    regist_div_medium = tk.Frame(regist_div_container, width=500, height=238, bg='Ivory')
    regist_div_bottom = tk.Frame(regist_div_container, width=500, height=10, bg='#262626')
    regist_div_top.grid(row=0, column=0)
    regist_div_medium.grid(row=1, column=0)
    regist_div_bottom.grid(row=2, column=0)

    regist_L1=tk.Label(regist_div_top,text='註冊',bg='#262626',fg='#FFFFFF',font=('標楷體',20))
    regist_L1.grid(row=0, column=0, ipadx=219, ipady=10)

    regist_im = Image.open("img/user.png")
    regist_img = regist_im.resize((20, 20), Image.ANTIALIAS) #調整大小
    regist_img = ImageTk.PhotoImage(regist_img)
    regist_imLabel1=tk.Label(regist_UI,image=regist_img,bg='Ivory').place(x=366,y=222)

    regist_im2 = Image.open("img/padlock.png")
    regist_img2 = regist_im2.resize((20, 20), Image.ANTIALIAS) #調整大小
    regist_img2 = ImageTk.PhotoImage(regist_img2)
    imLabel2=tk.Label(regist_UI,image=regist_img2,bg='Ivory').place(x=366,y=282)

    regist_textbox1=tk.Text(regist_UI,show=None,width=20,height=1,font=('標楷體', 15))
    regist_textbox1.place(x=406,y=222)
    regist_textbox2=tk.Text(regist_UI,show=None,width=20,height=1,font=('標楷體', 15))
    regist_textbox2.place(x=406,y=282)
    regist_btn=tk.Button(regist_UI,text='註冊並生成AES key',bg='#adcde5',activebackground='#e7f0f7',font=('標楷體',12),width=24,relief='groove',command=regist_Step1_Confirm)
    regist_btn.place(x=406,y=342)

    regist_log_out_btn=tk.Button(regist_UI,text='返回',bg='#f7ebb5',activebackground='#fcf7e3',font=('標楷體',12),width=9,relief='groove',command=Regist_log_out)
    regist_log_out_btn.place(x=665,y=185)
    
    regist_UI.mainloop()
    
def regist_Step1_Confirm():
    regName=regist_textbox1.get('1.0','end')[:-1]
    regPassword=regist_textbox2.get('1.0','end')[:-1]
    print(regName)                              
    if regName in name or regName==SUname:
        root = tk.Tk()
        root.withdraw()
        messagebox.showinfo("Pop up", "名稱重複,請重新輸入")
    elif regName=="" or regPassword=="":
        root = tk.Tk()
        root.withdraw()
        messagebox.showinfo("Pop up", "帳號密碼不能為空")
    else:
        #生成新User金鑰
        new_key=get_random_bytes(16)
        filename="User"+str(len(name)+1)+".pem"
        f=open(filename,"wb")
        f.write(new_key)
        f.close()
        
        #user account.txt新建使用者
        path="database/acccount_data/user account.txt"
        f=open(path,"a")
        print("\n"+regName,file=f,end="")
        f.close()
        name.append(regName)
        
        #加密new user輸入的密碼
        cipher=AES.new(new_key,AES.MODE_EAX)
        ciphertext,tag= cipher.encrypt_and_digest(regPassword.encode())

        path="database/acccount_data/"+regName+".bin"
        f=open(path,"wb")
        for x in (cipher.nonce, tag, ciphertext):
            f.write(x)
        f.close()

        #生成待加密檔案+更改status
        cipher=AES.new(syskey,AES.MODE_EAX)
        ciphertext,tag=cipher.encrypt_and_digest(regPassword.encode())
        for i in range(2):
            #生成待加密
            path="database/waitForEncrypt/"+str(name[len(name)-1])+"-"+str(name[len(name)-(i+1)-1])+".bin"
            f=open(path,"wb")
            for j in (cipher.nonce,tag,ciphertext):
                f.write(j)
            f.close()
            #更改status
            user_helpUserEncrypt[len(name)-(i+2)][i]=len(name)-1

        #更改state
        user_helpSUdecrypt.append(-1)
        user_helpUserEncrypt.append([-1,-1])
        user_haveSaved.append(0)
        user_saveList.append([0,0])
        saveStatus()

        #顯示註冊成功
        regist_text4=tk.Label(regist_UI,text='註冊成功,請保管好您的AES金鑰',bg='#f7ebb5',font=('標楷體',12))
        regist_text4.place(x=390,y=385)

def Regist_log_out():
    regist_UI.destroy()
    UI_for_sign_in()
#------STEP TWO:User、SU頁面------
#***SU介面區***
def UI_for_SU():
    global SU_UI,SU_combo1,SU_text2                     ##UI global
    SU_UI=tk.Tk()
    SU_UI.geometry("1000x600")    
    SU_UI.title('帳號密碼管理系統')
    SU_UI.configure(bg='#d9dded')

    #產生container並且置中
    SU_div_container = tk.Frame(SU_UI, width=500, height=420, bg='white',highlightbackground="black", highlightthickness=1)
    SU_div_container.grid(row=0, column=0, padx=250, pady=90)
    
    #頁面分成3大塊(上、中、下)
    SU_div_top = tk.Frame(SU_div_container, width=500, height=100, bg='#262626')
    SU_div_medium = tk.Frame(SU_div_container, width=500, height=350, bg='Ivory')
    SU_div_bottom = tk.Frame(SU_div_container, width=500, height=10, bg='#262626')
    SU_div_top.grid(row=0, column=0)
    SU_div_medium.grid(row=1, column=0)
    SU_div_bottom.grid(row=2, column=0)

    #添加標題
    SU_L1=tk.Label(SU_div_top,text='超級使用者操作介面',bg='#262626',fg='#FFFFFF',font=('標楷體',20))
    SU_L1.grid(row=0, column=0, ipadx=121, ipady=10)
    
    #步驟一
    SU_text1=tk.Label(SU_UI,text='Step1.請選擇您要調用的員工:',bg='Ivory',font=('標楷體',13))
    SU_text1.place(x=270,y=160)
    SU_text2=tk.Label(SU_UI,text='選擇不能留空!',font=('標楷體',13),bg='Ivory',fg='red')
    #沒選時才顯示
    SU_combo1 = ttk.Combobox(SU_UI,values=name,font=('標楷體',12),width=10)
    SU_combo1.place(x=270,y=200)
    SU_btn=tk.Button(SU_UI,text='確定',bg='#adcde5',activebackground='#e7f0f7',font=('標楷體',12),width=12,relief='groove',command=SU_Step1_Confirm)
    SU_btn.place(x=411,y=197)
    SU_log_out_btn=tk.Button(SU_UI,text='登出',bg='#f7ebb5',activebackground='#fcf7e3',font=('標楷體',12),width=9,relief='groove',command=SU_log_out)
    SU_log_out_btn.place(x=660,y=151)

    SU_UI.mainloop()


def SU_Step1_Confirm():
    global pick_num,help_name                           ##變數 global
    global SU_combo1,SU_combol2,SU_text2,SU_text3       ##UI global
    help_name=[]
    
    SU_text2.place_forget()
    pick_num=SU_combo1.current()
    pickName=name[pick_num]
    #先定義誰可以幫忙解密
    if pick_num==-1:
        SU_text2.place(x=550,y=200)
        print()
    else:
        if pick_num==0:
            help_name.append(name[1])
            help_name.append(name[2])
        elif pick_num==1:
            help_name.append(name[0])
            help_name.append(name[2])
        else:
            help_name.append(name[pick_num-1])
            help_name.append(name[pick_num-2])

        SU_text2=tk.Label(SU_UI,text='Step2.請選擇其中一個員工幫您解密:',bg='Ivory',font=('標楷體',13))
        SU_text2.place(x=270,y=240)
        SU_combol2 = ttk.Combobox(SU_UI,values=help_name,font=('標楷體',12),width=10)
        SU_combol2.place(x=270,y=280)
        SU_text3=tk.Label(SU_UI,text='選擇不能留空!',font=('標楷體',13),bg='Ivory',fg='red')
        #沒選時才顯示
        SU_btn2=tk.Button(SU_UI,text='確定',bg='#e5c5ad',font=('標楷體',12),width=12,relief='groove',command=SU_Step2_Confirm)
        SU_btn2.place(x=411,y=277)


def SU_Step2_Confirm():
    global help_num                                     ##變數 global
    global SU_combol2,SU_text3                          ##UI global

    SU_text3.place_forget()
    help_num=name.index(help_name[SU_combol2.current()])

    if SU_combol2.current()==-1:
        SU_text3.place(x=550,y=280)
    else:
        SU_text4=tk.Label(SU_UI,text='Step3.請上傳RSA privateKey:',bg='Ivory',font=('標楷體',13))
        SU_text4.place(x=270,y=320)
        SU_btn3=tk.Button(SU_UI,text='上傳',bg='#ade5c5',activebackground='#ecf5ea',font=('標楷體',12),width=12,relief='groove',command=SU_rsaPri_fileIn)
        SU_btn3.place(x=270,y=360)
        SU_btn4=tk.Button(SU_UI,text='請求',bg='#e5adcd',activebackground='#f5eaec',font=('標楷體',12),width=12,relief='groove',command=SU_requsrForDecrypt)
        SU_btn4.place(x=411,y=360)
        #更改Status
        user_helpSUdecrypt[help_num]=pick_num
        saveStatus()


def SU_rsaPri_fileIn():#**解密**
    #載入私鑰
    root = tk.Tk()
    root.withdraw()
    file_path=filedialog.askopenfilename()
    f=open(file_path,"rb")
    PrivateKey=f.read()
    f.close()
    #載入待解密檔案
    file_path="database/SU_database/"+str(name[pick_num])+"-"+str(name[help_num])+".bin"
    f=open(file_path,"rb")
    E_data=f.read()
    f.close()
    #嘗試解密
    #try:
    #解密ing
    RSAkey_pri=RSA.import_key(PrivateKey)
    decrypt_cipher=PKCS1_OAEP.new(RSAkey_pri)
    data1=decrypt_cipher.decrypt(E_data)
    #存在暫存區
    file_path="database/waitForDecrypt/"+str(name[pick_num])+"-"+str(name[help_num])+".bin"
    f=open(file_path,"wb")
    f.write(data1)
    f.close()
    #下一步
    SU_text5=tk.Label(SU_UI,text='Step4.等待解密:',bg='Ivory',font=('標楷體',13))
    SU_text5.place(x=270,y=400)
    '''
    except:
        root = tk.Tk()
        root.withdraw()
        messagebox.showinfo("Pop up", "載入私鑰錯誤!")
    '''
def SU_requsrForDecrypt():
    global cipher_flag
    cipher_flag=1
    UI_for_sign_in()

def SU_log_out():
    global cipher_flag
    SU_UI.destroy()
    cipher_flag=0
    UI_for_sign_in()
         
#***User介面區***
def UI_for_User(number):
    global UserID                                   ##變數 global
    global userUI,User_text4,User_text7,User_text8  ##UI global
    UserID=int(number)
    userUI=tk.Tk()
    userUI.geometry("1000x600")
    userUI.title('帳號密碼管理系統')
    userUI.configure(bg='#d9dded')

    #產生container並且置中
    User_div_container = tk.Frame(userUI, width=500, height=420, bg='white',highlightbackground="black", highlightthickness=1)
    User_div_container.grid(row=0, column=0, padx=250, pady=90)
    
    #頁面分成3大塊(上、中、下)
    User_div_top = tk.Frame(User_div_container, width=500, height=100, bg='#262626')
    User_div_medium = tk.Frame(User_div_container, width=500, height=350, bg='Ivory')
    User_div_bottom = tk.Frame(User_div_container, width=500, height=10, bg='#262626')
    User_div_top.grid(row=0, column=0)
    User_div_medium.grid(row=1, column=0)
    User_div_bottom.grid(row=2, column=0)

    #添加標題
    SU_L1=tk.Label(User_div_top,text='User操作介面',bg='#262626',fg='#FFFFFF',font=('標楷體',20))
    SU_L1.grid(row=0, column=0, ipadx=163, ipady=10)
    
    #User顯示密碼+換密碼區
    User_text1=tk.Label(userUI,text=name[number]+' 您的密碼:', bg='Ivory',font=('標楷體',15))
    User_text1.place(x=270,y=160)
    User_textbox1=tk.Text(userUI,show=None,font=('標楷體',14),width=20,height=1)
    User_textbox1.insert("insert",cipher_data)
    User_textbox1.place(x=310,y=200)
    #User_btn=tk.Button(userUI,text='修改密碼',bg='#adcde5',activebackground='#e7f0f7',font=('標楷體',12),width=12,relief='groove',command=User_changeCipher)
    #User_btn.place(x=560,y=197)
    User_log_out_btn=tk.Button(userUI,text='登出',bg='#f7ebb5',activebackground='#fcf7e3',font=('標楷體',12),width=9,relief='groove',command=User_log_out)
    User_log_out_btn.place(x=660,y=151)
    
    #User被SU要求幫忙解密
    if user_helpSUdecrypt[number]>-1:
        User_text2=tk.Label(userUI,text='◎注意! 您的主管請求您幫忙解密:', bg='Ivory',font=('標楷體',14))
        User_text2.place(x=270,y=250)
        User_text3=tk.Label(userUI,text='要解密的對象  ->  '+name[user_helpSUdecrypt[number]], bg='Ivory',font=('標楷體',14))
        User_text3.place(x=310,y=290)
        User_text4=tk.Label(userUI,text='錯誤AES key', bg='Ivory',font=('標楷體',14),fg='red')
        #錯誤時才顯示
        User_btn2=tk.Button(userUI,text='同意並載入AES key',bg='#adcde5',activebackground='#e7f0f7',font=('標楷體',12),width=20,relief='groove',command=User_helpSU_fileIn)
        User_btn2.place(x=560,y=287)
        
    #User被要求幫忙加密    
    if user_helpUserEncrypt[number][0]>-1 or user_helpUserEncrypt[number][1]>-1:
        if number==0:
            print()
        elif number==1:
            print()

        if user_helpUserEncrypt[number][0]>-1:
            User_text5=tk.Label(userUI,text='◎注意! User請求您幫忙加密:', bg='Ivory',font=('標楷體',14))
            User_text5.place(x=270,y=330)
            User_text6=tk.Label(userUI,text='要幫忙的對象  ->  '+name[user_helpUserEncrypt[number][0]], bg='Ivory',font=('標楷體',14))
            User_text6.place(x=310,y=370)
            User_text7=tk.Label(userUI,text='成功加密!', bg='Ivory',font=('標楷體',13),fg='red')
            #成功時才顯示
            User_btn3=tk.Button(userUI,text='同意並載入AES key',bg='#adcde5',activebackground='#e7f0f7',font=('標楷體',12),width=20,relief='groove',command=User_helpUser_fileIn0)
            User_btn3.place(x=560,y=367)
        if user_helpUserEncrypt[number][1]>-1:
            User_text5=tk.Label(userUI,text='◎注意! User請求您幫忙加密:', bg='Ivory',font=('標楷體',14))
            User_text5.place(x=270,y=410)
            User_text6=tk.Label(userUI,text='要幫忙的對象  ->  '+name[user_helpUserEncrypt[number][1]], bg='Ivory',font=('標楷體',14))
            User_text6.place(x=310,y=450)
            User_text8=tk.Label(userUI,text='成功加密!', bg='Ivory',font=('標楷體',13),fg='red')
            #成功時才顯示
            User_btn3=tk.Button(userUI,text='同意並載入AES key',bg='#adcde5',activebackground='#e7f0f7',font=('標楷體',12),width=20,relief='groove',command=User_helpUser_fileIn1)
            User_btn3.place(x=560,y=447)
            
def User_helpSU_fileIn():
    #載入金鑰
    root = tk.Tk()
    root.withdraw()
    file_path=filedialog.askopenfilename()
    f=open(file_path,"rb")
    AESkey=f.read()
    f.close()
    #載入檔案
    file_path="database/waitForDecrypt/"+str(name[user_helpSUdecrypt[UserID]])+"-"+str(name[UserID])+".bin"
    f=open(file_path,"rb")
    data1=f.read()
    f.close()
    nonce=data1.split(b" ")[0]
    tag=data1.split(b" ")[1]
    ciphertext=data1.split(b" ")[2]
    try:
        #解密
        cipher=AES.new(AESkey,AES.MODE_EAX,nonce) 
        data=cipher.decrypt_and_verify(ciphertext,tag)
        data=data.decode()
        print(data)
        #更新
        os.remove(file_path)
        user_helpSUdecrypt[UserID]=-1
        saveStatus()
        SU_text6=tk.Label(SU_UI,text='密碼是:'+data,bg='Ivory',font=('標楷體',13))
        SU_text6.place(x=270,y=440)
    except:
        User_text4.place(x=600,y=250)

   
def User_helpUser_fileIn0():
    global user_UI                              ##UI global
    #載入檔案
    file_path="database/waitForEncrypt/"+str(name[user_helpUserEncrypt[UserID][0]])+"-"+str(name[UserID])+".bin"
    f=open(file_path,"rb")
    nonce,tag,ciphertext=[f.read(x) for x in (16, 16, -1)]
    f.close()
    os.remove(file_path)

    cipher=AES.new(syskey,AES.MODE_EAX,nonce)
    password=cipher.decrypt_and_verify(ciphertext,tag)
    
    #載入AES key AES加密
    root = tk.Tk()
    root.withdraw()
    file_path=filedialog.askopenfilename()
    f=open(file_path,"rb")
    User_key=f.read()
    f.close()
    
    cipher=AES.new(User_key,AES.MODE_EAX)
    ciphertext,tag=cipher.encrypt_and_digest(password)
    data1=cipher.nonce+b" "+tag+b" "+ciphertext
    
    #載入RSA key+RSA加密
    f=open("SU_publicKey.pem","rb")
    PublicKey=f.read()
    f.close()

    RSAkey_pub=RSA.import_key(PublicKey)
    encrypt_cipher = PKCS1_OAEP.new(RSAkey_pub)
    data2=encrypt_cipher.encrypt(data1)
    
    file_path="database/SU_database/"+str(name[user_helpUserEncrypt[UserID][0]])+"-"+str(name[UserID])+".bin"
    f=open(file_path,"wb")
    f.write(data2)
    f.close()

    #變更status
    user_saveList[user_helpUserEncrypt[UserID][0]][0]=1
    user_helpUserEncrypt[UserID][0]=-1
    saveStatus()

    #顯示成功
    User_text7.place(x=600,y=330)


def User_helpUser_fileIn1():
    global user_UI                              ##UI global
    #載入檔案
    file_path="database/waitForEncrypt/"+str(name[user_helpUserEncrypt[UserID][1]])+"-"+str(name[UserID])+".bin"
    f=open(file_path,"rb")
    nonce,tag,ciphertext=[f.read(x) for x in (16, 16, -1)]
    f.close()
    os.remove(file_path)

    cipher=AES.new(syskey,AES.MODE_EAX,nonce)
    password=cipher.decrypt_and_verify(ciphertext,tag)
    
    #載入AES key+AES加密
    root = tk.Tk()
    root.withdraw()
    file_path=filedialog.askopenfilename()
    f=open(file_path,"rb")
    User_key=f.read()
    f.close()
    
    cipher=AES.new(User_key,AES.MODE_EAX)
    ciphertext,tag=cipher.encrypt_and_digest(password)
    data1=cipher.nonce+b" "+tag+b" "+ciphertext
    
    #載入RSA key+RSA加密
    f=open("SU_publicKey.pem","rb")
    PublicKey=f.read()
    f.close()

    RSAkey_pub=RSA.import_key(PublicKey)
    encrypt_cipher = PKCS1_OAEP.new(RSAkey_pub)
    data2=encrypt_cipher.encrypt(data1)
    
    file_path="database/SU_database/"+str(name[user_helpUserEncrypt[UserID][1]])+"-"+str(name[UserID])+".bin"
    f=open(file_path,"wb")
    f.write(data2)
    f.close()

    #變更status
    user_saveList[user_helpUserEncrypt[UserID][1]][1]=1
    user_helpUserEncrypt[UserID][1]=-1
    saveStatus()

    #顯示成功
    User_text8.place(x=600,y=410)
    
def User_changeCipher():
    print("User換密碼囉")
    #未完成
    #未完成
    #未完成
    #未完成

#存Status
def saveStatus():
    f=open("database/status.txt","w")
    for i in range(len(user_helpSUdecrypt)):
        user_haveSaved[i]=user_saveList[i][0] or user_saveList[i][1]
        print(user_helpSUdecrypt[i],user_helpUserEncrypt[i][0],user_helpUserEncrypt[i][1],user_haveSaved[i],user_saveList[i][0],user_saveList[i][1],sep="\t",file=f)
    f.close()

    print("name",name)
    print("user_helpSUdecrypt",user_helpSUdecrypt)
    print("user_helpUserEncrypt",user_helpUserEncrypt)
    print("user_haveSaved",user_haveSaved)
    print("user_saveList",user_saveList)
def User_log_out():
    userUI.destroy()
    UI_for_sign_in()
#--------主程式----------------主程式----------------主程式--------
#變數區
global SUname,SUpassword,name,syskey,cipher_flag
global user_helpSUdecrypt,user_helpUserEncrypt,user_haveSaved,user_saveList
name=[]
user_helpSUdecrypt,user_helpUserEncrypt,user_haveSaved,user_saveList=[],[],[],[]
cipher_flag=0

#System key import
f=open("syskey.bin",'rb')
syskey=f.read()
f.close()

#SU account載入
f=open("database/acccount_data/Super user account.txt","r")
line=f.read()
f.close()
SUname=line.split(" ")[0]
SUpassword=line.split(" ")[1]

#普通Use accoun載入
f=open("database/acccount_data/user account.txt","r")
for line in f:
    name.append(line.split()[0])
f.close()

#讀取status表 status表說明如下
#user_helpSUdecrypt     =   SU是否要該User幫忙解密
#user_helpUserEncrypt   =   User是否要幫其他User加密
#user_haveSaved         =   User是否有供SU解密的檔案
#user_saveList          =   User的已加密檔案列表

f=open("database/status.txt","r")
for line in f:
    data=line.strip().split("\t")
    user_helpSUdecrypt.append(int(data[0]))
    user_helpUserEncrypt.append([int(data[1]),int(data[2])])
    user_haveSaved.append(int(data[3]))
    user_saveList.append([int(data[4]),int(data[5])])
f.close()

saveStatus()
#開啟登入頁面
UI_for_sign_in()
