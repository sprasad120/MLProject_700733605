from tkinter import *
from tkinter import messagebox

import joblib

from sql_injection import scan_sql_injection

icmp_model = joblib.load('model/icmp_new.ml')
tcp_sync_model= joblib.load('model/tcp_sync_new.ml')
udp_model= joblib.load('model/udp_new.ml')

main=Tk()
main.geometry('1080x650')
root = Frame(main)
root.pack(side="top", expand=True, fill="both")
       


def clear_frame():
    global btn1, btn2
    for widgets in root.winfo_children():
      widgets.destroy()
    title = Label(root, text = "DDOS Attack Detection Using Supervised Machine Learning Techniques", font=("Arial", 20),fg='red').place(x = 250, y = 60)
    
    uline = Label(root, text = "---------------------------------------------------------------", font=("Arial", 20),fg='red').place(x = 250, y = 95)

    btn1 = Button(root, text = 'DDoS Atach Detector', font=("Arial", 10), bd = '5', width=20, height=2, command = ddos_home)
    btn2 = Button(root, text = "SQL Injection", bd='5', font=("Arial", 10), width=20, height=2, command=sql_inject)



    btn1.place(x=300,y=200)
    btn2.place(x=600,y=200)




def home():
     
    title = Label(root, text = "Web Attack Detection using Machine Learning", font=("Arial", 20),fg='red').place(x = 250, y = 60)
    uline = Label(root, text = "---------------------------------------------------------------", font=("Arial", 20),fg='red').place(x = 250, y = 95)

    btn1 = Button(root, text = 'DDoS Atach Detector', font=("Arial", 10), bd = '5', width=20, height=2, command = ddos_home)
    btn2 = Button(root, text = "SQL Injection", bd='5', font=("Arial", 10), width=20, height=2, command=sql_inject)



    btn1.place(x=300,y=200)
    btn2.place(x=600,y=200)


def ddos_home():

    global icmp, tcp, udp
    btn1.destroy()
    btn2.destroy()
    icmp=Button(root, text = "Test for ICMP protocol",font=("Arial", 10), width=25, height=1, command=icmp_form)
    icmp.place(x=400, y=200)
    tcp= Button(root, text = "Test for TCP_SYNC protocol", font=("Arial", 10), width=25, height=1, command=tcp_form)
    tcp.place(x=400, y=300)
    udp= Button(root, text = "Test for UDP protocol", font=("Arial", 10), width=25, height=1, command=udp_form)
    udp.place(x=400, y=400)

def icmp_form():
    global duration_field,service_field,wrong_frag_field, srcbytes_field, cnt_field, urgent_field,num_cmp_field, srv_cnt_field
    icmp.destroy()
    tcp.destroy()
    udp.destroy()
    head = Label(root, text = "Fill the below values to test {ICMP PROTOCOL}", font=("Arial", 12),fg='blue')
    head.place(x = 390, y = 160)

    duration = Label(root, text="Duration             ")
    duration.place(x=400,y=200)
    duration_field = Entry(root)
    duration_field.place(x=550, y= 200)

    service = Label(root, text="Service             ")
    service.place(x=400,y=440)
    service_options = ["eco_i","ecr_i","tim_i","urp_i"]
    service_field = StringVar()
    service_field.set( "Select the Service")
    service_drop = OptionMenu( root , service_field , *service_options )
    service_drop.place(x=550, y=440)

    wrong_frag = Label(root, text="Wrong Fragmentation       ")
    wrong_frag.place(x=400,y=490)
    wrong_frag_options = [0,1]
    wrong_frag_field = StringVar()
    wrong_frag_field.set( "Select the option")
    wrong_frag_drop = OptionMenu( root , wrong_frag_field , *wrong_frag_options )
    wrong_frag_drop.place(x=550, y=490)

    srcbytes = Label(root, text="Src_Bytes            ")
    srcbytes.place(x=400,y=240)
    srcbytes_field = Entry(root)
    srcbytes_field.place(x=550, y= 240)


    cnt = Label(root, text="Count      ")
    cnt.place(x=400,y=280)
    cnt_field = Entry(root)
    cnt_field.place(x=550, y= 280)
    cnt_range = Label(root, text="[1-511]")
    cnt_range.place(x=680,y=280)


    urgent = Label(root, text="Urgent        ")
    urgent.place(x=400,y=320)
    urgent_field = Entry(root)
    urgent_field.place(x=550, y= 320)
    urgent_range = Label(root, text="Always '0'")
    urgent_range.place(x=680,y=320)


    num_cmp = Label(root, text="Num Compromised    ")
    num_cmp.place(x=400,y=360)
    num_cmp_field = Entry(root)
    num_cmp_field.place(x=550, y= 360)
    num_cmp_range = Label(root, text="Always '0'")
    num_cmp_range.place(x=680,y=360)


    srv_cnt = Label(root, text="Srv_count      ")
    srv_cnt.place(x=400,y=400)
    srv_cnt_field = Entry(root)
    srv_cnt_field.place(x=550, y= 400)
    srv_cnt_range = Label(root, text="[1-511]")
    srv_cnt_range.place(x=680,y=400)

    prd_icmp=Button(root, text="Predict", font=("Arial", 10), bd='5', width=15,command=icmp_pred)
    prd_icmp.place(x=380, y= 540)

    home=Button(root, text='Back to Home', font=("Arial", 10), bd='5', width=15, command=clear_frame)
    home.place(x=620, y=540)

def icmp_pred():
    service_d={"eco_i":-0.1,"ecr_i":0.0, "tim_i":0.1, "urp_i":0.2}
    #wrong_frag_d={'yes':1,'no':0}
    ft_l=[duration_field.get(), service_d[service_field.get()], srcbytes_field.get(), wrong_frag_field.get(), cnt_field.get(), urgent_field.get(), num_cmp_field.get(), srv_cnt_field.get()] 
    l=icmp_model.predict([ft_l])
    if l[0]==0:
        messagebox.showinfo("showinfo", "No Attack found in ICMP Protocol")
    else:
        messagebox.showwarning("showwarning", "Attack Found in ICMP Protocol")


def tcp_pred():
    ft_l=[service_field.get(), cnt_field.get(), srv_cnt_field.get(), srcbytes_field.get(), serror_rate_field.get()] 
    l=tcp_sync_model.predict([ft_l])
    if l[0]==0:
        messagebox.showinfo("showinfo", "No Attack found in TCP SYNC Protocol")
    else:
        messagebox.showwarning("showwarning", "Attack Found in TCP SYNC Protocol")

    
def tcp_form():
    global service_field, srcbytes_field, cnt_field, srv_cnt_field, serror_rate_field
    icmp.destroy()
    tcp.destroy()
    udp.destroy()
    head = Label(root, text = "Fill the below values to test TCP_SYNC Protocol", font=("Arial", 12),fg='blue').place(x = 380, y = 160)

    service = Label(root, text="Service            ")
    service.place(x=400,y=360)
    service_field = Entry(root)
    service_field.place(x=550, y= 360)
    service_range = Label(root, text="[-2.80 to 2.80]")
    service_range.place(x=680,y=360)


    srcbytes = Label(root, text="Src_Bytes       ")
    srcbytes.place(x=400,y=280)
    srcbytes_options = [0,   132,     1,   151,   183,   261,   190,  1256,   156,  209,   336,   122, 27472]
    srcbytes_field = StringVar()
    srcbytes_field.set( "Select the option")
    srcbytes_drop = OptionMenu( root , srcbytes_field , *srcbytes_options )
    srcbytes_drop.place(x=550, y=280)
    


    serror_rate = Label(root, text="SError Rate            ")
    serror_rate.place(x=400,y=320)
    serror_rate_field = Entry(root)
    serror_rate_field.place(x=550, y= 320)
    serror_rate_range = Label(root, text="[0.00-1.00]")
    serror_rate_range.place(x=680,y=320)


    cnt = Label(root, text="Count      ")
    cnt.place(x=400,y=200)
    cnt_field = Entry(root)
    cnt_field.place(x=550, y= 200)
    cnt_range = Label(root, text="[1-511]")
    cnt_range.place(x=680,y=200)


    srv_cnt = Label(root, text="Srv_count      ")
    srv_cnt.place(x=400,y=240)
    srv_cnt_field = Entry(root)
    srv_cnt_field.place(x=550, y= 240)
    srv_cnt_range = Label(root, text="[1-511]")
    srv_cnt_range.place(x=680,y=240)

    prd_icmp=Button(root, text="Predict", font=("Arial", 10), bd='5', width=15,command=tcp_pred)
    prd_icmp.place(x=380, y= 420)

    home=Button(root, text='Back to Home', font=("Arial", 10), bd='5', width=15, command=clear_frame)
    home.place(x=620, y=420)

def udp_pred():
    ft_l=[dst_host_srv_cnt_field.get(), service_field.get(), srcbytes_field.get(), dst_host_srv_cnt_field.get(), cnt_field.get()] 
    l=udp_model.predict([ft_l])
    if l[0]==0:
        messagebox.showinfo("showinfo", "No Attack found in UDP Protocol")
    else:
        messagebox.showwarning("showwarning", "Attack Found in UDP Protocol")   

def udp_form():
    global service_field, srcbytes_field, dst_bytes_field, cnt_field, dst_host_srv_cnt_field 
    icmp.destroy()
    tcp.destroy()
    udp.destroy()
    head = Label(root, text = "Fill the below values to test UDP Protocol", font=("Arial", 12),fg='blue').place(x = 380, y = 160)


    service = Label(root, text="Service       ")
    service.place(x=400,y=240)
    service_options = [ 0. , -0.3, -0.1, -0.2,  0.1]
    service_field = StringVar()
    service_field.set( "Select the option")
    service_drop = OptionMenu( root , service_field , *service_options )
    service_drop.place(x=550, y=240)




    srcbytes = Label(root, text="Src_Bytes       ")
    srcbytes.place(x=400,y=290)
    srcbytes_options = [0,   132,     1,   151,   183,   261,   190,  1256,   156,  209,   336,   122, 27472]
    srcbytes_field = StringVar()
    srcbytes_field.set( "Select the option")
    srcbytes_drop = OptionMenu( root , srcbytes_field , *srcbytes_options )
    srcbytes_drop.place(x=550, y=290)
    


    dst_bytes = Label(root, text="DST Bytes            ")
    dst_bytes.place(x=400,y=200)
    dst_bytes_field = Entry(root)
    dst_bytes_field.place(x=550, y= 200)
    dst_bytes_range = Label(root, text="[0 - 516]")
    dst_bytes_range.place(x=680,y=200)


    cnt = Label(root, text="Count      ")
    cnt.place(x=400,y=400)
    cnt_field = Entry(root)
    cnt_field.place(x=550, y= 400)
    cnt_range = Label(root, text="[1-511]")
    cnt_range.place(x=680,y=400)


    dst_host_srv_cnt = Label(root, text="DST_Host_Srv_count      ")
    dst_host_srv_cnt.place(x=400,y=350)
    dst_host_srv_cnt_field = Entry(root)
    dst_host_srv_cnt_field.place(x=550, y= 350)
    dst_host_srv_cnt_range = Label(root, text="[1-255]")
    dst_host_srv_cnt_range.place(x=680,y=350)

    prd_icmp=Button(root, text="Predict", font=("Arial", 10), bd='5', width=15, command=udp_pred)
    prd_icmp.place(x=380, y= 460)

    home=Button(root, text='Back to Home', font=("Arial", 10), bd='5', width=15, command=clear_frame)
    home.place(x=620, y=460)

    
    
def sql_inject():
    global sql_field
    btn1.destroy()
    btn2.destroy()
    head = Label(root, text = "Paste the URL below to check for SQL Injection", font=("Arial", 12),fg='blue').place(x = 380, y = 160)
    sql_field = Entry(root, width=60)  
    sql_field.place(x=360, y= 210)
    sql_btn=Button(root, text='Check', font=("Arial", 10), bd='5', width=15, command=sql_pred)
    sql_btn.place(x=400, y= 240)
    home=Button(root, text='Back to Home', font=("Arial", 10), bd='5', width=15, command=clear_frame)
    home.place(x=620, y=240)

def sql_pred():
    st=sql_field.get()
    scan_sql_injection(st)



 
title = Label(root, text = "Web Attack Detection using Machine Learning", font=("Arial", 20),fg='red').place(x = 250, y = 60)
uline = Label(root, text = "---------------------------------------------------------------", font=("Arial", 20),fg='red').place(x = 250, y = 95)

btn1 = Button(root, text = 'DDoS Atach Detector', font=("Arial", 10), bd = '5', width=20, height=2, command = ddos_home)
btn2 = Button(root, text = "SQL Injection", bd='5', font=("Arial", 10), width=20, height=2, command=sql_inject)



btn1.place(x=300,y=200)
btn2.place(x=600,y=200)
main.mainloop()
