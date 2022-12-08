from tkinter import *   
import joblib

l_model = joblib.load('model/icmp_new.ml')


            
root = Tk()             
root.geometry('1080x600')


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
    icmp.destroy()
    tcp.destroy()
    udp.destroy()
    head = Label(root, text = "Fill the below values to test {ICMP PROTOCOL}", font=("Arial", 12),fg='blue')
    head.place(x = 390, y = 160)

    duration = Label(root, text="Duration            :")
    duration.place(x=400,y=200)
    duration_field = Entry(root)
    duration_field.place(x=550, y= 200)

    service = Label(root, text="Service            :")
    service.place(x=400,y=440)
    service_options = ["eco_i","ecr_i","tim_i","urp_i"]
    service_field = StringVar()
    service_field.set( "Select the Service")
    service_drop = OptionMenu( root , service_field , *service_options )
    service_drop.place(x=550, y=440)

    wrong_frag = Label(root, text="Wrong Fragmentation      :")
    wrong_frag.place(x=400,y=490)
    wrong_frag_options = [0,1]
    wrong_frag_field = StringVar()
    wrong_frag_field.set( "Select the option")
    wrong_frag_drop = OptionMenu( root , wrong_frag_field , *wrong_frag_options )
    wrong_frag_drop.place(x=550, y=490)

    srcbytes = Label(root, text="Src_Bytes           :")
    srcbytes.place(x=400,y=240)
    srcbytes_field = Entry(root)
    srcbytes_field.place(x=550, y= 240)


    cnt = Label(root, text="Count     :")
    cnt.place(x=400,y=280)
    cnt_field = Entry(root)
    cnt_field.place(x=550, y= 280)
    cnt_range = Label(root, text="[1-511]")
    cnt_range.place(x=680,y=280)


    urgent = Label(root, text="Urgent       :")
    urgent.place(x=400,y=320)
    urgent_field = Entry(root)
    urgent_field.place(x=550, y= 320)
    urgent_range = Label(root, text="Always '0'")
    urgent_range.place(x=680,y=320)


    num_cmp = Label(root, text="Num Compromised   :")
    num_cmp.place(x=400,y=360)
    num_cmp_field = Entry(root)
    num_cmp_field.place(x=550, y= 360)
    num_cmp_range = Label(root, text="Always '0'")
    num_cmp_range.place(x=680,y=360)


    srv_cnt = Label(root, text="Srv_count     :")
    srv_cnt.place(x=400,y=400)
    srv_cnt_field = Entry(root)
    srv_cnt_field.place(x=550, y= 400)
    srv_cnt_range = Label(root, text="[1-511]")
    srv_cnt_range.place(x=680,y=400)


def icmp_pred():
    service_d={"eco_i":-0.1,"ecr_i":0.0, "tim_i":0.1, "urp_i":0.2}
    wrong_frag_d={'yes':1,'no':0}
    ft_l=[duration_field.get(), service_d[service_field.get()], srcbytes_field.get(), wrong_frag_d[wrong_frag_field.get()], cnt_field.get(), urgent_field.get(), num_cmp_field.get(), srv_cnt_field.get()] 
    l=l_model.predict([ft_l])
    print(l)


def tcp_form():
    icmp.destroy()
    tcp.destroy()
    udp.destroy()
    head = Label(root, text = "Fill the below values to test TCP_SYNC Protocol", font=("Arial", 12),fg='black').place(x = 380, y = 160)

def udp_form():
    icmp.destroy()
    tcp.destroy()
    udp.destroy()
    head = Label(root, text = "Fill the below values to test UDP Protocol", font=("Arial", 12),fg='blue').place(x = 380, y = 160)
    
    
 
title = Label(root, text = "Web Attack Detection using Machine Learning", font=("Arial", 20),fg='red').place(x = 250, y = 60)
uline = Label(root, text = "---------------------------------------------------------------", font=("Arial", 20),fg='red').place(x = 250, y = 95)

btn1 = Button(root, text = 'DDoS Atach Detector', font=("Arial", 10), bd = '5', width=20, height=2, command = ddos_home)
btn2 = Button(root, text = "SQL Injection", bd='5', font=("Arial", 10), width=20, height=2)



btn1.place(x=300,y=200)
btn2.place(x=600,y=200)
root.mainloop()
