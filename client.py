# Import socket module 
import socket, threading
import time as TIME
import hashlib
import random
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import base64
from Crypto.Cipher import AES


###############################################################################################
def makeMessageMulti16(msg):
    length = len(msg)
    
    while length > 16:
        length=length-16
    length=16-length
    
    for index in range(0,length):
        msg=msg+'\x00'.encode()
    
    return msg
def returnMessageSize(msg):
    last_char = msg[len(msg)-1:len(msg)]
    while last_char == '\x00'.encode():
        msg=msg[:len(msg)-1]
        last_char = msg[len(msg)-1:len(msg)]
    return msg
def encryptMessage(msg, client_pri, server_pub):
    msg=makeMessageMulti16(msg)
    aes = AES.new(client_pri, AES.MODE_CBC, server_pub)
    encd = aes.encrypt(msg)
    return encd
def decryptMessage(msg, client_pri, server_pub):
    aes = AES.new(client_pri, AES.MODE_CBC, server_pub)
    decd = aes.decrypt(msg)
    plaintext=returnMessageSize(decd)

    return plaintext



token=b'\x00\x00\x00\x00'

logged_out=False
useless=True

class ServerThread(threading.Thread):
    def __init__(self,clientAddress,clientsocket, actualsocket, client_pub, client_pri):
        threading.Thread.__init__(self)
        self.csocket = clientsocket
        self.host = clientAddress
        self.csocket = actualsocket
        self.tokennn=b'\x00\x00\x00\x00'
        self.lastMessage=''
        self.first_message=True
        self.good_message = False
        self.client_pub = client_pub
        self.client_pri = client_pub
        self.server_pub = client_pub
        
         

    def run(self):
        magicnumber1 = "R".encode()
        magicnumber2 = "C".encode()
        while(1):
            in_data = ''
            in_data = self.csocket.recv(4096)
            if self.first_message:#first message is the server public key
                
                self.good_message =True
                self.first_message=False
                self.server_pub = in_data
                #print("server public key")
                #print(self.server_pub)
                continue

            else:
                
                in_data = decryptMessage(in_data, self.client_pri, self.server_pub)
                
                self.good_message = True
                
            #print(self.good_message)
            if self.good_message:
                magicnumbers = in_data[:2].decode()
                in_opcode=bytes([in_data[2]])
                #print("this is opcode", str(in_opcode))


                if in_opcode == b'\x80' and magicnumbers[0]=="R" and magicnumbers[1]=="C":
                    print("login_ack#successful")
                    #print("saving this token to self.token", in_data[4:])
                    self.tokennn=in_data[4:]
                    #print(self.token,"result")
                    #print("saving this token to gloabl token", in_data[4:])
                    token=in_data[4:]
                    #print(token,"result")
                elif in_opcode==b'\x81':
                    print("login_ack#failed")

                elif in_opcode == b'\xB0' and magicnumbers[0]=="R" and magicnumbers[1]=="C":
                    print("post_ack#successful")
                
                elif in_opcode == b'\x90' and magicnumbers[0]=="R" and magicnumbers[1]=="C":
                    print("subscribe_ack#successful")

                elif in_opcode == b'\x91' and magicnumbers[0]=="R" and magicnumbers[1]=="C":
                    print("subscribe_ack#failed")

                

                elif in_opcode == b'\xA0' and magicnumbers[0]=="R" and magicnumbers[1]=="C":
                    print("unsubscribe_ack#successful")

                elif in_opcode == b'\xA1' and magicnumbers[0]=="R" and magicnumbers[1]=="C":
                    print("unsubscribe_ack#failed")

                

                elif in_opcode == b'\xC0' and magicnumbers[0]=="R" and magicnumbers[1]=="C":
                    times_to_read = in_data[3]
                    sub_message = in_data[8:].decode()
                    print(sub_message)

                elif in_opcode == b'\xC1' and magicnumbers[0]=="R" and magicnumbers[1]=="C":
                    times_to_read =in_data[3]
                    sub_message = in_data[8:].decode()
                    print(sub_message)

                elif in_opcode == b'\xB1' and magicnumbers[0]=="R" and magicnumbers[1]=="C":
                    #new_message = magicnumber1 + magicnumber2 + b'\x00' + b'\x31' + self.tokennn 
                    #self.csocket.sendall(new_message)
                    #times_to_read =in_data[3]
                    sub_message = in_data[8:].decode()
                    print(sub_message)

                elif in_opcode == b'\x8F' and magicnumbers[0]=="R" and magicnumbers[1]=="C":
                    print("Logging you out!")
                    client.close()
                    exit()


                elif in_opcode==b'\xF0':
                    print("error#must_login_first")
                else:
                    useless=True
                self.lastMessage=in_data
            
                        
            

    
SERVER = "127.0.0.1"
PORT = 8080
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((SERVER, PORT))
public_key = random.getrandbits(128)
public_key=public_key.to_bytes(16, 'little')
private_key = public_key


newthread = ServerThread(SERVER, PORT, client, public_key, private_key)
newthread.start()
magicnumber1 = "R".encode()
magicnumber2 = "C".encode()
client.sendall(public_key)
#print(public_key)
#client.sendall(bytes("This is from Client",'UTF-8'))
while True:
    token=newthread.tokennn
    #print("From Server :" ,in_data.decode())
    msg=''
    out_data = input()
    #print(str(token))
    if 'login#' in out_data[:6]:
        if '$' in out_data[6:]:
            
            (user, password) = out_data[6:].split('$')
            
            m = hashlib.md5()
            m.update(password.encode())
            hashvalue = m.hexdigest()
            

            opcode = b'\x01'
            userpassword = user + '$' + str(hashvalue)
            
            msg =magicnumber1 + magicnumber2 +opcode+ str(len(out_data)).encode() + userpassword.encode()
            msg = encryptMessage(msg, public_key, newthread.server_pub)
            #print("encrypted message")
            #print(msg)
            
            client.sendall(msg)

        

    elif 'post#' in out_data[:5]:
        opcode= b'\x30'
        post =out_data[5:]
        #print(post)

        msg =magicnumber1 + magicnumber2 +opcode+ bytes([len(post)]) +token+ post.encode() 
        msg = encryptMessage(msg, public_key, newthread.server_pub)
        client.sendall(msg)
        
        
    elif 'subscribe#' in out_data[:10]:
        opcode= b'\x20'
        subto =out_data[10:]
        #print(post)

        msg =magicnumber1 + magicnumber2 +opcode+ bytes([len(subto)]) +token+ subto.encode() 
        msg = encryptMessage(msg, public_key, newthread.server_pub)
        client.sendall(msg)
       
    elif 'unsubscribe#' in out_data[:12]:
        opcode= b'\x21'
        unsubto =out_data[12:]
        #print(post)

        msg =magicnumber1 + magicnumber2 +opcode+ bytes([len(unsubto)]) +token+ unsubto.encode() 
        msg = encryptMessage(msg, public_key, newthread.server_pub)
        client.sendall(msg)
        
    elif 'retrieve#' in out_data[:9]:
        opcode= b'\x40'
        n = out_data[9:]
        isNumber = False
        try:
            number_of_times = int(n)
            isNumber = True
        except:
            pass
        if isNumber:
            msg = magicnumber1+ magicnumber2 + opcode+ b'\x00'+ token+ n.encode()
            msg = encryptMessage(msg, public_key, newthread.server_pub)
            client.sendall(msg)

        else:
            print("Must input a number at the end of retrieve#, try again")

    elif 'logout#' in out_data[:7]:
        opcode= b'\x1F'
        msg= magicnumber1+magicnumber2+opcode+b'\x00'+token
        logged_out = True
        msg = encryptMessage(msg, public_key, newthread.server_pub)
        client.sendall(msg)
        
        
    elif '&&&RESET&&&' in out_data[:11]:
        print("Calling for Session Reset!")
        opcode= b'\x00'
        msg= magicnumber1+magicnumber2+opcode+b'\x00'+token
        logged_out = True
        msg = encryptMessage(msg, public_key, newthread.server_pub)
        client.sendall(msg)
    TIME.sleep(.5)
            