import socket, threading
import random
import time as TIME
from datetime import datetime
in_production=False
useless = True
import copy
import hashlib
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from Crypto.Cipher import AES
import sqlite3

userList=[]
sessionList={}#stores the usernames given the [token]
posts={}#dictionary of queues given [username]
lastAction={}#dictionary that gives the time of last post/retrieve request given[username]
subscriptions={}#sictionary that gives list of usernames the client is subscribed to given [username]
subscribers={}#dictionary that gives a list of usernames of the subscribers to the given [username] client
thread_dict = []#ductionary that takes in a username and gives a thread



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

def attemptToLogin(user, password):
    con = sqlite3.connect('ass4.db')
    c=con.cursor()
    temp =c.execute("SELECT * FROM users WHERE name=? ", (user,) )
    row=c.fetchall()
    c.close()
    try:
        _user, _pass = row[0]
        return (_user==user and password==_pass)
    except:
        
        return False

        
    

def encryptMessage(msg, client_pri, server_pub):
    msg=makeMessageMulti16(msg)
    aes = AES.new(server_pub, AES.MODE_CBC, client_pri)
    encd = aes.encrypt(msg)
    return encd
def decryptMessage(msg, client_pri, server_pub):
    aes = AES.new(server_pub, AES.MODE_CBC, client_pri)
    decd = aes.decrypt(msg)
    #print("this is",decd)
    plaintext=returnMessageSize(decd)
    return plaintext
def removeOtherSessionTokens(user):
    for (token, suser) in sessionList.items():
        if user==suser:
            try:
                sessionList.remove(token)
            except:
                pass
def getMsgStack( user):
    try: 
        stack = posts[user]
        return stack
    except:
        stack=[]
        return stack
def getSubList(user):
    try:
        sublist=subscriptions[user]
        return sublist
    except:
        sublist=[]
        return sublist
def getSubscriberList(username):
    con = sqlite3.connect('ass4.db')
    c=con.cursor()
    temp = c.execute('SELECT * FROM subscriptions WHERE subcribedTo=?', (username,))
    rows = c.fetchall()
    sublist=[]
    for row in rows:
        sublist.append(row[0])
    #print(sublist)
    return sublist

def getSubscriptionList(username):
    con = sqlite3.connect('ass4.db')
    c=con.cursor()
    temp = c.execute('SELECT * FROM subscriptions WHERE name=?', (username,))
    rows = c.fetchall()
    sublist=[]
    for row in rows:
        sublist.append(row[1])
    #print(sublist)
    return sublist





def subscribeTo(usernameclient, sub):
    con = sqlite3.connect('ass4.db')
    c=con.cursor()
    #check that sub is valid username
    temp =c.execute("SELECT count(name) FROM users WHERE name=? ", (sub,) )
    row=c.fetchall()

    value = row[0][0]
    
    if row[0][0]==1:
        #are they already subscribed?
        temp=c.execute('SELECT count(name) FROM subscriptions WHERE name=? AND subcribedTo=?', (usernameclient, sub,) )
        row=c.fetchall()
        
        if row[0][0]!=1:
            c.execute('INSERT INTO subscriptions (name, subcribedTo) VALUES(?,?)', (usernameclient, sub,))
            con.commit()
            #print("added it to the subscriber list")
            c.close()
            return True
        else:
            #print("already subscribed to this user")
            c.close()
            return False
    else:
        #print("subto user not found")
        c.close()
        return False


def unsubscribeTo(usernameclient, sub):
    con = sqlite3.connect('ass4.db')
    c=con.cursor()
    #check that sub is valid username
    temp =c.execute("SELECT count(name) FROM users WHERE name=? ", (sub,) )
    row=c.fetchall()

    value = row[0][0]
    
    if row[0][0]==1:
        #where they never subscribed?
        temp=c.execute('SELECT count(name) FROM subscriptions WHERE name=? AND subcribedTo=?', (usernameclient, sub,) )
        row=c.fetchall()
        
        if row[0][0]==1:
            c.execute('DELETE FROM subscriptions WHERE name=? AND subcribedTo=?', (usernameclient, sub,))
            con.commit()
            #print("removed it to the subscriber list")
            c.close()
            return True
        else:
            #print("not previously subscribed to this user")
            c.close()
            return False
    else:
        #print("subto user not found")
        c.close()
        return False

def postMessage(user,msg, date):
    con = sqlite3.connect('ass4.db')
    c=con.cursor()
    print(date)
    #make sure that this user exists
    temp =c.execute('SELECT count(name) FROM users WHERE name=?', (user,))
    row=c.fetchall()
    #print(row[0][0])
    if row[0][0]==1:
        c.execute('INSERT INTO posts (poster, message, date) VALUES(?,?,?)', (user, msg, date,))
        #print("message posted")
        con.commit()
    c.close()
        

def querryRecentPosts(username, num):
    con = sqlite3.connect('ass4.db')
    c=con.cursor()
    temp =c.execute('SELECT count(name) FROM users WHERE name=?', (username,))
    row=c.fetchall()
    if row[0][0]==1:
        sublist = getSubscriptionList(username)
        #print(sublist)
        posts=[]
        temp =c.execute('SELECT * FROM posts WHERE poster IN (SELECT subcribedTo FROM subscriptions WHERE name=?) ORDER BY date DESC', (username,))
        

        rows = c.fetchall()
        for row in rows:
            posts.append((row[0],row[1]))
            #print(row[0], row[1])
        
        return posts[:num]



        
    else:
        return -1


def getRecentPosts(username, n):
    sublist = getSubList(username)
    if sublist == []:
        return -1
    else:
        postlist =[]
        for user in sublist:
            posts=getMsgStack(user)
            if not posts==[]:
                for (message, timee) in posts:
                    postlist.append((message, timee, user))
        sortedlist = sorted(postlist, key=lambda L: L[1])#this gets all the posts that the user is subs ribed to and sorts them based on first to latest,
        #thats why we need to reverse them
        sortedlist.reverse()
        if len(sortedlist)<n:
            return sortedlist
        else:
            return sortedlist[:n]

def getUser(clientToken):
    username=''
    try:
        username=sessionList[clientToken]
    except:
        pass
    return username
def generateSessionToken():
    temp = random.getrandbits(32)
    token=temp.to_bytes(4, 'little')
    return token
def isUserSessionActive( user):

    try:
        lasttime = lastAction[user]
        
        currtime = datetime.now()
        
        difference = currtime-lasttime
        (minutes, seconds)=divmod(difference.days*86400+difference.seconds,60)
        #print("minutes:",minutes,"seconds:", seconds)
        if minutes ==0:
            return 1
        else:
            #print("removing other sessions")
            removeOtherSessionTokens(user)
            return 0
    except:
        #print("session not found")
        return 0
def getclientaddress(username):
    for thread in thread_dict:
        if thread.lastUser==username:
            return thread.csocket
def getkey(username):
    for thread in thread_dict:
        if thread.lastUser==username:
            return (thread.client_pub, thread.server_pri)
    
def isValidSubscription(user):
    for (fuser, fpassword) in userList:
        if fuser==user:
            return 1
    return 0
class ClientThread(threading.Thread):
    def __init__(self,clientAddress,clientsocket,counter,server_pub, server_pri):
        threading.Thread.__init__(self)
        self.csocket = clientsocket
        self.host = clientAddress
        self.thread_index=counter
        self.lastUser=''
        self.server_pub =server_pub
        self.server_pri =server_pub
        self.client_pub =server_pub
        self.first_message=True
        
    def sendMessage(msg):
        self.csocket.send(msg)

    def run(self):
        msg = ''
        while True:
            data = self.csocket.recv(4096)
            if self.first_message:
                self.first_message= False
                self.client_pub = data
                self.csocket.send(self.server_pub)
                #print("this is server pub")
                #print(self.server_pub)
                #print("this is client pub")
                #print(self.client_pub)

                continue
            else:
                
                #print("original message")
                #print(data)
                
                data = decryptMessage(data, self.server_pri, self.client_pub)
                #print(data)
            msg = data[:2].decode()
            magicnum1= msg[0]
            magicnum2= msg[1]
            opcode = bytes([data[2]])
            #print("opcode is:",opcode)
            if magicnum1=="R" and magicnum2=="C":
                
                if b'\x01' == opcode:#LOGIN
                    temp = data[5:].decode()
                    
                    if '$' in temp:
                        (user, password) = temp.split('$')
                        
                        if attemptToLogin(user, password):
                            loggedin=generateSessionToken()
                            removeOtherSessionTokens(user)
                            sessionList[loggedin]=user

                            #start timer for session?
                            out_opcode=b'\x80'
                            out_message=magicnum1.encode()+magicnum2.encode()+out_opcode+b'\x00'+loggedin
                            
                            lastAction[user]=datetime.now()
                            self.lastUser = user
                            out_message = encryptMessage(out_message, self.server_pri, self.client_pub)
                            self.csocket.send(out_message)
                            
                        else:
                            out_opcode=b'\x81'
                            out_message=magicnum1.encode()+magicnum2.encode()+out_opcode+b'\x00'
                            out_message = encryptMessage(out_message, self.server_pri, self.client_pub)
                            self.csocket.send(out_message)
                            
                    else:
                        out_opcode=b'\x81'
                        out_message=magicnum1.encode()+magicnum2.encode()+out_opcode+b'\x00'
                        out_message = encryptMessage(out_message, self.server_pri, self.client_pub)
                        self.csocket.send(out_message)
                
                if b'\x30'==opcode:#POST
                    clientToken=data[4:8]
                    sessionBool=0
                    
                    username=getUser(clientToken)
                    
                    if not username=='' and isUserSessionActive(username):
                        sessionBool=1
                    if sessionBool==1:
                        post_message=data[8:].decode()
                        
                        """
                        stack=getMsgStack(username)
                        stack.append((post_message, datetime.now() ))
                        posts[username]=stack
                        """
                        postMessage(username,post_message, datetime.now())
                        
                        
                        ###############Send to subscribers!!
                        subscribersList = getSubscriberList(username)
                        if subscribersList != []:
                            
                            for sub in subscribersList:
                                #print("checking")
                                #check that the user is online
                                if isUserSessionActive(sub):
                                    #print(sub,"is online! about to send them their forward")
                                    clientsocket = getclientaddress(sub)
                                    tempstr = '<' + username + '>'+ post_message
                                    out_message = magicnum1.encode()+magicnum2.encode()+b'\xB1'+ b'\x00'+clientToken+ tempstr.encode()
                                    #print(out_message)
                                    clientkey, serverkey = getkey(sub)
                                    out_message = encryptMessage(out_message, serverkey, clientkey)
                                    #print(out_message)
                                    #print(decryptMessage(out_message, serverkey, clientkey))
                                    clientsocket.send(out_message)
                            #print("donee")
                        else:
                            useless=True     



                        ##########
                        out_opcode=b'\xB0'
                        out_message=magicnum1.encode()+magicnum2.encode()+out_opcode+b'\x00'+clientToken
                        lastAction[username]=datetime.now()
                        out_message = encryptMessage(out_message, self.server_pri, self.client_pub)
                        self.csocket.send(out_message)
                        

                    else:
                        
                        out_opcode=b'\xF0'
                        out_message=magicnum1.encode()+magicnum2.encode()+out_opcode+b'\x00'
                        out_message = encryptMessage(out_message, self.server_pri, self.client_pub)
                        self.csocket.send(out_message)
                
                if b'\x20'==opcode:#SUBCRIBE
                    clientToken=data[4:8]
                    sessionBool=0
                    username=getUser(clientToken)
                    if not username=='' and isUserSessionActive(username):
                        sessionBool=1
                    
                    if sessionBool==1:
                        subto=data[8:].decode()
                        #subList is a temp list representative of this client's subscriptions
                        sublist = getSubList(username)
                        
                        if subscribeTo(username, subto):
                            
                            out_opcode=b'\x90'
                            out_message=magicnum1.encode()+magicnum2.encode()+out_opcode+b'\x00'+clientToken
                            lastAction[username]=datetime.now()
                            out_message = encryptMessage(out_message, self.server_pri, self.client_pub)
                            self.csocket.send(out_message)
                        else:
                            
                            out_opcode=b'\x91'
                            out_message=magicnum1.encode()+magicnum2.encode()+out_opcode+b'\x00'+clientToken
                            lastAction[username]=datetime.now()
                            out_message = encryptMessage(out_message, self.server_pri, self.client_pub)
                            self.csocket.send(out_message)

                        
                    else:
                        out_opcode=b'\xF0'
                        out_message=magicnum1.encode()+magicnum2.encode()+out_opcode+b'\x00'
                        out_message = encryptMessage(out_message, self.server_pri, self.client_pub)
                        self.csocket.send(out_message)
                if b'\x21'==opcode:#UNSUB
                    clientToken=data[4:8]
                    sessionBool=0
                    username=getUser(clientToken)
                    if not username=='' and isUserSessionActive(username):
                        sessionBool=1
                    
                    if sessionBool==1:
                        unsubto=data[8:].decode()
                        sublist = getSubList(username)
                        #print(sublist)
                        #print(isValidSubscription(unsubto))
                        if unsubscribeTo(username, unsubto):

                            out_opcode=b'\xA0'
                            out_message=magicnum1.encode()+magicnum2.encode()+out_opcode+b'\x00'+clientToken
                            lastAction[username]=datetime.now()
                            out_message = encryptMessage(out_message, self.server_pri, self.client_pub)
                            self.csocket.send(out_message)
                        else:
                            
                            out_opcode=b'\xA1'
                            out_message=magicnum1.encode()+magicnum2.encode()+out_opcode+b'\x00'+clientToken
                            lastAction[username]=datetime.now()
                            out_message = encryptMessage(out_message, self.server_pri, self.client_pub)
                            self.csocket.send(out_message)

                        
                    else:
                        out_opcode=b'\xF0'
                        out_message=magicnum1.encode()+magicnum2.encode()+out_opcode+b'\x00'
                        out_message = encryptMessage(out_message, self.server_pri, self.client_pub)
                        self.csocket.send(out_message)
                if b'\x40'==opcode:#RETRIEVE
                    clientToken=data[4:8]
                    sessionBool=0
                    username=getUser(clientToken)
                    if not username=='' and isUserSessionActive(username):
                        sessionBool=1
                    
                    if sessionBool==1:
                        number = int(data[8:].decode())
                        '''
                        messagelist=getRecentPosts(username, number)
                        '''
                        messagelist = querryRecentPosts(username, number)
                        if messagelist ==-1:
                            useless=True
                        else:
                            variable_length = len(messagelist)
                            out_opcode=b'\xC0'
                            for (usern, msg) in messagelist:
                                if variable_length == 1:
                                    out_opcode=b'\xC1'
                                tempstr = '<' + usern + '> '+ msg
                                out_message=magicnum1.encode()+magicnum2.encode()+out_opcode+b'\x00'+clientToken + tempstr.encode()
                                variable_length =variable_length-1
                                out_message = encryptMessage(out_message, self.server_pri, self.client_pub)
                                self.csocket.send(out_message)
                                TIME.sleep(.5)
                        
                    else:
                        out_opcode=b'\xF0'
                        out_message=magicnum1.encode()+magicnum2.encode()+out_opcode+b'\x00'
                        out_message = encryptMessage(out_message, self.server_pri, self.client_pub)
                        self.csocket.send(out_message)
                if b'\x1F' ==opcode:#LOGOUT
                    clientToken=data[4:8]
                    sessionBool=0
                    username=getUser(clientToken)
                    if not username=='':
                        
                        removeOtherSessionTokens(username)
                        out_opcode=b'\x8F'
                        out_message=magicnum1.encode()+magicnum2.encode()+out_opcode+b'\x00'+clientToken
                        
                        out_message = encryptMessage(out_message, self.server_pri, self.client_pub)
                        self.csocket.send(out_message)
                        break
                    else:
                        out_opcode=b'\xF0'
                        out_message=magicnum1.encode()+magicnum2.encode()+out_opcode+b'\x00'
                        out_message = encryptMessage(out_message, self.server_pri, self.client_pub)
                        self.csocket.send(out_message)
                        break
                if b'\x31'==opcode:#forward ack
                    useless = True
                if b'\x00'==opcode:#Reset
                    print("Session Reset")
                    sessionList.clear()#stores the usernames given the [token]
                    posts.clear()#dictionary of queues given [username]
                    lastAction.clear()#dictionary that gives the time of last post/retrieve request given[username]
                    subscriptions.clear()#sictionary that gives list of usernames the client is subscribed to given [username]
                    subscribers.clear()#dictionary that gives a list of usernames of the subscribers to the given [username] client
                
                    





            #self.csocket.send(bytes(msg,'UTF-8'))
        print ("Client at ", clientAddress , " disconnected...")
LOCALHOST = "127.0.0.1"
PORT = 8080
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((LOCALHOST, PORT))
print("Epic Server Started")
#################################################
#sql stuff
con = sqlite3.connect('ass4.db')
c=con.cursor()
c.execute(''' SELECT count(name) FROM sqlite_master WHERE type='table' AND name='users' ''')
if c.fetchone()[0]!=1:
    c.execute("CREATE TABLE users(name TEXT, password TEXT)")
    c.execute("CREATE TABLE posts(poster TEXT, message TEXT, date DATE)")
    c.execute("CREATE TABLE subscriptions(name TEXT, subcribedTo TEXT)")
    con.commit()
    c.execute("INSERT INTO users VALUES('robert', 'd5b1ee4b463dc7db3b0eaaa0ea2cb5b4' )")
    c.execute("INSERT INTO users VALUES('niceguy21', 'b3cd49636247ac076967a363360e1e8d')")
    c.execute("INSERT INTO users VALUES('cutie42', '0782efd61b7a6b02e602cc6a11673ec9')")
    con.commit()
    print("database created")




#password hashed
#robert ->    d5b1ee4b463dc7db3b0eaaa0ea2cb5b4
#niceguy21 -> b3cd49636247ac076967a363360e1e8d
#cutie42 ->   0782efd61b7a6b02e602cc6a11673ec9


"""
#################################################
#passwordstoring into memory
F = open("secrets.txt", "r")
for line in F:
    (fuser,fpassword)=line.split('%')
    if '\n' in fpassword:
        fpassword =fpassword.split('\n')[0]
    userList.append((fuser, fpassword))      
F.close()
#################################################
"""
counter = 0

while True:
    server.listen(1)
          
    clientsock, clientAddress = server.accept()
    private_key = random.getrandbits(128)
    private_key=private_key.to_bytes(16, 'little')
    public_key = random.getrandbits(128)
    public_key=public_key.to_bytes(16, 'little')

    newthread = ClientThread(clientAddress, clientsock,counter, public_key, private_key)
    thread_dict.append(newthread)
    newthread.start()
    counter=counter+1

conn.close()