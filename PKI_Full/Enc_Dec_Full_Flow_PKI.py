import os

#Function to create and save Private and Public Key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def key_Generation(UserName):
    private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
    )
    
    public_key = private_key.public_key()

    # Storing the keys
    Private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
    )

    with open('keys/'+UserName+'_private_key.pem', 'wb') as f:
        f.write(Private_pem)
    print("Private key generated and saved for", UserName)
    
    Public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    with open('keys/'+UserName+'_public_key.pem', 'wb') as f:
        f.write(Public_pem)
    print("Public key generated and saved for", UserName)


def EncMsg(RName, Msg):
    with open('keys/'+RName+'_public_key.pem', "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read(),backend=default_backend())
    
    EncMsg = public_key.encrypt(
    Msg,
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),label=None))
    return EncMsg

def DecMsg(RName, EncMsg):
    with open('keys/'+RName+'_private_key.pem', "rb") as key_file:
        private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend())

    DecMsg = private_key.decrypt(
    EncMsg,
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),label=None))
    return DecMsg

def EncFile(RName,OrgFilePath):
    #FDetails = os.path.split(os.path.abspath(OrgFilePath))
    #print(FDetails[0]+'/')
    #print(FDetails[1])
    f = open(OrgFilePath, 'rb')
    FileContent = f.read()
    f.close()
    #print("File Content ---------",FileContent)
    with open('keys/'+RName+'_public_key.pem', "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read(),backend=default_backend())
        
    File_encrypted = public_key.encrypt(
    FileContent,
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),label=None))
    #print(File_encrypted)
    #rootPath = FDetails[0]
    #fName = os.path.splitext(FDetails[0])
    #f = open(os.path.splitext(OrgFilePath)[0]+'.encrypted', 'wb')
    f = open(os.path.splitext(OrgFilePath)[0]+'.Harsha', 'wb')
    f.write(File_encrypted)
    f.close()
    DecFile('Swati',os.path.splitext(OrgFilePath)[0]+'.Harsha')

def DecFile(RName,EncFilePath):
    f = open(EncFilePath, 'rb')
    EncContent = f.read()
    f.close()
    
    with open('keys/'+RName+'_private_key.pem', "rb") as key_file:
        private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend())
    
    original_message = private_key.decrypt(
    EncContent,
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),label=None))

    f = open(os.path.splitext(EncFilePath)[0]+'_Dec.txt', 'wb')
    f.write(original_message)
    f.close()


# using the while loop to print menu list  
while True:
    print("\n\n\nWELCOME TO A SAILANDRA PKI Implimentation")  
    print("\nMENU")
    print("1. Generate Private and Public keys")
    print("2. Choose Sender and Receiver")
    print("3. Encrypt and Decrypt Message")
    print("4. Encrypt and Decrypt File")
    print("5. Clear Screen")
    print("6. Exit")
    choice = int(input("\nEnter the Choice: "))

    # using if-elif-else statement to pick different options
    if choice == 1:
        print( "\nGenerate Private and Public keys\n")
        UserName = input("Enter username:")
        if (os.path.exists('keys/'+UserName+'_private_key.pem') == False):
            key_Generation(UserName)

    elif choice == 2:  
        print( "\nChoose Sender and Receiver\n")
        SenderName = input("Enter username:")
        ReceiverName = input("Enter username:")
        if (os.path.exists('keys/'+SenderName+'_private_key.pem') == False):
            key_Generation(SenderName)
        if (os.path.exists('keys/'+ReceiverName+'_private_key.pem') == False):
            key_Generation(ReceiverName)
  
    elif choice == 3:
        print( "\nEncrypt and Decrypt Message\n")
        SenderName = input("Enter sender username:")
        ReceiverName = input("Enter receiver username:")
        if (os.path.exists('keys/'+SenderName+'_private_key.pem') == False):
            key_Generation(SenderName)
        if (os.path.exists('keys/'+ReceiverName+'_private_key.pem') == False):
            key_Generation(ReceiverName)
        
        Msg = input("Enter message from "+ SenderName+" : ")
        print("Orignal Message: ",Msg)
        EncMsg = EncMsg(ReceiverName, Msg.encode('utf-8'))
        print("Enc Msg: ",EncMsg)
        DecMsg = DecMsg(ReceiverName, EncMsg)
        print("Dec Msg: ",DecMsg)

    elif choice == 4:  
        print( "\nEncrypt and Decrypt Message\n")
        SenderName = input("Enter sender username:")
        ReceiverName = input("Enter receiver username:")
        if (os.path.exists('keys/'+SenderName+'_private_key.pem') == False):
            key_Generation(SenderName)
        if (os.path.exists('keys/'+ReceiverName+'_private_key.pem') == False):
            key_Generation(ReceiverName)
        
        OrgFilePath = input("Enter file path sent from "+ SenderName+" to "+ ReceiverName+" : ")
        EncFilePath = EncFile(ReceiverName, OrgFilePath)
        #print("File Encrypted and saved at : ",EncFilePath)
        #DecFilePath = DecFile(ReceiverName, EncFilePath)
        #print("File Decrypted and saved at : ",DecFilePath)

    elif choice == 5:
        os.system('clear')
  
    elif choice == 6:
        break  
      
    else:  
        print( "Please Provide a valid Input!") 








