#!/usr/bin/env python3

from __init__ import *


def derive_key_and_iv(password, key_length=16, iv_length=16):
    """
    This function will give you a deterministic "key" and "iv" for a
    given password.
    """
    password_ = password.encode('utf8')
    d = hashlib.sha256(password_).digest()
    return d[:key_length], d[key_length:key_length + iv_length]


def encryptCredentials(User_cred_, out_file_, PWD_):
    """
    Encrypts "User_cred_" (UserCredentials type object) with password
    "PWD_" in "out_file_".
    """
    bs_ = 128
    key_, iv_ = derive_key_and_iv(PWD_)
    aes_mode_ = AES.MODE_CBC
    encryptor = AES.new(key_, aes_mode_, iv_)
    with open(out_file_, 'wb') as File_:
        for key_cred_, value_cred_ in User_cred_.self().items():
            ending_ = b''
            for i in range(bs_ - len(key_cred_)):
                ending_ += b'\x00'
            key_cred_ = key_cred_.encode('utf8')
            File_.write(encryptor.encrypt(key_cred_ + ending_))
            ending_ = b''
            for i in range(bs_ - len(value_cred_)):
                ending_ += b'\x00'
            value_cred_ = value_cred_.encode('utf8')
            File_.write(encryptor.encrypt(value_cred_ + ending_))
    return 0


def decryptCredentials(in_file_, PWD_):
    """
    Decrypts "in_file_" with password "PWD_" and returns a
    UserCredentials type object.
    """
    bs_ = 128
    key_, iv_ = derive_key_and_iv(PWD_)
    aes_mode_ = AES.MODE_CBC
    decryptor = AES.new(key_, aes_mode_, iv_)
    with open(in_file_, 'rb') as File_:
        User_cred_ = UserCredentials()
        while True:
            chunk = decryptor.decrypt(File_.read(bs_))
            if chunk:
                break
            key_cred_ = chunk.decode('utf8').replace('\x00', '')
            chunk = decryptor.decrypt(File_.read(bs_))
            value_cred_ = chunk.decode('utf8').replace('\x00', '')
            User_cred_.addUser(key_cred_, True, value_cred_)
    return User_cred_


def encryptUserCredentials(text_, out_file_, PWD_):
    """
    Encrypts "text_" (with maximum length of 128) in "out_file" with
    password "PWD_"
    """
    bs_ = 128
    key_, iv_ = derive_key_and_iv(PWD_)
    aes_mode_ = AES.MODE_CBC
    encryptor = AES.new(key_, aes_mode_, iv_)
    with open(out_file_, 'wb') as File_:
        ending_ = b''
        for i in range(bs_ - len(text_)):
            ending_ += b'\x00'
        key_cred_ = text_.encode('utf8')
        File_.write(encryptor.encrypt(key_cred_ + ending_))

@try_except
def decryptUserCredentials(in_file_, PWD_):
    """
    Decrypts "in_file" using password "PWD_" and returns a text file
    of maximum 128 character long.
    """
    bs_ = 128
    key_, iv_ = derive_key_and_iv(PWD_)
    aes_mode_ = AES.MODE_CBC
    decryptor = AES.new(key_, aes_mode_, iv_)
    with open(in_file_, 'rb') as File_:
        chunk = decryptor.decrypt(File_.read(bs_))
        text_ = chunk.decode('utf8').replace('\x00', '')
    return text_


class UserCredentials():
    def __init__(self):
        self.__dict__ = {}

    def Configure(self):
        pass

    def self(self):
        return self.__dict__

    def addUser(self, id_, admin_=False, pwd_hash_=None):
        if(pwd_hash_ is not None):
            self.__dict__[id_] = pwd_hash_
            return 0
        if(admin_):
            id_ = input(bcolors.OKBLUE +
                        "Enter a new username: " + bcolors.ENDC)
            if(id_ not in self.__dict__):
                tmp_password_ = ''.join(
                    [random.choice(string.ascii_letters + string.digits) for n in range(8)])
                self.__dict__[id_] = hashlib.sha512(
                    tmp_password_.encode('utf8')).hexdigest()
                print("User \"" + str(id_) + "\" has been added successfully!")
                print("Temporary password is: " + tmp_password_)
                print("To save write save'")
                return 0
            else:
                print("Username already exits.")
                return 1
        else:
            print(bcolors.WARNING + "Only admin can add users." + bcolors.ENDC)
            return 1

    def removeUser(self, admin_=False):
        if(admin_):
            id_ = input(bcolors.OKBLUE +
                        "Enter the username to remove: " + bcolors.ENDC)
            if(id_ in self.__dict__):
                del self.__dict__[id_]
                file_name_ = "../bin/" + \
                    hashlib.md5(id_.encode('utf8')).hexdigest()[-10:] + ".aes"
                if os.path.exists(file_name_):
                    os.remove(file_name_)
                print("User \"" + id_ + "\" has been removed successfully!")
                return 0
            else:
                print(
                    bcolors.WARNING +
                    "Username does not exit." +
                    bcolors.ENDC)
                return 1
        else:
            print(
                bcolors.WARNING +
                "Only admin can remove users." +
                bcolors.ENDC)
            return 1

    def resetPassword(self, admin_=False):
        if(admin_):
            id_ = input(bcolors.OKBLUE +
                        "Enter the username to reset password: " + bcolors.ENDC)
            if(id_ in self.__dict__):
                file_name_ = "../bin/" + \
                    hashlib.md5(id_.encode('utf8')).hexdigest()[-10:] + ".aes"
                if os.path.exists(file_name_):
                    os.remove(file_name_)
                tmp_password_ = ''.join(
                    [random.choice(string.ascii_letters + string.digits) for n in range(8)])
                self.__dict__[id_] = hashlib.sha512(
                    tmp_password_.encode('utf8')).hexdigest()
                print(
                    "Password is reset. Temporary password is: " +
                    tmp_password_)
                return 0
            else:
                print(
                    bcolors.WARNING +
                    "Username does not exit." +
                    bcolors.ENDC)
                return 1
        else:
            print(
                bcolors.WARNING +
                "Only admin can resert password." +
                bcolors.ENDC)
            return 1

    def changePassword(self, id_, admin_=False):
        if(admin_):
            trial_ad = 0
            while(trial_ad < 3):
                PWD_admin_ = getpass.getpass(
                    bcolors.OKBLUE + "enter old admin password: " + bcolors.ENDC)
                PWD_admin_sha12_ = hashlib.sha512(
                    PWD_admin_.encode('utf8')).hexdigest()
                PWD_master_ = getpass.getpass(
                    bcolors.OKBLUE + "enter master password: " + bcolors.ENDC)
                PWD_master_sha512_ = hashlib.sha512(
                    PWD_master_.encode('utf8')).hexdigest()
                PWD_dec_admin_ = decryptUserCredentials("../bin/adp.aes", PWD_admin_sha12_)
                PWD_dec_master_ = decryptUserCredentials("../bin/msp.aes", PWD_master_sha512_)
                if(PWD_admin_sha12_ == PWD_dec_admin_):
                    if(PWD_admin_ == PWD_dec_master_):
                        PWD_new_ = getpass.getpass(
                            bcolors.OKBLUE + "Enter new admin password: " + bcolors.ENDC)
                        PWD_new_repeat_ = getpass.getpass(
                            bcolors.OKBLUE + "Repeat new admin password: " + bcolors.ENDC)
                        if(PWD_new_ == PWD_new_repeat_):
                            os.remove("../bin/adp.aes")
                            os.remove("../bin/msp.aes")
                            PWD_master_sha512_ = hashlib.sha512(
                                PWD_master_.encode('utf8')).hexdigest()
                            encryptUserCredentials(
                                PWD_new_, "../bin/msp.aes", PWD_master_sha512_)  # as backup
                            PWD_new_admin_sha12_ = hashlib.sha512(
                                PWD_new_.encode('utf8')).hexdigest()
                            encryptUserCredentials(
                                PWD_new_admin_sha12_, "../bin/adp.aes", PWD_new_admin_sha12_)
                            print("Password is changed successfuly!")
                        else:
                            print(bcolors.WARNING +
                                  "Passwords do not match!" + bcolors.ENDC)
                    else:
                        trial_ad += 1
                        print(bcolors.WARNING +
                              "Password is wrong, try again!" + bcolors.ENDC)
                else:
                    trial_ad += 1
                    print(bcolors.WARNING +
                          "Password is wrong, try again!" + bcolors.ENDC)
                del PWD_admin_, PWD_admin_sha12_, PWD_master_, PWD_new_, PWD_new_repeat_
                del PWD_new_admin_sha12_, PWD_master_sha512_,PWD_dec_admin_,PWD_dec_master_
        else:
            PWD_new_ = getpass.getpass(
                bcolors.OKBLUE + "New password: " + bcolors.ENDC)
            PWD_new_repeat_ = getpass.getpass(
                bcolors.OKBLUE + "Repeat new password: " + bcolors.ENDC)
            if(PWD_new_ == PWD_new_repeat_):
                file_name_ = "../bin/" + \
                    hashlib.md5(id_.encode('utf8')).hexdigest()[-10:] + ".aes"
                if os.path.exists(file_name_):
                    os.remove(file_name_)
                PWD_new_sha512_ = hashlib.sha512(
                    PWD_new_.encode('utf8')).hexdigest()
                encryptUserCredentials(
                    PWD_new_, user_file_name_, PWD_new_sha512_)
                trial = 0
                print("Password is changed successfuly!")
            else:
                print(
                    bcolors.WARNING +
                    "Passwords do not match!" +
                    bcolors.ENDC)
            del PWD_new_, PWD_new_repeat_


### Saving credentials ###
def save(UserCred_, admin=False):
    if(admin):
        encryptCredentials(UserCred_, "../bin/creds.aes", User_hash_sha512)
        print("Information is saved!")
        return 0
    else:
        print("Only admin can edit credentials.")
        return 1


### Loging in ###
def LogIn():
    master_ = False
    admin_ = False
    user_ = False
    User_ = input(bcolors.OKBLUE + "Username: " + bcolors.ENDC)
    if(User_ == 'master'):
        print(bcolors.WARNING +
              "master privilege is only used to recover 'admin' password." + bcolors.ENDC)
        PWD_master_ = getpass.getpass(
            bcolors.OKBLUE + "enter master password: " + bcolors.ENDC)
        PWD_master_sha512_ = hashlib.sha512(
            PWD_master_.encode('utf8')).hexdigest()
        PWD_admin_ = decryptUserCredentials(
            "../bin/msp.aes", PWD_master_sha512_)
        print("'admin' password is: " + PWD_admin_)
        print(
            bcolors.WARNING +
            "'admin' password may not be correct if you have entered the wrong password." +
            bcolors.ENDC)
        del PWD_master_, PWD_admin_
        master_ = True
    elif(User_ == 'admin'):
        trial_ad = 0
        while(trial_ad < 3):
            PWD_admin_ = getpass.getpass(
                bcolors.OKBLUE + "enter admin password: " + bcolors.ENDC)
            PWD_admin_sha512_ = hashlib.sha512(
                PWD_admin_.encode('utf8')).hexdigest()
            if(PWD_admin_sha512_ == decryptUserCredentials("../bin/adp.aes", PWD_admin_sha512_)):
                admin_ = True
                break
            else:
                trial_ad += 1
                print(bcolors.WARNING +
                      "Password is wrong, try again!" + bcolors.ENDC)
    else:
        trial = 0
        while(trial < 3):
            PWD_ = getpass.getpass(
                bcolors.OKBLUE + "Password: " + bcolors.ENDC)
            if User_ not in UserCred.self():
                print(
                    bcolors.WARNING + "Username does not exist, please contact administrator!" + bcolors.ENDC)
                break
            user_file_name_ = "../bin/" + \
                hashlib.md5(User_.encode('utf8')).hexdigest()[-10:] + ".aes"
            if os.path.exists(user_file_name_):
                PWD_sha512_ = hashlib.sha512(PWD_.encode('utf8')).hexdigest()
                PWD_dec_ = decryptUserCredentials(user_file_name_, PWD_sha512_)
                if(PWD_dec_ == PWD_sha512_):
                    user_ = True
                    break
                else:
                    trial += 1
                    print(bcolors.WARNING +
                          "Password is wrong, try again!" + bcolors.ENDC)
                del PWD_sha512_,PWD_dec_
            elif(UserCred.self()[User_] == hashlib.sha512(PWD_.encode('utf8')).hexdigest()):
                PWD_new_ = getpass.getpass(
                    bcolors.OKBLUE + "New Password: " + bcolors.ENDC)
                PWD_new_repeat_ = getpass.getpass(
                    bcolors.OKBLUE + "Repeat new Password: " + bcolors.ENDC)
                if(PWD_new_ == PWD_new_repeat_):
                    PWD_new_sha512_ = hashlib.sha512(
                        PWD_new_.encode('utf8')).hexdigest()
                    encryptUserCredentials(
                        PWD_new_sha512_, user_file_name_, PWD_new_sha512_)
                    trial = 0
                    print("Password is changed successfuly!")
                    user_ = True
                    break
                else:
                    print(bcolors.WARNING +
                          "Passwords do not match!" + bcolors.ENDC)
            else:
                trial += 1
                print(bcolors.WARNING +
                      "Password is wrong, try again!" + bcolors.ENDC)
    return master_, admin_, user_, User_


def create_poll():
    if not os.path.isdir("../bin/polls/"):
        os.makedirs("../bin/polls/")

    trial = 0
    while(trial < 3):
        Number_ = input(bcolors.OKBLUE + "Enter poll number: " + bcolors.ENDC)
        if not os.path.exists('../bin/polls/poll_' + Number_ + '.poll'):
            break
        else:
            trial += 1
            print(
                bcolors.WARNING +
                "Poll already exists. Try again!" +
                bcolors.ENDC)

    Question_ = input(
        bcolors.OKBLUE + "Enter the poll questoin: " + bcolors.ENDC)
    trial = 0
    while(trial < 3):
        try:
            Num_answer_ = int(
                input(bcolors.OKBLUE + "How many choices there are= " + bcolors.ENDC))
            break
        except BaseException:
            trial += 1
            print(
                bcolors.WARNING +
                "Please enter an integer number." +
                bcolors.ENDC)
    if not isinstance(Num_answer_, int):
        print(bcolors.WARNING + "Poll was not created!" + bcolors.ENDC)
        return 1

    Answers_ = []
    for i in range(Num_answer_):
        Answer_ = input(bcolors.OKBLUE + "Enter choice " +
                        str(i) + ": " + bcolors.ENDC)
        Answers_.append(Answer_)

    with open('../bin/polls/poll_' + Number_ + '.poll', 'w') as File_:
        File_.write(Question_ + '\n')
        for i in range(Num_answer_):
            File_.write(Answers_[i] + '\n')

    with open('../bin/polls/poll_' + Number_ + '.results', 'a') as f:
        f.write("Vote" + '\t' + "Receipt" + '\n')

    if not os.path.isdir("../bin/polls/poll_" + Number_ + "/"):
        os.makedirs("../bin/polls/poll_" + Number_ + "/")

    print("Poll number " + Number_ + " is created, successfully!")
    return 0


# Voting
def vote(UserName_, admin_):
    Casted_ = False
    if admin_:
        print("Admin cannot vote. Please log in as a user.")
        return 1

    trial_ = 0
    Poll_assigned_ = False
    while(trial_ < 3):
        Number_ = input(bcolors.OKBLUE + "Enter poll number: " + bcolors.ENDC)
        if os.path.exists('../bin/polls/poll_' + Number_ + '.poll'):
            Poll_assigned_ = True
            break
        else:
            trial_ += 1
            print(
                bcolors.WARNING +
                "Poll does not exist. Try again!" +
                bcolors.ENDC)
    if not Poll_assigned_:
        return 1

    with open('../bin/polls/poll_' + Number_ + '.poll') as f:
        lines_ = f.readlines()

    print(bcolors.BOLD + lines_[0][:-1] + bcolors.ENDC)
    for i in range(1, len(lines_)):
        print(bcolors.BOLD + str(i) + ') ' + bcolors.ENDC + lines_[i][:-1])

    hash_ = hashlib.sha256(
        ((UserName_ + Number_).encode('utf8'))).hexdigest()[:12]
    if os.path.exists('../bin/polls/poll_' + Number_ + '/' + hash_ + '.hash'):
        print(bcolors.WARNING + "You have already voted!" + bcolors.ENDC)
        return 2

    trial_ = 0
    while(trial_ < 3):
        try:
            Vote_ = int(input(bcolors.OKBLUE + "Enter your vote (as a number between 1 and "
                              + str(len(lines_) - 1) + "): " + bcolors.ENDC))
            if((Vote_ > 0) & (Vote_ < len(lines_))):
                Casted_ = True
                break
            else:
                trial_ += 1
                print(bcolors.WARNING + "Error! Enter a number between 1 and " +
                      str(len(lines_) - 1) + bcolors.ENDC)
        except BaseException:
            trial_ += 1
            print(bcolors.WARNING + "Error! Enter a number between 1 and " +
                  str(len(lines_) - 1) + bcolors.ENDC)

    if not Casted_:
        print(
            bcolors.WARNING +
            "Vote has not been casted. Try again!" +
            bcolors.ENDC)
        return 1

    with open('../bin/polls/poll_' + Number_ + '/' + hash_ + '.hash', 'wb') as f:
        f.write(Random.new().read(32))  # Just for fun

    salt_ = Random.new().read(16)
    receipt_ = hashlib.sha256(
        (UserName_.encode('utf8') + salt_)).hexdigest()[:32]
    with open('../bin/polls/poll_' + Number_ + '.results', 'a') as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        f.write(str(Vote_) + '\t' + str(receipt_) + '\n')
        fcntl.flock(f, fcntl.LOCK_UN)

    print("Thank you! Your vote has been casted anonymously!")  # receipt needed
    print("Your receipt number is: " + bcolors.BOLD + receipt_ + bcolors.ENDC)
    print("Keep your receipt in order to validate your vote later.")
    print("Receipt numbers are public but not traceable by anyone!")
    return 0

