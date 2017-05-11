#!/usr/bin/env python3

from functions import *


def main():

    print("%%%%%%%%%%%%%%%%%$%%%%%%%%%%%")
    print("%          WELCOME          %")
    print("%   to the polling system   %")
    print("% created by Kevin Ghorbani %")
    print("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%")
    print('\n')

    master = False
    admin = False
    user = False

    global UserCred
    UserCred = UserCredentials()
    if os.path.exists("../bin/creds.aes"):
        UserCred = decryptCredentials("../bin/creds.aes", User_hash_sha512)

    # First time use (by master)
    if not os.path.isdir("../bin/"):
        os.makedirs("../bin/")
    if not os.path.exists("../bin/msp.aes"):
        PWD_master_ = getpass.getpass(
            bcolors.OKBLUE + "Enter 'master' password: " + bcolors.ENDC)
        PWD_admin_ = getpass.getpass(
            bcolors.OKBLUE + "Enter 'admin' password: " + bcolors.ENDC)
        PWD_master_sha512_ = hashlib.sha512(
            PWD_master_.encode('utf8')).hexdigest()
        encryptUserCredentials(PWD_admin_, "../bin/msp.aes",
                               PWD_master_sha512_)  # as backup
        PWD_admin_sha12_ = hashlib.sha512(
            PWD_admin_.encode('utf8')).hexdigest()
        encryptUserCredentials(
            PWD_admin_sha12_, "../bin/adp.aes", PWD_admin_sha12_)
        del PWD_master_, PWD_admin_, PWD_admin_sha12_
        save(UserCred, True)
        print("Passwords are set.")

    # Logging in
    master, admin, user, UserName = LogIn()

    #
    Input = None
    if(user or admin):
        while(True):
            if(admin):
                Input = input(bcolors.OKBLUE +
                              "Enter command (admin): " + bcolors.ENDC)
            else:
                Input = input(bcolors.OKBLUE +
                              "Enter command: " + bcolors.ENDC)

            # to add a new user use "add_user"
            if(Input == 'add_user'):
                UserCred.addUser(UserName, admin)
            # to remove a user use "remove_user"
            elif(Input == 'remove_user'):
                UserCred.removeUser(admin)
            # to change password use "change_password"
            elif(Input == 'change_password'):
                UserCred.changePassword(UserName, admin)
            # to save credentials use "save"
            elif(Input == 'save'):
                save(UserCred, admin)
            # to creat a poll or an election use "create_poll"
            elif(Input == 'create_poll'):
                create_poll()
            # to vote use "vote"
            elif(Input == 'vote'):
                vote(UserName, admin)
            # to print users
            elif(Input == 'print_users'):
                if(admin):
                    print(UserCred.self().keys())
            # to exit use "exit"
            elif(Input == 'exit'):
                break
            else:
                print(
                    bcolors.WARNING +
                    "Command does not exist!" +
                    bcolors.ENDC)


if __name__ == '__main__':
    main()
