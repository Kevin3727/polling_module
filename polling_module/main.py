#!/usr/bin/env python3

from functions import *


def main():

    print("%%%%%%%%%%%%%%%%%$%%%%%%%%%%%")
    print("%          WELCOME          %")
    print("%     to polling system     %")
    print("% created by Kevin Ghorbani %")
    print("%%%%%%%%%%%%%%%%%%%%$%%%%%%%%")
    print('\n')

    master = False
    admin = False
    user = False

    global user_database_location
    user_database_location = '../bin/user_creds.db'

    # First time use
    if not os.path.isdir("./bin/"):
        os.makedirs("./bin/")
    if not os.path.exists(user_database_location):
        init(user_database_location)

    '''
    if not os.path.exists("./bin/msp.aes"):
        PWD_master_ = getpass.getpass(
            bcolors.OKBLUE + "Enter 'master' password: " + bcolors.ENDC)
        PWD_admin_ = getpass.getpass(
            bcolors.OKBLUE + "Enter 'admin' password: " + bcolors.ENDC)
        PWD_master_sha512_ = hashlib.sha512(
            PWD_master_.encode('utf8')).hexdigest()
        encryptUserCredentials(PWD_admin_, "./bin/msp.aes",
                               PWD_master_sha512_)  # as backup
        PWD_admin_sha512_ = hashlib.sha512(
            PWD_admin_.encode('utf8')).hexdigest()
        encryptUserCredentials(
            PWD_admin_sha512_, "./bin/adp.aes", PWD_admin_sha512_)
        del PWD_master_, PWD_admin_, PWD_admin_sha512_
        save(UserCred, True)
        print("Passwords are set.")
    '''
    # Logging in
    master, admin, user, UserName = Login(user_database_location)

    #
    if(user or admin):
        while(True):
            Input = None
            if(admin):
                Input = input(bcolors.OKBLUE +
                              "Enter command (admin): " + bcolors.ENDC)
            else:
                Input = input(bcolors.OKBLUE +
                              "Enter command: " + bcolors.ENDC)

            if Input == 'help':
                print('to add a new user use "add_user"', end='\n')
                print('to remove a user use "remove_user"', end='\n')
                print('to reset password use "reset_password"', end='\n')
                print('to change password use "change_password"', end='\n')
                print('to creat a poll or an election use "create_poll"', end='\n')
                print('to vote use "vote"', end='\n')
                print('to list all users use "list_users"', end='\n')
                print(
                    'to close a poll and publish the results use "close_poll"', end='\n')
                print(
                    'to add or update users from CSV file use "add_users_csv"', end='\n')
                print('to view closed polls\' results use "view_results"', end='\n')
                print('to exit use "exit"', end='\n')
            elif Input == 'add_user':
                addUser(user_database_location, admin)
            elif Input == 'remove_user':
                deleteUser(user_database_location, admin)
            elif Input == 'reset_password':
                resetPassword(user_database_location, admin, None)
            elif Input == 'change_password':
                changePassword(user_database_location, UserName)
            elif Input == 'create_poll':
                createPoll(user_database_location, admin)
            elif Input == 'vote':
                vote(user_database_location, admin)
            elif Input == 'list_users':
                printUsers(user_database_location, admin)
            elif Input == 'close_poll':
                closePolling(admin)
            elif Input == 'add_users_csv':
                createUsersFromFile(user_database_location, admin)
            elif Input == 'view_results':
                viewResults()
            elif Input == 'exit':
                break
            elif Input == '':
                pass
            else:
                print(
                    bcolors.WARNING +
                    "Command does not exist!" +
                    bcolors.ENDC)


if __name__ == '__main__':
    main()
