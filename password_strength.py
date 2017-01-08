import string
import os
import re
import getpass


def password_check(password):
    strength = 0
    if len(password) >= 8:
        strength += 2
    if len(password) >= 12:
        strength += 2
    if not password.isnumeric():
        if not password.islower() and not password.isupper():
            strength += 2
        if any(char.isdigit() for char in password):
            strength += 2
    if any(char in string.punctuation for char in password):
        strength += 2
    return strength


def load_blacklist(file_path):
    if not os.path.exists(file_path):
        return None
    with open(file_path, 'r') as file_handler:
        return re.findall(r'[\w]+', file_handler.read())


def check_password_in_blacklist(password, blacklist):
    if blacklist is not None:
        return password in blacklist


def get_password_to_check():
    return getpass.getpass('Type password to check\n')


def get_path_to_blacklist():
    return input('Type path to passwords blacklist, if you haven\'t one '
                 'just don\'t type anything and press \'Enter\'.\n')


if __name__ == '__main__':
    password_to_check = get_password_to_check()
    if password_to_check:
        path_to_blacklist = get_path_to_blacklist()
        black_list = load_blacklist(path_to_blacklist)
        password_strength = password_check(password_to_check)
        blacklist_check_result = check_password_in_blacklist(password_to_check,
                                                             black_list)
        password_strength *= not blacklist_check_result
        if blacklist_check_result is None:
            print('Evaluation is not complete because we could not verify '
                  'the existence of the password in black lists.\n')
        else:
            print('Your password is {}in the blacklist'.format(
                'not ' * (not blacklist_check_result)))
        print('Password strength is {}/10.'.format(password_strength))
    else:
        print('Since you haven\'t typed anything, there is nothing to check.')
